//! The view (`fuseview.View`), request for request: a passthrough keyed by backing-file reference
//! -- a directory inode holds an O_PATH descriptor and its path, a file inode the directory it was
//! found in and its name there -- every name decided by the filter, and every use of a descriptor
//! preceded by the check that the object is still where it was recorded, as the kernel reports it
//! (/proc/self/fd). The docstring of certorail/fuseview.py is the specification, the contract
//! included; the comments here say only what that one does not.
//!
//! Requests are served one at a time, under one lock, as the Python view serves them in one trio
//! task. `read` and `write` use only the descriptor the kernel names, and take no lock.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags,
    KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

use crate::filter::Filter;
use crate::spec::Spec;
use crate::sys::{self, Change, Key, Stat, Target, When};

const ROOT: u64 = INodeNo::ROOT.0;

/// How long the kernel may cache what it is told: a name, a directory's attributes, a file's.
/// The Python view's are 1, 1 and 0 seconds.
#[derive(Clone, Copy)]
pub struct Ttls {
    pub entry: Duration,
    pub dirs: Duration,
    pub files: Duration,
}

impl Ttls {
    fn attr(&self, st: &Stat) -> Duration {
        if st.is_dir() {
            self.dirs
        } else {
            self.files
        }
    }

    /// For fuser's listing and create replies, which carry one time for the name and the
    /// attributes both: the shorter, so that neither is cached longer than it may be. A listed
    /// file's name is thus cached no longer than its attributes (0 s where the Python view says 1).
    fn both(&self, st: &Stat) -> Duration {
        self.entry.min(self.attr(st))
    }
}

/// The requests the probe counts (`scripts/probe_view_find.py`).
#[derive(Default)]
pub struct Counts {
    lookup: AtomicU64,
    getattr: AtomicU64,
    readdir: AtomicU64,
    open: AtomicU64,
    read: AtomicU64,
}

impl Counts {
    /// The requests answered since the last call, as the probe's JSON line; the counts start over.
    pub fn take(&self) -> String {
        let n = |count: &AtomicU64| count.swap(0, Relaxed);
        format!(
            r#"{{"lookup": {}, "getattr": {}, "readdir": {}, "open": {}, "read": {}}}"#,
            n(&self.lookup),
            n(&self.getattr),
            n(&self.readdir),
            n(&self.open),
            n(&self.read)
        )
    }
}

enum Place {
    /// A directory: an O_PATH descriptor, and its path below the served directory.
    Dir { fd: OwnedFd, path: Vec<OsString> },
    /// Anything else: the directory inode it was found in, and its name there.
    File { parent: u64, name: OsString },
}

struct Inode {
    place: Place,
    key: Key,
    refs: u64,
}

/// A descriptor to act through: one an inode holds, or one opened for the occasion, closed when
/// this is dropped.
enum Fd {
    Held(RawFd),
    Opened(OwnedFd),
}

impl Fd {
    fn raw(&self) -> RawFd {
        match self {
            Fd::Held(fd) => *fd,
            Fd::Opened(fd) => fd.as_raw_fd(),
        }
    }
}

/// An entry as the kernel is told of it.
struct Entry {
    ino: u64,
    st: Stat,
}

/// A directory's visible entries, as the scan that began its listing found them.
type Entries = Arc<Vec<(OsString, Stat)>>;

struct Listing {
    inode: u64,
    entries: Option<Entries>,
}

/// What cannot happen, if it does: logged, and answered EIO.
fn bug(what: &str) -> Errno {
    eprintln!("fuseview-rs: {what}");
    Errno::EIO
}

fn is(e: &io::Error, errno: libc::c_int) -> bool {
    e.raw_os_error() == Some(errno)
}

/// A descriptor for the directory at *source* now, reached without a symbolic link, or None when
/// there is none.
fn served(source: &Path) -> io::Result<Option<OwnedFd>> {
    let fd = match sys::open(source, libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW) {
        Ok(fd) => fd,
        Err(e) if is(&e, libc::ENOENT) || is(&e, libc::ENOTDIR) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(if sys::is_at(fd.as_raw_fd(), source)? { Some(fd) } else { None }) // else: a link above it
}

struct Core {
    rules: Filter,
    /// the served directory's path, and where the kernel reports it to be
    source: PathBuf,
    inodes: HashMap<u64, Inode>,
    // directories by identity, since a directory has one name; files by where they were found,
    // since a file may have several
    by_key: HashMap<Key, u64>,
    by_place: HashMap<(u64, OsString), u64>,
    next_inode: u64,
    /// a directory handle (the descriptor the listing reads) -> the directory, and its entries
    listings: HashMap<u64, Listing>,
    // the handles open on each file, and the file each is on: an open file still has attributes
    // when no name leads to it any more
    open_handles: HashMap<u64, Vec<u64>>,
    handle_inodes: HashMap<u64, u64>,
}

impl Core {
    fn new(spec: Spec) -> io::Result<Core> {
        let source = spec.directory;
        let Some(fd) = served(&source)? else {
            return Err(io::Error::other(format!(
                "{}: not a directory reached without a symbolic link",
                source.display()
            )));
        };
        let key = sys::fstat(fd.as_raw_fd())?.key();
        let root = Inode { place: Place::Dir { fd, path: Vec::new() }, key, refs: 1 };
        Ok(Core {
            rules: Filter::new(source.clone(), spec.layers),
            source,
            inodes: HashMap::from([(ROOT, root)]),
            by_key: HashMap::from([(key, ROOT)]),
            by_place: HashMap::new(),
            next_inode: ROOT + 1,
            listings: HashMap::new(),
            open_handles: HashMap::new(),
            handle_inodes: HashMap::new(),
        })
    }

    // -- paths and helpers ------------------------------------------------------------------------

    fn node(&self, inode: u64) -> Result<&Inode, Errno> {
        self.inodes.get(&inode).ok_or_else(|| bug(&format!("inode {inode} is not known")))
    }

    /// The directory and name of a file inode, and its identity; None for a directory.
    fn file(&self, inode: u64) -> Result<Option<(u64, OsString, Key)>, Errno> {
        let node = self.node(inode)?;
        Ok(match &node.place {
            Place::Dir { .. } => None,
            Place::File { parent, name } => Some((*parent, name.clone(), node.key)),
        })
    }

    fn path_of(&self, inode: u64) -> Result<Vec<OsString>, Errno> {
        match &self.node(inode)?.place {
            Place::Dir { path, .. } => Ok(path.clone()),
            Place::File { parent, name } => {
                let mut path = self.path_of(*parent)?;
                path.push(name.clone());
                Ok(path)
            }
        }
    }

    fn child_path(&self, parent: u64, name: &OsStr) -> Result<Vec<OsString>, Errno> {
        let mut path = self.path_of(parent)?;
        path.push(name.to_os_string());
        Ok(path)
    }

    /// *name* under *parent* may be created, replaced or removed, or EPERM.
    fn writable_name(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        if self.rules.may_write(&self.child_path(parent, name)?) {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    }

    /// The file itself may be written: its one name may, or EPERM.
    fn writable_inode(&mut self, inode: u64) -> Result<(), Errno> {
        if inode == ROOT || !self.rules.may_write(&self.path_of(inode)?) {
            return Err(Errno::EPERM);
        }
        let st = self.stat_of(inode)?;
        if !st.is_dir() && st.nlink > 1 {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// Is *name*, which resolves under *parent*, the spelling the directory stores?
    fn spelled_as_stored(&mut self, parent: u64, name: &OsStr) -> Result<bool, Errno> {
        let fd = self.parent_fd(parent)?;
        if sys::exact_lookups(fd) {
            return Ok(true);
        }
        for entry in std::fs::read_dir(sys::proc_path(fd))? {
            if entry?.file_name() == name {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// EEXIST when the backing filesystem resolves *name* to an entry it stores under another
    /// spelling.
    fn refuse_alias(&mut self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        match sys::fstatat(self.parent_fd(parent)?, name) {
            Err(e) if is(&e, libc::ENOENT) => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) if self.spelled_as_stored(parent, name)? => Ok(()),
            Ok(_) => Err(Errno::EEXIST),
        }
    }

    /// The served directory's descriptor, while the directory it holds is at the served path; else
    /// the directory there now, reached without a symbolic link; with none there, ESTALE.
    fn anchor(&mut self) -> Result<RawFd, Errno> {
        let root = self.node(ROOT)?;
        let old = root.key;
        let Place::Dir { fd, .. } = &root.place else {
            return Err(bug("the root inode is not a directory"));
        };
        let fd = fd.as_raw_fd();
        if sys::is_at(fd, &self.source)? {
            return Ok(fd);
        }
        let Some(new) = served(&self.source)? else {
            return Err(Errno::ESTALE);
        };
        let key = sys::fstat(new.as_raw_fd())?.key();
        if self.by_key.get(&old) == Some(&ROOT) {
            self.by_key.remove(&old);
        }
        let fd = new.as_raw_fd();
        let root = self.inodes.get_mut(&ROOT).expect("the root inode");
        root.place = Place::Dir { fd: new, path: Vec::new() }; // the old descriptor closes
        root.key = key;
        self.by_key.insert(key, ROOT);
        Ok(fd)
    }

    /// The descriptor the directory *inode* holds, while the object it refers to is at the inode's
    /// recorded path; else ESTALE, and the kernel looks the path up again.
    fn held(&mut self, inode: u64) -> Result<RawFd, Errno> {
        if inode == ROOT {
            return self.anchor();
        }
        let (fd, recorded) = match &self.node(inode)?.place {
            Place::Dir { fd, path } => (fd.as_raw_fd(), sys::join(&self.source, path)),
            Place::File { .. } => return Err(bug(&format!("inode {inode} is not a directory"))),
        };
        if !sys::is_at(fd, &recorded)? {
            return Err(Errno::ESTALE);
        }
        Ok(fd)
    }

    fn parent_fd(&mut self, parent: u64) -> Result<RawFd, Errno> {
        self.held(parent) // the kernel names children only of directories, which hold one
    }

    /// The descriptor the directory *inode* holds, unchecked: for opening a child whose own path
    /// is checked next, which vouches for every directory above it.
    fn unchecked_fd(&self, inode: u64) -> Result<RawFd, Errno> {
        match &self.node(inode)?.place {
            Place::Dir { fd, .. } => Ok(fd.as_raw_fd()),
            Place::File { .. } => Err(bug(&format!("inode {inode} is not a directory"))),
        }
    }

    /// A live O_PATH descriptor for *inode*: held, for a directory still at its path; opened, for a
    /// file, by the name it was found under in its held parent, and refused (ESTALE) if what is
    /// there now is a different file.
    fn fd_of(&mut self, inode: u64) -> Result<Fd, Errno> {
        let Some((parent, name, key)) = self.file(inode)? else {
            return Ok(Fd::Held(self.held(inode)?));
        };
        let dir = self.parent_fd(parent)?;
        let fd = match sys::openat(dir, &name, libc::O_PATH | libc::O_NOFOLLOW, 0) {
            Ok(fd) => fd,
            Err(e) if is(&e, libc::ENOENT) => return Err(Errno::ESTALE),
            Err(e) => return Err(e.into()),
        };
        if sys::fstat(fd.as_raw_fd())?.key() != key {
            return Err(Errno::ESTALE);
        }
        Ok(Fd::Opened(fd))
    }

    /// *inode*'s attributes: a directory's through its checked descriptor; a file's at its name,
    /// while the object there is the one recorded -- else through a handle still open on it, else
    /// ESTALE.
    fn stat_of(&mut self, inode: u64) -> Result<Stat, Errno> {
        let Some((parent, name, key)) = self.file(inode)? else {
            return Ok(sys::fstat(self.held(inode)?)?);
        };
        match self.parent_fd(parent).and_then(|dir| sys::fstatat(dir, &name).map_err(Errno::from)) {
            Ok(st) if st.key() == key => return Ok(st),
            Ok(_) => {}
            Err(e) if e == Errno::ENOENT || e == Errno::ESTALE => {}
            Err(e) => return Err(e),
        }
        match self.open_handles.get(&inode).and_then(|handles| handles.first()) {
            Some(&fh) => Ok(sys::fstat(fh as RawFd)?),
            None => Err(Errno::ESTALE),
        }
    }

    fn fresh_inode(&mut self) -> u64 {
        let inode = self.next_inode;
        self.next_inode += 1;
        inode
    }

    /// The entry *name* under the directory inode *parent* as an inode the kernel may hold: the one
    /// recorded for it there, or a new one; its count bumped. A directory is recorded only if the
    /// object opened is the one *st* describes (default: a stat now), at the path its name says;
    /// one replaced or moved between the two is ENOENT.
    ///
    /// Only a stat taken here checks the parent (it is taken through the parent's descriptor and
    /// judged by its path). One the caller hands over was taken so already -- by a listing's scan,
    /// a lookup, a create -- and admitting acts on nothing more: a file is recorded untouched, and
    /// every later use of it checks its parent again; a directory's own path check vouches for
    /// every directory above it. (The Python view checks the parent here every time: one readlink
    /// per listed entry.)
    fn admit(&mut self, parent: u64, name: &OsStr, st: Option<Stat>) -> Result<Entry, Errno> {
        let st = match st {
            Some(st) => st,
            None => sys::fstatat(self.parent_fd(parent)?, name)?,
        };
        let key = st.key();
        if st.is_dir() {
            let path = self.child_path(parent, name)?;
            if let Some(&ino) = self.by_key.get(&key) {
                let node = self.inodes.get_mut(&ino).expect("by_key names a live inode");
                if matches!(&node.place, Place::Dir { path: recorded, .. } if *recorded == path) {
                    node.refs += 1;
                    return Ok(Entry { ino, st });
                }
            }
            let dir = self.unchecked_fd(parent)?;
            let fd = match sys::openat(dir, name, libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY, 0) {
                Ok(fd) => fd,
                Err(e) if is(&e, libc::ENOENT) || is(&e, libc::ENOTDIR) => return Err(Errno::ENOENT),
                Err(e) => return Err(e.into()),
            };
            if sys::fstat(fd.as_raw_fd())?.key() != key || !sys::is_at(fd.as_raw_fd(), &sys::join(&self.source, &path))? {
                return Err(Errno::ENOENT);
            }
            let ino = self.fresh_inode();
            self.inodes.insert(ino, Inode { place: Place::Dir { fd, path }, key, refs: 1 });
            self.by_key.insert(key, ino); // an older inode with this key stays, unfindable, until forgotten
            Ok(Entry { ino, st })
        } else {
            let place = (parent, name.to_os_string());
            if let Some(&ino) = self.by_place.get(&place) {
                let node = self.inodes.get_mut(&ino).expect("by_place names a live inode");
                if node.key == key {
                    node.refs += 1;
                    return Ok(Entry { ino, st });
                }
            }
            let ino = self.fresh_inode();
            self.inodes.insert(ino, Inode { place: Place::File { parent, name: name.to_os_string() }, key, refs: 1 });
            self.inodes.get_mut(&parent).expect("the parent inode").refs += 1; // a file pins its directory
            self.by_place.insert(place, ino);
            Ok(Entry { ino, st })
        }
    }

    /// *count* of the kernel's references to *inode* let go.
    fn unref(&mut self, inode: u64, count: u64) {
        if inode == ROOT {
            return;
        }
        let Some(node) = self.inodes.get_mut(&inode) else {
            return;
        };
        node.refs = node.refs.saturating_sub(count);
        if node.refs > 0 {
            return;
        }
        let node = self.inodes.remove(&inode).expect("just found");
        match node.place {
            Place::Dir { fd, .. } => {
                if self.by_key.get(&node.key) == Some(&inode) {
                    self.by_key.remove(&node.key); // not if a newer inode took the key
                }
                drop(fd);
            }
            Place::File { parent, name } => {
                let place = (parent, name);
                if self.by_place.get(&place) == Some(&inode) {
                    self.by_place.remove(&place);
                }
                self.unref(parent, 1);
            }
        }
    }

    fn opened(&mut self, inode: u64, fh: u64) {
        self.open_handles.entry(inode).or_default().push(fh);
        self.handle_inodes.insert(fh, inode);
    }

    fn closed(&mut self, fh: u64) {
        let Some(inode) = self.handle_inodes.remove(&fh) else {
            return;
        };
        if let Some(handles) = self.open_handles.get_mut(&inode) {
            handles.retain(|&h| h != fh);
            if handles.is_empty() {
                self.open_handles.remove(&inode);
            }
        }
    }

    /// The visible entries of the directory *fh* reads, read afresh from its start (a new listing,
    /// or a rewinddir); the listing's later pages index them.
    fn scan(&mut self, fh: u64, parent: u64) -> Result<Entries, Errno> {
        let base = self.path_of(parent)?;
        let fd = fh as RawFd;
        if !sys::is_at(fd, &sys::join(&self.source, &base))? {
            return Err(Errno::ESTALE); // the directory is not where it was opened any more
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(sys::proc_path(fd))? {
            let name = entry?.file_name();
            let st = match sys::fstatat(fd, &name) {
                Ok(st) => st,
                Err(e) if is(&e, libc::ENOENT) => continue, // vanished mid-scan
                Err(e) => return Err(e.into()),
            };
            let mut path = base.clone();
            path.push(name.clone());
            if self.rules.visible(&path, st.is_dir()) {
                entries.push((name, st));
            }
        }
        let entries = Arc::new(entries);
        self.listings.insert(fh, Listing { inode: parent, entries: Some(entries.clone()) });
        Ok(entries)
    }

    // -- names: the filter lives here --------------------------------------------------------------

    fn lookup(&mut self, parent: u64, name: &OsStr) -> Result<Entry, Errno> {
        let st = sys::fstatat(self.parent_fd(parent)?, name)?;
        if !self.spelled_as_stored(parent, name)? {
            return Err(Errno::ENOENT); // another spelling of an entry: not this name
        }
        if !self.rules.visible(&self.child_path(parent, name)?, st.is_dir()) {
            return Err(Errno::ENOENT); // the name does not exist, not "may not"
        }
        self.admit(parent, name, Some(st))
    }

    fn opendir(&mut self, inode: u64) -> Result<RawFd, Errno> {
        let at = self.fd_of(inode)?;
        let fd = sys::open(&sys::proc_path(at.raw()), libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        self.listings.insert(fd as u64, Listing { inode, entries: None });
        Ok(fd)
    }

    /// One page of the listing on *fh*, from *offset*, each entry handed to *add* -- which says
    /// whether the page is full, and the entry left out. Entries are admitted, since the kernel
    /// then skips a lookup; one it is not sent is let go again, since the kernel never forgets what
    /// it never saw.
    fn readdirplus(&mut self, fh: u64, offset: u64, add: &mut dyn FnMut(&Entry, u64, &OsStr) -> bool) -> Result<(), Errno> {
        let (parent, entries) = match self.listings.get(&fh) {
            Some(listing) => (listing.inode, listing.entries.clone()),
            None => return Err(bug(&format!("no listing on handle {fh}"))),
        };
        let entries = match entries {
            Some(entries) if offset != 0 => entries,
            _ => self.scan(fh, parent)?,
        };
        let mut sent = Vec::new();
        for (i, (name, st)) in entries.iter().enumerate().skip(offset as usize) {
            let entry = match self.admit(parent, name, Some(*st)) {
                Ok(entry) => entry,
                Err(e) if e == Errno::ENOENT => continue, // gone, or replaced, since the scan
                Err(e) => {
                    for inode in sent {
                        self.unref(inode, 1); // the kernel discards the page with the error
                    }
                    return Err(e);
                }
            };
            if add(&entry, (i + 1) as u64, name) {
                self.unref(entry.ino, 1);
                break;
            }
            sent.push(entry.ino);
        }
        Ok(())
    }

    fn releasedir(&mut self, fh: u64) {
        self.listings.remove(&fh);
        sys::close(fh as RawFd);
    }

    fn create(&mut self, parent: u64, name: &OsStr, mode: u32, flags: i32) -> Result<(Entry, RawFd), Errno> {
        self.writable_name(parent, name)?;
        self.refuse_alias(parent, name)?;
        let dir = self.fd_of(parent)?;
        let fd = sys::openat(dir.raw(), name, flags | libc::O_CREAT | libc::O_EXCL, mode)?;
        // the inode is the file the handle is on, not whatever is at the name by now
        let entry = self.admit(parent, name, Some(sys::fstat(fd.as_raw_fd())?))?;
        let fd = fd.into_raw_fd();
        self.opened(entry.ino, fd as u64);
        Ok((entry, fd))
    }

    fn mkdir(&mut self, parent: u64, name: &OsStr, mode: u32) -> Result<Entry, Errno> {
        self.writable_name(parent, name)?;
        self.refuse_alias(parent, name)?;
        sys::mkdirat(self.fd_of(parent)?.raw(), name, mode)?;
        self.admit(parent, name, None)
    }

    fn symlink(&mut self, parent: u64, name: &OsStr, target: &Path) -> Result<Entry, Errno> {
        self.writable_name(parent, name)?;
        self.refuse_alias(parent, name)?;
        sys::symlinkat(target.as_os_str(), self.fd_of(parent)?.raw(), name)?;
        self.admit(parent, name, None)
    }

    fn link(&mut self, inode: u64, new_parent: u64, new_name: &OsStr) -> Result<Entry, Errno> {
        self.writable_name(new_parent, new_name)?;
        self.refuse_alias(new_parent, new_name)?;
        // a new name for a file is a way to write it later: only for a file that may be written
        self.writable_inode(inode)?;
        let fd = self.fd_of(inode)?;
        sys::link_fd(fd.raw(), self.fd_of(new_parent)?.raw(), new_name)?;
        drop(fd);
        self.admit(new_parent, new_name, None)
    }

    /// The directories the kernel holds at or below *src*, recorded now at or below *dst*: their
    /// paths are what every check below them compares against.
    fn move_dirs(&mut self, src: &[OsString], dst: &[OsString]) {
        for node in self.inodes.values_mut() {
            if let Place::Dir { path, .. } = &mut node.place {
                if path.starts_with(src) {
                    *path = dst.iter().chain(&path[src.len()..]).cloned().collect();
                }
            }
        }
    }

    fn rename(&mut self, parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr) -> Result<(), Errno> {
        self.writable_name(parent, name)?; // removing the old name is a write there
        self.writable_name(new_parent, new_name)?;
        self.refuse_alias(new_parent, new_name)?; // renaming onto another spelling replaces that entry
        let (src, dst) = (self.child_path(parent, name)?, self.child_path(new_parent, new_name)?);
        let old_dir = self.fd_of(parent)?;
        let st = sys::fstatat(old_dir.raw(), name)?;
        // a directory's path is every path beneath it: it moves only where each of those is
        // decided alike before and after
        if st.is_dir() && !self.rules.may_move_dir(&src, &dst) {
            return Err(Errno::EPERM);
        }
        sys::renameat(old_dir.raw(), name, self.fd_of(new_parent)?.raw(), new_name)?;
        if st.is_dir() {
            self.move_dirs(&src, &dst);
            return Ok(());
        }
        let old_place = (parent, name.to_os_string());
        let Some(&moved) = self.by_place.get(&old_place) else {
            return Ok(());
        };
        if self.inodes[&moved].key == st.key() {
            self.by_place.remove(&old_place);
            // the new directory is pinned before the old one is let go: they may be the same
            self.inodes.get_mut(&new_parent).expect("the new parent inode").refs += 1;
            self.inodes.get_mut(&moved).expect("the moved inode").place =
                Place::File { parent: new_parent, name: new_name.to_os_string() };
            self.unref(parent, 1);
            self.by_place.insert((new_parent, new_name.to_os_string()), moved);
        }
        Ok(())
    }

    fn remove(&mut self, parent: u64, name: &OsStr, flags: libc::c_int) -> Result<(), Errno> {
        self.writable_name(parent, name)?;
        Ok(sys::unlinkat(self.fd_of(parent)?.raw(), name, flags)?)
    }

    // -- inodes: no names involved -----------------------------------------------------------------

    fn setattr(&mut self, inode: u64, change: &Change, fh: Option<u64>) -> Result<Stat, Errno> {
        self.writable_inode(inode)?;
        match fh {
            // the handle the call came through: an unlinked file has no name
            Some(fh) => change.apply(Target::Open(fh as RawFd))?,
            None => change.apply(Target::Path(self.fd_of(inode)?.raw()))?,
        }
        self.stat_of(inode)
    }

    fn readlink(&mut self, inode: u64) -> Result<Vec<u8>, Errno> {
        // the link text passes through; the kernel resolves it inside the view
        let Some((parent, name, _)) = self.file(inode)? else {
            return Err(Errno::EINVAL); // a directory is never a link
        };
        if !self.rules.readable(&self.path_of(inode)?) {
            return Err(Errno::EACCES);
        }
        self.stat_of(inode)?; // identity check
        Ok(sys::readlinkat(self.parent_fd(parent)?, &name)?)
    }

    fn open(&mut self, inode: u64, flags: i32) -> Result<RawFd, Errno> {
        let writing = flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_APPEND | libc::O_TRUNC) != 0;
        if writing {
            self.writable_inode(inode)?;
        } else if !self.rules.readable(&self.path_of(inode)?) {
            return Err(Errno::EACCES); // listed by name under a readable directory only
        }
        // promote the reference to an I/O descriptor; truncating waits until the descriptor is
        // known to be on the file checked
        let opening = flags & !(libc::O_CREAT | libc::O_TRUNC);
        let fd = match self.file(inode)? {
            None => sys::open(&sys::proc_path(self.held(inode)?), opening & !libc::O_NOFOLLOW)?,
            Some((parent, name, key)) => {
                let fd = match sys::openat(self.parent_fd(parent)?, &name, opening | libc::O_NOFOLLOW, 0) {
                    Ok(fd) => fd,
                    Err(e) if is(&e, libc::ENOENT) => return Err(Errno::ESTALE),
                    Err(e) => return Err(e.into()),
                };
                let st = sys::fstat(fd.as_raw_fd())?;
                if st.key() != key {
                    return Err(Errno::ESTALE);
                }
                if writing && st.nlink > 1 {
                    return Err(Errno::EPERM); // a name was added since the check
                }
                fd
            }
        };
        if flags & libc::O_TRUNC != 0 {
            sys::ftruncate(fd.as_raw_fd(), 0)?;
        }
        let fd = fd.into_raw_fd();
        self.opened(inode, fd as u64);
        Ok(fd)
    }

    fn release(&mut self, fh: u64) {
        self.closed(fh);
        sys::close(fh as RawFd);
    }

    fn statfs(&mut self) -> Result<libc::statvfs, Errno> {
        let root = self.fd_of(ROOT)?;
        Ok(sys::statvfs(&sys::proc_path(root.raw()))?)
    }
}

fn kind_of(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn attr_of(st: &Stat, ino: u64) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: st.size as u64,
        blocks: st.blocks as u64,
        atime: sys::system_time(st.atime),
        mtime: sys::system_time(st.mtime),
        ctime: sys::system_time(st.ctime),
        crtime: UNIX_EPOCH,
        kind: kind_of(st.mode),
        perm: (st.mode & 0o7777) as u16,
        nlink: st.nlink as u32,
        uid: st.uid,
        gid: st.gid,
        rdev: st.rdev as u32,
        blksize: st.blksize as u32,
        flags: 0,
    }
}

fn when(t: TimeOrNow) -> When {
    match t {
        TimeOrNow::SpecificTime(t) => When::At(t),
        TimeOrNow::Now => When::Now,
    }
}

pub struct View {
    core: Mutex<Core>,
    ttls: Ttls,
    keep_cache: bool,
    counts: Arc<Counts>,
}

impl View {
    pub fn new(spec: Spec, ttls: Ttls, keep_cache: bool, counts: Arc<Counts>) -> io::Result<View> {
        Ok(View { core: Mutex::new(Core::new(spec)?), ttls, keep_cache, counts })
    }

    /// *op*, on the tables, under the lock. A panic -- a bug -- fails this request, EIO, and no
    /// other: every jail using the view goes on being served.
    fn with<T>(&self, op: &str, f: impl FnOnce(&mut Core) -> Result<T, Errno>) -> Result<T, Errno> {
        let mut core = self.core.lock().unwrap_or_else(PoisonError::into_inner);
        panic::catch_unwind(AssertUnwindSafe(|| f(&mut *core)))
            .unwrap_or_else(|_| Err(bug(&format!("{op} panicked (see above); answered EIO"))))
    }

    fn entry(&self, reply: ReplyEntry, result: Result<Entry, Errno>) {
        match result {
            Ok(Entry { ino, st }) => {
                reply.entry_with_ttls(&self.ttls.attr(&st), &self.ttls.entry, &attr_of(&st, ino), Generation(0))
            }
            Err(e) => reply.error(e),
        }
    }

    fn attr(&self, reply: ReplyAttr, ino: INodeNo, result: Result<Stat, Errno>) {
        match result {
            Ok(st) => reply.attr(&self.ttls.attr(&st), &attr_of(&st, ino.0)),
            Err(e) => reply.error(e),
        }
    }

    fn empty(reply: ReplyEmpty, result: Result<(), Errno>) {
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn file_flags(&self) -> FopenFlags {
        if self.keep_cache {
            FopenFlags::FOPEN_KEEP_CACHE
        } else {
            FopenFlags::empty()
        }
    }
}

impl Filesystem for View {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // what libfuse negotiates for pyfuse3, and so for the Python view: listings always with
        // attributes, a file's cached pages dropped when its size or mtime is seen to change,
        // O_TRUNC sent with the open, lookups in parallel with listings
        for flag in [
            InitFlags::FUSE_DO_READDIRPLUS,
            InitFlags::FUSE_AUTO_INVAL_DATA,
            InitFlags::FUSE_ATOMIC_O_TRUNC,
            InitFlags::FUSE_PARALLEL_DIROPS,
        ] {
            if let Err(missing) = config.add_capabilities(flag) {
                eprintln!("fuseview-rs: the kernel does not offer {missing:?}");
            }
        }
        println!("ready");
        Ok(())
    }

    // -- names -----------------------------------------------------------------------------------

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.counts.lookup.fetch_add(1, Relaxed);
        let result = self.with("lookup", |core| core.lookup(parent.0, name));
        self.entry(reply, result);
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let _ = self.with("forget", |core| {
            core.unref(ino.0, nlookup);
            Ok(())
        });
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.with("opendir", |core| core.opendir(ino.0)) {
            Ok(fd) => reply.opened(FileHandle(fd as u64), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn readdirplus(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, offset: u64, mut reply: ReplyDirectoryPlus) {
        self.counts.readdir.fetch_add(1, Relaxed);
        let ttls = self.ttls;
        let result = self.with("readdirplus", |core| {
            core.readdirplus(fh.0, offset, &mut |entry, next, name| {
                reply.add(INodeNo(entry.ino), next, name, &ttls.both(&entry.st), &attr_of(&entry.st, entry.ino), Generation(0))
            })
        });
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn releasedir(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, reply: ReplyEmpty) {
        let result = self.with("releasedir", |core| {
            core.releasedir(fh.0);
            Ok(())
        });
        View::empty(reply, result);
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.with("create", |core| core.create(parent.0, name, mode, flags)) {
            Ok((Entry { ino, st }, fd)) => reply.created(
                &self.ttls.both(&st),
                &attr_of(&st, ino),
                Generation(0),
                FileHandle(fd as u64),
                self.file_flags(),
            ),
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, mode: u32, _umask: u32, reply: ReplyEntry) {
        let result = self.with("mkdir", |core| core.mkdir(parent.0, name, mode));
        self.entry(reply, result);
    }

    fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        let result = self.with("symlink", |core| core.symlink(parent.0, link_name, target));
        self.entry(reply, result);
    }

    fn link(&self, _req: &Request, ino: INodeNo, newparent: INodeNo, newname: &OsStr, reply: ReplyEntry) {
        let result = self.with("link", |core| core.link(ino.0, newparent.0, newname));
        self.entry(reply, result);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if !flags.is_empty() {
            return reply.error(Errno::EINVAL);
        }
        View::empty(reply, self.with("rename", |core| core.rename(parent.0, name, newparent.0, newname)));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        View::empty(reply, self.with("unlink", |core| core.remove(parent.0, name, 0)));
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        View::empty(reply, self.with("rmdir", |core| core.remove(parent.0, name, libc::AT_REMOVEDIR)));
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM); // no device nodes or fifos through the view
    }

    // -- inodes ----------------------------------------------------------------------------------

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.counts.getattr.fetch_add(1, Relaxed);
        let result = self.with("getattr", |core| core.stat_of(ino.0));
        self.attr(reply, ino, result);
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let change = Change { mode, uid, gid, size, atime: atime.map(when), mtime: mtime.map(when) };
        let result = self.with("setattr", |core| core.setattr(ino.0, &change, fh.map(|fh| fh.0)));
        self.attr(reply, ino, result);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.with("readlink", |core| core.readlink(ino.0)) {
            Ok(text) => reply.data(&text),
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.counts.open.fetch_add(1, Relaxed);
        match self.with("open", |core| core.open(ino.0, flags.0)) {
            Ok(fd) => reply.opened(FileHandle(fd as u64), self.file_flags()),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.counts.read.fetch_add(1, Relaxed);
        match sys::pread(fh.0 as RawFd, size as usize, offset) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e.into()),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match sys::pwrite(fh.0 as RawFd, data, offset) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(e.into()),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, datasync: bool, reply: ReplyEmpty) {
        View::empty(reply, sys::fsync(fh.0 as RawFd, datasync).map_err(Errno::from));
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let result = self.with("release", |core| {
            core.release(fh.0);
            Ok(())
        });
        View::empty(reply, result);
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.with("statfs", |core| core.statfs()) {
            Ok(st) => reply.statfs(
                st.f_blocks as u64,
                st.f_bfree as u64,
                st.f_bavail as u64,
                st.f_files as u64,
                st.f_ffree as u64,
                st.f_bsize as u32,
                st.f_namemax as u32,
                st.f_frsize as u32,
            ),
            Err(e) => reply.error(e),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::from_i32(libc::ENOTSUP));
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::from_i32(libc::ENOTSUP));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Access, Layer, Location, Region, Says};

    /// A directory `many` of three files, under target/, served whole: *access* to everything.
    fn served(name: &str, access: Access) -> (PathBuf, Core) {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-trees").join(name);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("many")).expect("a test tree");
        for f in ["f1", "f2", "f3"] {
            std::fs::write(base.join("many").join(f), f).expect("a test file");
        }
        let dir = std::fs::canonicalize(&base).expect("the tree's real path");
        let everything = Layer {
            region: Region::Pattern { location: Location::Splat { prefix: vec![], leaf: None }, anchor: dir.clone() },
            says: Says::Grant(access),
        };
        let core = Core::new(Spec { directory: dir.clone(), layers: vec![everything] }).expect("served");
        (dir, core)
    }

    #[test]
    fn a_directory_moves_under_one_whole_grant_and_its_inode_follows() {
        let (dir, mut core) = served("moving-dir", Access::Writable);
        let many = core.lookup(ROOT, OsStr::new("many")).expect("many").ino;
        core.lookup(many, OsStr::new("f1")).expect("many/f1");
        core.rename(ROOT, OsStr::new("many"), ROOT, OsStr::new("renamed")).expect("the directory moves");
        assert!(core.lookup(many, OsStr::new("f1")).is_ok()); // its recorded path moved with it
        assert!(dir.join("renamed").join("f1").exists());
        // cargo's target directory: made under a temporary name, renamed into place
        core.mkdir(ROOT, OsStr::new("targetXYZ"), 0o755).expect("the temporary");
        core.rename(ROOT, OsStr::new("targetXYZ"), ROOT, OsStr::new("target")).expect("renamed into place");
        assert!(dir.join("target").is_dir());
    }

    #[test]
    fn a_listing_outlives_its_directory_moving_and_a_lookup_does_not() {
        let (dir, mut core) = served("moving-listing", Access::ReadOnly);
        let many = core.lookup(ROOT, OsStr::new("many")).expect("many").ino;
        let listing = core.opendir(many).expect("a listing") as u64;
        let mut first = 0;
        core.readdirplus(listing, 0, &mut |_, _, _| {
            first += 1;
            first > 1 // a page with room for one entry
        })
        .expect("a first page");
        assert_eq!(first, 2); // one sent, one that did not fit
        std::fs::rename(dir.join("many"), dir.join("moved")).expect("moved behind the view");
        let mut rest = 0;
        core.readdirplus(listing, 1, &mut |_, _, _| {
            rest += 1;
            false
        })
        .expect("the later pages serve what the first page found");
        assert_eq!(rest, 2);
        assert_eq!(core.lookup(many, OsStr::new("f1")).err(), Some(Errno::ESTALE));
        core.releasedir(listing);
    }
}
