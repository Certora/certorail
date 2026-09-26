//! The system calls the view makes, over libc. Every descriptor opened here is close-on-exec, as
//! Python opens them; one the caller owns comes back as an `OwnedFd`.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A backing file's identity: device, inode number, and file type -- an inode number a deleted
/// file freed may come back as a directory.
pub type Key = (u64, u64, u32);

/// What stat(2) says, in the fields the view uses.
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: (i64, i64),
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

impl Stat {
    #[allow(clippy::unnecessary_cast)] // the field types differ between platforms
    fn of(st: &libc::stat) -> Stat {
        Stat {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mode: st.st_mode as u32,
            nlink: st.st_nlink as u64,
            uid: st.st_uid as u32,
            gid: st.st_gid as u32,
            rdev: st.st_rdev as u64,
            size: st.st_size as i64,
            blksize: st.st_blksize as i64,
            blocks: st.st_blocks as i64,
            atime: (st.st_atime as i64, st.st_atime_nsec as i64),
            mtime: (st.st_mtime as i64, st.st_mtime_nsec as i64),
            ctime: (st.st_ctime as i64, st.st_ctime_nsec as i64),
        }
    }

    pub fn key(&self) -> Key {
        (self.dev, self.ino, self.mode & libc::S_IFMT)
    }

    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn check_size(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn c(text: &OsStr) -> io::Result<CString> {
    CString::new(text.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    check(fd).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn proc_path(fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

/// *base* with *names* below it.
pub fn join(base: &Path, names: &[OsString]) -> PathBuf {
    let mut path = base.to_path_buf();
    path.extend(names);
    path
}

pub fn open(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let path = c(path.as_os_str())?;
    owned(unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) })
}

pub fn openat(dir: RawFd, name: &OsStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let name = c(name)?;
    owned(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })
}

/// The inherited descriptor *fd*, now owned, while it is open.
pub fn adopt(fd: RawFd) -> Result<OwnedFd, String> {
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!("descriptor {fd} is not open"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Close a descriptor handed to the kernel as a handle: nothing it could act on depends on the result.
pub fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

pub fn fstat(fd: RawFd) -> io::Result<Stat> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    Ok(Stat::of(unsafe { st.assume_init_ref() }))
}

/// The entry *name* under *dir*, not following a link.
pub fn fstatat(dir: RawFd, name: &OsStr) -> io::Result<Stat> {
    let name = c(name)?;
    let mut st = MaybeUninit::<libc::stat>::uninit();
    check(unsafe { libc::fstatat(dir, name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(Stat::of(unsafe { st.assume_init_ref() }))
}

/// Where the object *fd* refers to is, as the kernel reports it (`fuseview._located`): the whole
/// path, computed at one instant from real directory entries, so no symbolic link is on it. None:
/// it has no path any more (it was removed).
pub fn located(fd: RawFd) -> io::Result<Option<PathBuf>> {
    let path = std::fs::read_link(proc_path(fd))?;
    if path.as_os_str().as_bytes().ends_with(b" (deleted)") && fstat(fd)?.nlink == 0 {
        return Ok(None);
    }
    Ok(Some(path))
}

/// Is the object *fd* refers to at *path*, exactly?
pub fn is_at(fd: RawFd, path: &Path) -> io::Result<bool> {
    Ok(located(fd)?.is_some_and(|at| at.as_os_str() == path.as_os_str()))
}

pub fn mkdirat(dir: RawFd, name: &OsStr, mode: u32) -> io::Result<()> {
    let name = c(name)?;
    check(unsafe { libc::mkdirat(dir, name.as_ptr(), mode as libc::mode_t) }).map(drop)
}

pub fn symlinkat(target: &OsStr, dir: RawFd, name: &OsStr) -> io::Result<()> {
    let (target, name) = (c(target)?, c(name)?);
    check(unsafe { libc::symlinkat(target.as_ptr(), dir, name.as_ptr()) }).map(drop)
}

/// A new name, *name* under *dir*, for the object *fd* refers to: through its /proc link, which
/// links an O_PATH descriptor without CAP_DAC_READ_SEARCH.
pub fn link_fd(fd: RawFd, dir: RawFd, name: &OsStr) -> io::Result<()> {
    let (from, name) = (c(proc_path(fd).as_os_str())?, c(name)?);
    check(unsafe { libc::linkat(libc::AT_FDCWD, from.as_ptr(), dir, name.as_ptr(), libc::AT_SYMLINK_FOLLOW) })
        .map(drop)
}

pub fn renameat(old_dir: RawFd, old: &OsStr, new_dir: RawFd, new: &OsStr) -> io::Result<()> {
    let (old, new) = (c(old)?, c(new)?);
    check(unsafe { libc::renameat(old_dir, old.as_ptr(), new_dir, new.as_ptr()) }).map(drop)
}

pub fn unlinkat(dir: RawFd, name: &OsStr, flags: libc::c_int) -> io::Result<()> {
    let name = c(name)?;
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), flags) }).map(drop)
}

/// The text of the link *name* under *dir*.
pub fn readlinkat(dir: RawFd, name: &OsStr) -> io::Result<Vec<u8>> {
    let name = c(name)?;
    let mut buf = vec![0u8; 256];
    loop {
        let n = check_size(unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })?;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

pub fn pread(fd: RawFd, size: usize, offset: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let n = check_size(unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), size, offset as libc::off_t) })?;
    buf.truncate(n);
    Ok(buf)
}

pub fn pwrite(fd: RawFd, data: &[u8], offset: u64) -> io::Result<usize> {
    check_size(unsafe { libc::pwrite(fd, data.as_ptr().cast(), data.len(), offset as libc::off_t) })
}

pub fn ftruncate(fd: RawFd, size: u64) -> io::Result<()> {
    check(unsafe { libc::ftruncate(fd, size as libc::off_t) }).map(drop)
}

pub fn fsync(fd: RawFd, datasync: bool) -> io::Result<()> {
    check(unsafe { if datasync { libc::fdatasync(fd) } else { libc::fsync(fd) } }).map(drop)
}

pub fn statvfs(path: &Path) -> io::Result<libc::statvfs> {
    let path = c(path.as_os_str())?;
    let mut st = MaybeUninit::<libc::statvfs>::uninit();
    check(unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) })?;
    Ok(unsafe { st.assume_init() })
}

// -- setattr --------------------------------------------------------------------------------------

pub enum When {
    At(SystemTime),
    Now,
}

/// What a setattr asks: each field it leaves alone is None.
pub struct Change {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<When>,
    pub mtime: Option<When>,
}

/// What a setattr acts on: a descriptor open on the file, or an O_PATH one, acted on through its
/// /proc link, which leads to the file itself.
pub enum Target {
    Open(RawFd),
    Path(RawFd),
}

fn timespec(when: Option<&When>) -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    match when {
        None => ts.tv_nsec = libc::UTIME_OMIT as _, // left alone: it keeps its value
        Some(When::Now) => ts.tv_nsec = libc::UTIME_NOW as _,
        Some(When::At(t)) => {
            let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
                Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
                Err(before) => {
                    let d = before.duration();
                    let (s, n) = (d.as_secs() as i64, d.subsec_nanos() as i64);
                    if n == 0 {
                        (-s, 0)
                    } else {
                        (-s - 1, 1_000_000_000 - n)
                    }
                }
            };
            ts.tv_sec = sec as libc::time_t;
            ts.tv_nsec = nsec as _;
        }
    }
    ts
}

impl Change {
    /// Done to *target*, in the Python view's order: mode, size, owner, times.
    pub fn apply(&self, target: Target) -> io::Result<()> {
        let (fd, path) = match target {
            Target::Open(fd) => (fd, None),
            Target::Path(fd) => (fd, Some(c(proc_path(fd).as_os_str())?)),
        };
        if let Some(mode) = self.mode {
            let mode = (mode & 0o7777) as libc::mode_t;
            check(match &path {
                None => unsafe { libc::fchmod(fd, mode) },
                Some(p) => unsafe { libc::chmod(p.as_ptr(), mode) },
            })?;
        }
        if let Some(size) = self.size {
            let size = size as libc::off_t;
            check(match &path {
                None => unsafe { libc::ftruncate(fd, size) },
                Some(p) => unsafe { libc::truncate(p.as_ptr(), size) },
            })?;
        }
        if self.uid.is_some() || self.gid.is_some() {
            // -1: unchanged
            let (uid, gid) = (self.uid.unwrap_or(u32::MAX), self.gid.unwrap_or(u32::MAX));
            check(match &path {
                None => unsafe { libc::fchown(fd, uid, gid) },
                Some(p) => unsafe { libc::chown(p.as_ptr(), uid, gid) },
            })?;
        }
        if self.atime.is_some() || self.mtime.is_some() {
            let times = [timespec(self.atime.as_ref()), timespec(self.mtime.as_ref())];
            check(match &path {
                None => unsafe { libc::futimens(fd, times.as_ptr()) },
                Some(p) => unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), times.as_ptr(), 0) },
            })?;
        }
        Ok(())
    }
}

pub fn system_time((sec, nsec): (i64, i64)) -> SystemTime {
    let nanos = Duration::from_nanos(nsec.clamp(0, 999_999_999) as u64);
    if sec >= 0 {
        UNIX_EPOCH + Duration::from_secs(sec as u64) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(sec.unsigned_abs()) + nanos
    }
}

// -- folding (certorail/folding.py) ---------------------------------------------------------------

// statfs(2) f_type values
const EXT: u32 = 0xEF53; // ext2, ext3 and ext4 share it; only ext4 folds, per directory
const F2FS: u32 = 0xF2F52010;
const TMPFS: u32 = 0x01021994; // per directory, since Linux 6.13
const BTRFS: u32 = 0x9123683E; // never folds

// ioctl_iflags(2): _IOR('f', 1, long), though the argument is an int
const FS_IOC_GETFLAGS: u64 = (2 << 30) | ((std::mem::size_of::<libc::c_long>() as u64) << 16) | ((b'f' as u64) << 8) | 1;
const FS_CASEFOLD_FL: i32 = 0x40000000;

fn fs_type(fd: RawFd) -> Option<u32> {
    let mut st = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(fd, st.as_mut_ptr()) } != 0 {
        return None;
    }
    // the low 32 bits: the field is signed on some platforms, and btrfs's magic has the high bit set
    Some((unsafe { st.assume_init_ref() }.f_type as u64 & 0xFFFF_FFFF) as u32)
}

/// Does the directory's attribute word read, and without casefold? The ioctl wants a real
/// descriptor, so the directory is reopened for reading through its O_PATH one.
fn declared_exact(dir: RawFd) -> bool {
    let Ok(fd) = open(&proc_path(dir), libc::O_RDONLY | libc::O_DIRECTORY) else {
        return false;
    };
    let mut flags = [0u8; 8];
    if unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFLAGS as _, flags.as_mut_ptr()) } != 0 {
        return false;
    }
    let word = i32::from_ne_bytes([flags[0], flags[1], flags[2], flags[3]]);
    word & FS_CASEFOLD_FL == 0
}

/// Does the directory behind *dir* resolve names byte for byte, as its filesystem declares? False
/// when it folds, and when it cannot say (`folding.exact_lookups`).
pub fn exact_lookups(dir: RawFd) -> bool {
    match fs_type(dir) {
        Some(BTRFS) => true,
        Some(EXT | F2FS | TMPFS) => declared_exact(dir),
        _ => false,
    }
}

// -- the process ----------------------------------------------------------------------------------

/// A filesystem server holds descriptors for every directory the kernel has cached; the default
/// soft limit (1024) is for interactive programs. Lift it to the hard limit.
pub fn raise_fd_limit() {
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

pub fn clear_umask() {
    unsafe {
        libc::umask(0);
    }
}

/// Signals taken synchronously: blocked in every thread (block before any is spawned, and each
/// inherits the mask), and waited for by one. None ever interrupts a request in flight.
pub struct Signals(libc::sigset_t);

impl Signals {
    pub fn of(signals: &[libc::c_int]) -> Signals {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for &signal in signals {
                libc::sigaddset(&mut set, signal);
            }
            Signals(set)
        }
    }

    pub fn block(&self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, &self.0, std::ptr::null_mut());
        }
    }

    pub fn wait(&self) -> libc::c_int {
        let mut signal = 0;
        while unsafe { libc::sigwait(&self.0, &mut signal) } != 0 {}
        signal
    }
}

/// *signal*, to this process: whichever thread waits for it takes it.
pub fn signal_self(signal: libc::c_int) {
    unsafe {
        libc::kill(libc::getpid(), signal);
    }
}
