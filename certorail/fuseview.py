"""The FUSE view (MOUNTS.md): the sandbox root, served through a passthrough filesystem that
shows a confined tool exactly what the policy's filesystem section grants and lets it write
exactly what the section permits -- patterns included, which is what a bind mount cannot do.

The mount is one per (root, filesystem section) and long-lived (``viewdaemon``); bubblewrap binds
it at the root's real path for each confined child. The filesystem is a passthrough keyed by
backing-file reference, from ``scripts/probe_fuse_view.py`` where it was measured: a directory
inode holds an ``O_PATH`` descriptor (the anchor for every ``*at`` call), a file inode holds the
directory it was found in and its name there and is re-resolved on demand with an identity check,
an open handle is a real descriptor. What this module adds is the **filter**: every name the
kernel is shown or asked to create is decided against the policy by the analysis' own ordering
(``location_le``) on the concrete path -- exact, since one side is always a real path:

- a path is *readable* iff it lies within some ``read`` or ``write`` grant: a file's contents
  open, a directory lists every entry by name (listing a directory is reading it);
- an entry is *visible* -- it looks up, it is listed -- iff it is readable, its directory is, or
  (for a directory) some grant names a path below it; a name visible only because its directory
  is readable shows its metadata, never its contents;
- a name may be created, changed or removed iff its path lies within some ``write`` grant and at
  or below no ``no-write`` protection. Whether the child may write at all is bubblewrap's
  read-only bind, per rule (``write-fs``); the filesystem itself is always mounted writable.

Names are the directory's own: a lookup must name an entry exactly as the directory stores it, and
no operation may introduce a name the backing filesystem resolves to a differently spelled entry
(a case- or normalisation-folding filesystem would otherwise let ``.GIT`` reach ``.git``). Where
the directory's filesystem declares its lookups exact (``folding``), a name that resolves is so
stored; anywhere else, folding or unable to say, the name must appear in the directory's listing,
read afresh each time -- no cache, so nothing to go stale. A file
with several names cannot be written through the view, and a hard link may be made only to a file
that may be written: which of its names the policy would judge is not knowable.

A directory cannot be renamed through the view (EPERM): a file inode's visibility is a function
of its path, and moving a subtree would change every path beneath it under the kernel's cached
inodes. Files rename freely between permitted names. What is invisible is ENOENT, not EACCES;
what may not be written is EPERM.

Two integer domains meet here and the annotations keep them apart: the kernel's FUSE inode
numbers and file handles (``pyfuse3.InodeT``, ``pyfuse3.FileHandleT``: what the ``Operations``
methods receive), and the host's descriptors and inode identities (``NativeFd``, ``NativeKey``:
what ``os`` calls take). A handle handed to the kernel *is* a native descriptor here; the one
place a descriptor becomes a handle is spelled ``FileHandleT(fd)``.

Requires ``pyfuse3`` (the ``fuse`` extra); importing this module without it raises ImportError,
and ``viewdaemon`` reports the view unavailable.
"""
import errno
import os
import pathlib
import stat as statmod
from collections.abc import Sequence
from functools import lru_cache
from typing import override

import pyfuse3
from pyfuse3 import EntryAttributes, FileHandleT, FileInfo, FileNameT, FlagT, InodeT, ModeT, RequestContext

from certorail.analysis import DirSplat, LocationFact, Named, StaticPath, location_le, subsumes
from certorail.folding import exact_lookups

type NativeFd = int                 # a descriptor of this process (O_PATH or I/O)
type NativeKey = tuple[int, int]    # (st_dev, st_ino): a backing file's identity
type RelPath = tuple[str, ...]      # a path relative to the root, as component names


def _at(path: RelPath) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in path))


def _names_below(path: RelPath, loc: LocationFact) -> bool:
    """Does *loc* denote some path strictly below *path*?"""
    match loc:
        case StaticPath(path_components=cs):
            return len(cs) > len(path) and all(subsumes(c, Named(n)) for c, n in zip(cs, path))
        case DirSplat(static_prefix=ps):
            return all(subsumes(c, Named(n)) for c, n in zip(ps, path))


class Filter:
    """The policy's filesystem section, asked about concrete paths relative to the root, by the
    analysis' own ordering. Absolute locations are not the view's business: they are binds
    beside it."""

    def __init__(
        self,
        read: tuple[LocationFact, ...],
        write: tuple[LocationFact, ...],
        no_write: tuple[LocationFact, ...],
    ) -> None:
        def relative(locs: tuple[LocationFact, ...]) -> tuple[LocationFact, ...]:
            return tuple(loc for loc in locs if not loc.absolute)

        self.grants: tuple[LocationFact, ...] = relative(read) + relative(write)
        self.writes: tuple[LocationFact, ...] = relative(write)
        self.protections: tuple[LocationFact, ...] = relative(no_write)

    @lru_cache(maxsize=200_000)
    def readable(self, path: RelPath) -> bool:
        """Within some grant: a file's contents open, a directory lists every name."""
        return any(location_le(_at(path), g) for g in self.grants)

    @lru_cache(maxsize=200_000)
    def dir_visible(self, path: RelPath) -> bool:
        """A directory exists for the child iff it is readable or some grant names a path below
        it (the root always does)."""
        return not path or self.readable(path) or any(_names_below(path, g) for g in self.grants)

    def visible(self, path: RelPath, is_dir: bool) -> bool:
        """Does the entry look up and list? Readable, under a readable directory (its name
        only), or a directory on the way to a grant."""
        if path and self.readable(path[:-1]):
            return True
        return self.dir_visible(path) if is_dir else self.readable(path)

    @lru_cache(maxsize=200_000)
    def may_write(self, path: RelPath) -> bool:
        """Within some write grant, and at or below no protection."""
        if not path or not any(location_le(_at(path), w) for w in self.writes):
            return False
        return not any(
            location_le(_at(path[:k]), p) for p in self.protections for k in range(1, len(path) + 1)
        )


class Inode:
    """One FUSE inode the kernel knows about. A directory holds an O_PATH descriptor and its
    path; a file holds the directory it was found in and its name there (its path is derived)."""

    __slots__ = ("fd", "path", "parent", "name", "key", "refs")

    def __init__(
        self, key: NativeKey, *, fd: NativeFd | None = None, path: RelPath | None = None,
        parent: InodeT | None = None, name: FileNameT | None = None,
    ) -> None:
        self.fd = fd
        self.path = path
        self.parent = parent
        self.name = name
        self.key = key
        self.refs = 1


def _proc(fd: NativeFd) -> str:
    return f"/proc/self/fd/{fd}"


def raise_fd_limit() -> None:
    """A filesystem server holds descriptors for every directory the kernel has cached; the
    default soft limit (1024) is for interactive programs. Lift it to the hard limit."""
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


def _name(name: FileNameT) -> str:
    return os.fsdecode(name)


def _identity(st: os.stat_result) -> NativeKey:
    return (st.st_dev, st.st_ino)


class View(pyfuse3.Operations):
    supports_dot_lookup = True
    enable_writeback_cache = False

    def __init__(self, source: pathlib.Path, rules: Filter) -> None:
        super().__init__()
        self.rules = rules
        root_fd: NativeFd = os.open(source, os.O_PATH | os.O_DIRECTORY)
        root = Inode(_identity(os.stat(root_fd)), fd=root_fd, path=())
        self.inodes: dict[InodeT, Inode] = {pyfuse3.ROOT_INODE: root}
        self.by_key: dict[NativeKey, InodeT] = {root.key: pyfuse3.ROOT_INODE}
        self.next_inode: InodeT = pyfuse3.ROOT_INODE + 1
        # a directory handle (the descriptor scandir reads) -> the directory's inode and its
        # visible entries once scanned
        self.dir_handles: dict[FileHandleT, tuple[InodeT, list[tuple[FileNameT, os.stat_result]] | None]] = {}

    # -- paths and helpers ------------------------------------------------------------------

    def path_of(self, inode: InodeT) -> RelPath:
        node = self.inodes[inode]
        if node.path is not None:
            return node.path
        assert node.parent is not None and node.name is not None
        return (*self.path_of(node.parent), _name(node.name))

    def child_path(self, parent: InodeT, name: FileNameT) -> RelPath:
        return (*self.path_of(parent), _name(name))

    def writable_name(self, parent: InodeT, name: FileNameT) -> None:
        """*name* under *parent* may be created, replaced or removed, or EPERM."""
        if not self.rules.may_write(self.child_path(parent, name)):
            raise pyfuse3.FUSEError(errno.EPERM)

    def writable_inode(self, inode: InodeT) -> None:
        """The file itself may be written: its one name may, or EPERM. A file with several
        names is never written through the view -- the policy judges names, and which of this
        one's names it would judge is not knowable."""
        if inode == pyfuse3.ROOT_INODE or not self.rules.may_write(self.path_of(inode)):
            raise pyfuse3.FUSEError(errno.EPERM)
        st = self.stat_of(inode)
        if not statmod.S_ISDIR(st.st_mode) and st.st_nlink > 1:
            raise pyfuse3.FUSEError(errno.EPERM)

    def spelled_as_stored(self, parent: InodeT, name: FileNameT) -> bool:
        """Is *name*, which resolves under *parent*, the spelling the directory stores? Where the
        directory's lookups are exact, resolving says so; elsewhere only its listing does."""
        fd = self.parent_fd(parent)
        return exact_lookups(fd) or _name(name) in os.listdir(_proc(fd))

    def refuse_alias(self, parent: InodeT, name: FileNameT) -> None:
        """EEXIST when the backing filesystem resolves *name* to an entry it stores under another
        spelling: a folding filesystem would otherwise let a new name land on an existing one."""
        try:
            os.stat(name, dir_fd=self.parent_fd(parent), follow_symlinks=False)
        except FileNotFoundError:
            return
        if not self.spelled_as_stored(parent, name):
            raise pyfuse3.FUSEError(errno.EEXIST)

    def parent_fd(self, parent: InodeT) -> NativeFd:
        fd = self.inodes[parent].fd
        assert fd is not None  # the kernel names children only of directories, which hold one
        return fd

    def fd_of(self, inode: InodeT) -> NativeFd:
        """A live O_PATH descriptor for *inode*: held, for a directory; opened on demand for a
        file, by the name it was found under in its held parent, and refused (ESTALE) if what is
        there now is a different file. The caller closes a file's descriptor (``release_fd``)."""
        node = self.inodes[inode]
        if node.fd is not None:
            return node.fd
        assert node.parent is not None and node.name is not None
        try:
            fd: NativeFd = os.open(node.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=self.parent_fd(node.parent))
        except FileNotFoundError:
            raise pyfuse3.FUSEError(errno.ESTALE) from None
        if _identity(os.stat(fd)) != node.key:
            os.close(fd)
            raise pyfuse3.FUSEError(errno.ESTALE)
        return fd

    def release_fd(self, inode: InodeT, fd: NativeFd) -> None:
        if self.inodes[inode].fd is None:
            os.close(fd)

    def stat_of(self, inode: InodeT) -> os.stat_result:
        node = self.inodes[inode]
        if node.fd is not None:
            return os.stat(node.fd)
        assert node.parent is not None and node.name is not None
        try:
            st = os.stat(node.name, dir_fd=self.parent_fd(node.parent), follow_symlinks=False)
        except FileNotFoundError:
            raise pyfuse3.FUSEError(errno.ESTALE) from None
        if _identity(st) != node.key:
            raise pyfuse3.FUSEError(errno.ESTALE)
        return st

    def attrs_from(self, st: os.stat_result, inode: InodeT) -> EntryAttributes:
        entry = EntryAttributes()
        entry.st_ino = inode
        entry.st_mode = st.st_mode
        entry.st_nlink = st.st_nlink
        entry.st_uid = st.st_uid
        entry.st_gid = st.st_gid
        entry.st_rdev = st.st_rdev
        entry.st_size = st.st_size
        entry.st_blksize = st.st_blksize
        entry.st_blocks = st.st_blocks
        entry.st_atime_ns = st.st_atime_ns
        entry.st_mtime_ns = st.st_mtime_ns
        entry.st_ctime_ns = st.st_ctime_ns
        entry.generation = 0
        # the source changes under the kernel's nose (the program, other tools): cache briefly
        entry.entry_timeout = 1
        entry.attr_timeout = 1
        return entry

    def recorded_at(self, node: Inode, parent: InodeT, name: FileNameT, st: os.stat_result) -> bool:
        """Is *node* the entry *name* under *parent*, as the view recorded it: the same kind of
        entry, at the same place? Sharing a key is not enough. A file holds no descriptor, so
        once deleted its inode number is free for a new file or directory; and anything may be
        moved behind the view's back. The filter judges the recorded place."""
        if statmod.S_ISDIR(st.st_mode):
            return node.fd is not None and node.path == self.child_path(parent, name)
        return node.fd is None and node.parent == parent and node.name == name

    def admit(self, parent: InodeT, name: FileNameT, st: os.stat_result | None = None) -> EntryAttributes:
        """The entry *name* under the directory inode *parent* as an inode the kernel may hold:
        reuse the one recorded for it, or make one, bump the count, return its attributes. A
        key whose inode is recorded elsewhere gets a new inode, and the old one stays, unfindable
        by key, until the kernel forgets it."""
        parent_fd = self.parent_fd(parent)
        if st is None:
            try:
                st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                raise pyfuse3.FUSEError(errno.ENOENT) from None
        key = _identity(st)
        inode = self.by_key.get(key)
        if inode is not None and self.recorded_at(self.inodes[inode], parent, name, st):
            self.inodes[inode].refs += 1
            return self.attrs_from(st, inode)
        inode = self.next_inode
        self.next_inode += 1
        if statmod.S_ISDIR(st.st_mode):
            try:
                fd: NativeFd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)
            except OSError:
                raise pyfuse3.FUSEError(errno.ENOENT) from None
            self.inodes[inode] = Inode(key, fd=fd, path=self.child_path(parent, name))
        else:
            self.inodes[inode] = Inode(key, parent=parent, name=name)
            self.inodes[parent].refs += 1  # a file pins the directory it was found in
        self.by_key[key] = inode
        return self.attrs_from(st, inode)

    def drop(self, inode: InodeT, count: int) -> None:
        if inode == pyfuse3.ROOT_INODE:
            return
        node = self.inodes.get(inode)
        if node is None:
            return
        node.refs -= count
        if node.refs <= 0:
            del self.inodes[inode]
            if self.by_key.get(node.key) == inode:  # not if a newer inode took the key
                del self.by_key[node.key]
            if node.fd is not None:
                os.close(node.fd)
            if node.parent is not None:
                self.drop(node.parent, 1)

    # -- names: the filter lives here -------------------------------------------------------

    @override
    async def lookup(self, parent_inode: InodeT, name: FileNameT, ctx: RequestContext) -> EntryAttributes:
        try:
            st = os.stat(name, dir_fd=self.parent_fd(parent_inode), follow_symlinks=False)
        except FileNotFoundError:
            raise pyfuse3.FUSEError(errno.ENOENT) from None
        if not self.spelled_as_stored(parent_inode, name):
            raise pyfuse3.FUSEError(errno.ENOENT)  # another spelling of an entry: not this name
        if not self.rules.visible(self.child_path(parent_inode, name), statmod.S_ISDIR(st.st_mode)):
            raise pyfuse3.FUSEError(errno.ENOENT)  # the name does not exist, not "may not"
        return self.admit(parent_inode, name, st)

    @override
    async def forget(self, inode_list: Sequence[tuple[InodeT, int]]) -> None:
        for inode, nlookup in inode_list:
            self.drop(inode, nlookup)

    @override
    async def opendir(self, inode: InodeT, ctx: RequestContext) -> FileHandleT:
        fd: NativeFd = os.open(_proc(self.fd_of(inode)), os.O_RDONLY | os.O_DIRECTORY)
        fh = FileHandleT(fd)  # the handle the kernel holds is the descriptor scandir reads
        self.dir_handles[fh] = (inode, None)
        return fh

    @override
    async def readdir(self, fh: FileHandleT, start_id: int, token: pyfuse3.ReaddirToken) -> None:
        # scanned once per open handle, invisible names dropped there; continuations index the
        # cached list; entries are admitted (readdirplus) so the kernel skips a lookup round trip
        parent, entries = self.dir_handles[fh]
        if entries is None:
            entries = []
            base = self.path_of(parent)
            with os.scandir(fh) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # vanished mid-scan
                    if self.rules.visible((*base, e.name), statmod.S_ISDIR(st.st_mode)):
                        entries.append((os.fsencode(e.name), st))
            os.lseek(fh, 0, os.SEEK_SET)
            self.dir_handles[fh] = (parent, entries)
        for i in range(start_id, len(entries)):
            name, st = entries[i]
            entry = self.admit(parent, name, st)
            if not pyfuse3.readdir_reply(token, name, entry, i + 1):
                self.drop(entry.st_ino, 1)
                break

    @override
    async def releasedir(self, fh: FileHandleT) -> None:
        del self.dir_handles[fh]
        os.close(fh)

    @override
    async def create(
        self, parent_inode: InodeT, name: FileNameT, mode: ModeT, flags: FlagT, ctx: RequestContext,
    ) -> tuple[FileInfo, EntryAttributes]:
        self.writable_name(parent_inode, name)
        self.refuse_alias(parent_inode, name)
        fd: NativeFd = os.open(name, flags | os.O_CREAT | os.O_EXCL, mode, dir_fd=self.fd_of(parent_inode))
        entry = self.admit(parent_inode, name)
        return FileInfo(fh=FileHandleT(fd)), entry

    @override
    async def mkdir(self, parent_inode: InodeT, name: FileNameT, mode: ModeT, ctx: RequestContext) -> EntryAttributes:
        self.writable_name(parent_inode, name)
        self.refuse_alias(parent_inode, name)
        os.mkdir(name, mode, dir_fd=self.fd_of(parent_inode))
        return self.admit(parent_inode, name)

    @override
    async def symlink(
        self, parent_inode: InodeT, name: FileNameT, target: FileNameT, ctx: RequestContext,
    ) -> EntryAttributes:
        self.writable_name(parent_inode, name)
        self.refuse_alias(parent_inode, name)
        os.symlink(target, name, dir_fd=self.fd_of(parent_inode))
        return self.admit(parent_inode, name)

    @override
    async def link(
        self, inode: InodeT, new_parent_inode: InodeT, new_name: FileNameT, ctx: RequestContext,
    ) -> EntryAttributes:
        self.writable_name(new_parent_inode, new_name)
        self.refuse_alias(new_parent_inode, new_name)
        # a new name for a file is a way to write it later: only for a file that may be written
        self.writable_inode(inode)
        fd = self.fd_of(inode)
        try:
            os.link(_proc(fd), new_name, dst_dir_fd=self.fd_of(new_parent_inode), follow_symlinks=True)
        finally:
            self.release_fd(inode, fd)
        return self.admit(new_parent_inode, new_name)

    @override
    async def rename(
        self, parent_inode_old: InodeT, name_old: FileNameT, parent_inode_new: InodeT, name_new: FileNameT,
        flags: FlagT, ctx: RequestContext,
    ) -> None:
        if flags:
            raise pyfuse3.FUSEError(errno.EINVAL)
        self.writable_name(parent_inode_old, name_old)  # removing the old name is a write there
        self.writable_name(parent_inode_new, name_new)
        self.refuse_alias(parent_inode_new, name_new)  # renaming onto another spelling replaces that entry
        old_fd = self.fd_of(parent_inode_old)
        try:
            st = os.stat(name_old, dir_fd=old_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise pyfuse3.FUSEError(errno.ENOENT) from None
        if statmod.S_ISDIR(st.st_mode):
            raise pyfuse3.FUSEError(errno.EPERM)  # a directory's path is every path beneath it
        os.rename(name_old, name_new, src_dir_fd=old_fd, dst_dir_fd=self.fd_of(parent_inode_new))
        inode = self.by_key.get(_identity(st))
        if inode is not None and self.recorded_at(self.inodes[inode], parent_inode_old, name_old, st):
            node = self.inodes[inode]
            self.drop(parent_inode_old, 1)
            node.parent, node.name = parent_inode_new, name_new
            self.inodes[parent_inode_new].refs += 1

    @override
    async def unlink(self, parent_inode: InodeT, name: FileNameT, ctx: RequestContext) -> None:
        self.writable_name(parent_inode, name)
        os.unlink(name, dir_fd=self.fd_of(parent_inode))

    @override
    async def rmdir(self, parent_inode: InodeT, name: FileNameT, ctx: RequestContext) -> None:
        self.writable_name(parent_inode, name)
        os.rmdir(name, dir_fd=self.fd_of(parent_inode))

    # -- inodes: no names involved ----------------------------------------------------------

    @override
    async def getattr(self, inode: InodeT, ctx: RequestContext) -> EntryAttributes:
        return self.attrs_from(self.stat_of(inode), inode)

    @override
    async def setattr(
        self, inode: InodeT, attr: EntryAttributes, fields: pyfuse3.SetattrFields, fh: FileHandleT | None,
        ctx: RequestContext,
    ) -> EntryAttributes:
        self.writable_inode(inode)
        fd = self.fd_of(inode)
        try:
            path = _proc(fd)
            if fields.update_mode:
                os.chmod(path, statmod.S_IMODE(attr.st_mode))
            if fields.update_size:
                os.truncate(path, attr.st_size)
            if fields.update_uid or fields.update_gid:
                os.chown(path, attr.st_uid if fields.update_uid else -1, attr.st_gid if fields.update_gid else -1)
            if fields.update_atime or fields.update_mtime:
                os.utime(path, ns=(attr.st_atime_ns, attr.st_mtime_ns))
        finally:
            self.release_fd(inode, fd)
        return await self.getattr(inode, ctx)

    @override
    async def readlink(self, inode: InodeT, ctx: RequestContext) -> FileNameT:
        # the link text passes through; the kernel resolves it inside the view, so an invisible
        # target simply fails to look up. An absolute target escapes the view: bwrap's job.
        node = self.inodes[inode]
        if node.fd is not None:
            return os.fsencode(os.readlink(_proc(node.fd)))
        assert node.parent is not None and node.name is not None
        self.stat_of(inode)  # identity check
        return os.fsencode(os.readlink(node.name, dir_fd=self.parent_fd(node.parent)))

    @override
    async def open(self, inode: InodeT, flags: FlagT, ctx: RequestContext) -> FileInfo:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC):
            self.writable_inode(inode)
        elif not self.rules.readable(self.path_of(inode)):
            raise pyfuse3.FUSEError(errno.EACCES)  # listed by name under a readable directory only
        # promote the reference to an I/O descriptor: the open handle then keeps the file alive
        # by itself, whatever happens to its names
        node = self.inodes[inode]
        fd: NativeFd
        if node.fd is not None:
            fd = os.open(_proc(node.fd), flags & ~os.O_NOFOLLOW)
        else:
            assert node.parent is not None and node.name is not None
            try:
                fd = os.open(node.name, (flags & ~os.O_CREAT) | os.O_NOFOLLOW, dir_fd=self.parent_fd(node.parent))
            except FileNotFoundError:
                raise pyfuse3.FUSEError(errno.ESTALE) from None
            if _identity(os.fstat(fd)) != node.key:
                os.close(fd)
                raise pyfuse3.FUSEError(errno.ESTALE)
        return FileInfo(fh=FileHandleT(fd))

    @override
    async def read(self, fh: FileHandleT, off: int, size: int) -> bytes:
        return os.pread(fh, size, off)

    @override
    async def write(self, fh: FileHandleT, off: int, buf: bytes) -> int:
        return os.pwrite(fh, buf, off)

    @override
    async def flush(self, fh: FileHandleT) -> None:
        pass

    @override
    async def fsync(self, fh: FileHandleT, datasync: bool) -> None:
        os.fsync(fh)

    @override
    async def release(self, fh: FileHandleT) -> None:
        os.close(fh)

    @override
    async def statfs(self, ctx: RequestContext) -> pyfuse3.StatvfsData:
        st = os.statvfs(_proc(self.fd_of(pyfuse3.ROOT_INODE)))
        out = pyfuse3.StatvfsData()
        for attr in ("f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_favail"):
            setattr(out, attr, getattr(st, attr))
        return out

    @override
    async def mknod(
        self, parent_inode: InodeT, name: FileNameT, mode: ModeT, rdev: int, ctx: RequestContext,
    ) -> EntryAttributes:
        raise pyfuse3.FUSEError(errno.EPERM)  # no device nodes or fifos through the view

    @override
    async def setxattr(self, inode: InodeT, name: pyfuse3.XAttrNameT, value: bytes, ctx: RequestContext) -> None:
        raise pyfuse3.FUSEError(errno.ENOTSUP)

    @override
    async def removexattr(self, inode: InodeT, name: pyfuse3.XAttrNameT, ctx: RequestContext) -> None:
        raise pyfuse3.FUSEError(errno.ENOTSUP)
