"""Does a directory resolve names byte for byte? The FUSE view's one question about folding
(``fuseview``): where lookups are exact, a name that resolves is the name the directory stores and
nothing more need be asked; where the filesystem folds case or Unicode normalisation, or cannot say
whether it does, only the directory's listing tells a stored name from a folded spelling of one.

The answer is what the filesystem declares, never a trial. ``fstatfs``'s ``f_type`` names the
driver (statfs(2): the constants of ``linux/magic.h``). Where the driver folds per directory --
ext4, f2fs and tmpfs fold only a directory carrying the casefold attribute -- ``FS_IOC_GETFLAGS``
reads that attribute off the directory itself (ioctl_iflags(2)). It governs lookups in that
directory alone: a subdirectory carries its own, so the one directory a lookup happens in is the
one asked. Every other filesystem, and any failure to ask, is "cannot say". An allowlist, then: a
driver missing from it costs a listing, never an alias. XFS stays out until the kernel reports its
legacy case-insensitive mode; FUSE (whose backend is invisible) and the network filesystems (whose
server decides) stay out for good.

Linux only. ``fstatfs`` is reached through ``ctypes`` in the process's own C library (glibc or
musl alike: ``CDLL(None)`` is the global symbol scope the interpreter already links), and only
``f_type`` is read -- the structure's first field, a C ``long`` on x86_64 and aarch64. The ioctl
number is the generic encoding those platforms share; on one that encodes differently the ioctl
fails, which reads as "cannot say".
"""
import ctypes
import fcntl
import os
import struct

# statfs(2) f_type values
_EXT = 0xEF53          # ext2, ext3 and ext4 share it; only ext4 folds, per directory
_F2FS = 0xF2F52010
_TMPFS = 0x01021994    # per directory, since Linux 6.13
_BTRFS = 0x9123683E    # never folds

_NEVER_FOLDS = frozenset({_BTRFS})
_FOLDS_PER_DIRECTORY = frozenset({_EXT, _F2FS, _TMPFS})

# ioctl_iflags(2): _IOR('f', 1, long), though the argument is an int
_FS_IOC_GETFLAGS = (2 << 30) | (ctypes.sizeof(ctypes.c_long) << 16) | (ord("f") << 8) | 1
_FS_CASEFOLD_FL = 0x40000000

_libc = ctypes.CDLL(None, use_errno=True)
_libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
_libc.fstatfs.restype = ctypes.c_int
_STATFS_BYTES = 256  # room for any platform's struct statfs (120 bytes on 64-bit Linux)


def fs_type(fd: int) -> int | None:
    """The filesystem type of the descriptor *fd* (an ``O_PATH`` one will do), or None when
    ``fstatfs`` fails. The low 32 bits: the field is signed on some platforms, and btrfs's magic
    has the high bit set."""
    buf = ctypes.create_string_buffer(_STATFS_BYTES)
    if _libc.fstatfs(fd, buf) != 0:
        return None
    return ctypes.c_ulong.from_buffer(buf).value & 0xFFFF_FFFF


def _declared_exact(dir_fd: int) -> bool:
    """Does the directory's attribute word read, and without casefold? The ioctl wants a real
    descriptor, so the directory is reopened for reading through its ``O_PATH`` one."""
    try:
        fd = os.open(f"/proc/self/fd/{dir_fd}", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return False
    try:
        flags = fcntl.ioctl(fd, _FS_IOC_GETFLAGS, bytes(8))
    except OSError:
        return False
    finally:
        os.close(fd)
    return not struct.unpack_from("i", flags)[0] & _FS_CASEFOLD_FL


def exact_lookups(dir_fd: int) -> bool:
    """Does the directory behind *dir_fd* resolve names byte for byte, as its filesystem
    declares? False when it folds, and when it cannot say."""
    kind = fs_type(dir_fd)
    if kind in _NEVER_FOLDS:
        return True
    return kind in _FOLDS_PER_DIRECTORY and _declared_exact(dir_fd)
