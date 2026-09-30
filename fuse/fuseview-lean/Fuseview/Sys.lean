import Fuseview.Bytes

/-!
The system calls, over `c/shim.c`: each returns `Except Errno α` -- the errno, or the value -- and
never throws. A descriptor is a `UInt32`; the numbers below are x86_64's (the shim asserts them).
-/
namespace Fuseview

abbrev Errno := UInt32
abbrev Fd := UInt32

def EPERM : Errno := 1
def ENOENT : Errno := 2
def EINTR : Errno := 4
def EIO : Errno := 5
def EBADF : Errno := 9
def EAGAIN : Errno := 11
def EACCES : Errno := 13
def EEXIST : Errno := 17
def ENODEV : Errno := 19
def ENOTDIR : Errno := 20
def EINVAL : Errno := 22
def ENOSYS : Errno := 38
def ENOTSUP : Errno := 95
def ESTALE : Errno := 116

namespace O
def RDONLY : UInt32 := 0
def WRONLY : UInt32 := 0o1
def RDWR : UInt32 := 0o2
def CREAT : UInt32 := 0o100
def EXCL : UInt32 := 0o200
def TRUNC : UInt32 := 0o1000
def APPEND : UInt32 := 0o2000
def DIRECTORY : UInt32 := 0o200000
def NOFOLLOW : UInt32 := 0o400000
def PATH : UInt32 := 0o10000000
end O

def AT_REMOVEDIR : UInt32 := 0x200

namespace LOCK
def SH : UInt32 := 1
def EX : UInt32 := 2
def NB : UInt32 := 4
def UN : UInt32 := 8
end LOCK

-- a lock's type, as `struct flock` and `struct fuse_file_lock` both carry it
namespace F
def RDLCK : UInt32 := 0
def WRLCK : UInt32 := 1
def UNLCK : UInt32 := 2
end F

/-- What stat(2) says, in the fields the view uses. -/
structure Stat where
  dev : UInt64
  ino : UInt64
  mode : UInt32
  nlink : UInt64
  uid : UInt32
  gid : UInt32
  rdev : UInt64
  size : UInt64
  blksize : UInt64
  blocks : UInt64
  atime : UInt64
  atimeNs : UInt32
  mtime : UInt64
  mtimeNs : UInt32
  ctime : UInt64
  ctimeNs : UInt32
  deriving Inhabited

/-- A backing file's identity: device, inode number, and file type -- an inode number a deleted
file freed may come back as a directory. -/
abbrev Key := UInt64 × UInt64 × UInt32

def S_IFMT : UInt32 := 0o170000
def S_IFDIR : UInt32 := 0o040000

namespace Stat
def decode (b : ByteArray) : Stat where
  dev := rd64 b 0
  ino := rd64 b 8
  mode := (rd64 b 16).toUInt32
  nlink := rd64 b 24
  uid := (rd64 b 32).toUInt32
  gid := (rd64 b 40).toUInt32
  rdev := rd64 b 48
  size := rd64 b 56
  blksize := rd64 b 64
  blocks := rd64 b 72
  atime := rd64 b 80
  atimeNs := (rd64 b 88).toUInt32
  mtime := rd64 b 96
  mtimeNs := (rd64 b 104).toUInt32
  ctime := rd64 b 112
  ctimeNs := (rd64 b 120).toUInt32

def key (s : Stat) : Key := (s.dev, s.ino, s.mode &&& S_IFMT)
def isDir (s : Stat) : Bool := s.mode &&& S_IFMT == S_IFDIR
end Stat

namespace Sys

/-- One request from the FUSE device, read into *buf* when nothing else holds it -- hand the last
request back, and the daemon allocates one buffer for its life -- else into a fresh one of
*capacity* bytes, which must hold the largest request. -/
@[extern "fv_fuse_read"] opaque fuseRead (fd : Fd) (buf : ByteArray) (capacity : UInt32) : IO (Except Errno ByteArray)
@[extern "fv_writev"] opaque writev (fd : Fd) (head : @& ByteArray) (body : @& ByteArray) : IO (Except Errno UInt32)

@[extern "fv_open"] opaque openPath (path : @& ByteArray) (flags : UInt32) : IO (Except Errno Fd)
@[extern "fv_openat"] opaque openat (dir : Fd) (name : @& ByteArray) (flags mode : UInt32) : IO (Except Errno Fd)
@[extern "fv_reopen"] opaque reopen (fd : Fd) (flags : UInt32) : IO (Except Errno Fd)
@[extern "fv_close"] opaque close (fd : Fd) : IO Unit
@[extern "fv_fd_open"] opaque fdOpen (fd : Fd) : IO Bool
@[extern "fv_wait_readable"] opaque waitReadable (fd : Fd) (ms : UInt32) : IO (Except Errno Bool)

@[extern "fv_flock"] opaque flock (fd : Fd) (op : UInt32) : IO (Except Errno Unit)
@[extern "fv_ofd_lock"] opaque ofdLock (fd : Fd) (type : UInt32) (start len : UInt64) : IO (Except Errno Unit)
@[extern "fv_ofd_test"] opaque ofdTest (fd : Fd) (type : UInt32) (start len : UInt64) : IO (Except Errno ByteArray)

@[extern "fv_fstat"] opaque fstatRaw (fd : Fd) : IO (Except Errno ByteArray)
@[extern "fv_fstatat"] opaque fstatatRaw (dir : Fd) (name : @& ByteArray) : IO (Except Errno ByteArray)
@[extern "fv_readlink_fd"] opaque readlinkFd (fd : Fd) : IO (Except Errno ByteArray)
@[extern "fv_readlinkat"] opaque readlinkat (dir : Fd) (name : @& ByteArray) : IO (Except Errno ByteArray)
@[extern "fv_listdir"] opaque listdir (fd : Fd) : IO (Except Errno (Array ByteArray))

@[extern "fv_mkdirat"] opaque mkdirat (dir : Fd) (name : @& ByteArray) (mode : UInt32) : IO (Except Errno Unit)
@[extern "fv_symlinkat"] opaque symlinkat (target : @& ByteArray) (dir : Fd) (name : @& ByteArray) : IO (Except Errno Unit)
@[extern "fv_link_fd"] opaque linkFd (fd dir : Fd) (name : @& ByteArray) : IO (Except Errno Unit)
@[extern "fv_renameat"] opaque renameat (oldDir : Fd) (old : @& ByteArray) (newDir : Fd) (new : @& ByteArray) : IO (Except Errno Unit)
@[extern "fv_unlinkat"] opaque unlinkat (dir : Fd) (name : @& ByteArray) (flags : UInt32) : IO (Except Errno Unit)

@[extern "fv_pread"] opaque pread (fd : Fd) (size : UInt32) (offset : UInt64) : IO (Except Errno ByteArray)
@[extern "fv_pwrite"] opaque pwrite (fd : Fd) (buf : @& ByteArray) (start len : UInt32) (offset : UInt64) : IO (Except Errno UInt32)
@[extern "fv_ftruncate"] opaque ftruncate (fd : Fd) (size : UInt64) : IO (Except Errno Unit)
@[extern "fv_fsync"] opaque fsync (fd : Fd) (datasync : UInt8) : IO (Except Errno Unit)
@[extern "fv_setattr"] opaque setattr (fd : Fd) (viaProc : UInt8) (valid mode uid gid : UInt32) (size atime : UInt64)
  (atimeNs : UInt32) (mtime : UInt64) (mtimeNs : UInt32) : IO (Except Errno Unit)

@[extern "fv_statvfs_fd"] opaque statvfsRaw (fd : Fd) : IO (Except Errno ByteArray)
@[extern "fv_exact_lookups"] opaque exactLookups (dir : Fd) : IO Bool

@[extern "fv_setup"] opaque setup : IO Unit
@[extern "fv_count"] opaque count (which : UInt32) : IO Unit
@[extern "fv_start_reporter"] opaque startReporter : IO Unit

def fstat (fd : Fd) : IO (Except Errno Stat) := return (← fstatRaw fd).map Stat.decode
def fstatat (dir : Fd) (name : Name) : IO (Except Errno Stat) := return (← fstatatRaw dir name.bytes).map Stat.decode

end Sys
end Fuseview
