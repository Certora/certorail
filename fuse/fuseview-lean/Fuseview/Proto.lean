import Fuseview.Bytes
import Fuseview.Sys

/-!
The FUSE wire protocol, as `include/uapi/linux/fuse.h` lays it out (protocol 7.31 claimed: the
kernel speaks nothing newer to us): the reply bodies the view sends, little-endian, field for
field. A request's fields are read where they lie (`rd32 req 40` and so on, in `Main`); the
header is 40 bytes, a reply's 16.
-/
namespace Fuseview.Proto

def MINOR : UInt32 := 31
def MAX_WRITE : UInt32 := 128 * 1024
/-- Room for the largest request: a write of `MAX_WRITE` and its headers. The kernel refuses to read
into less than the headers and `max_write`; libfuse keeps 4 KiB for them. -/
def REQUEST_BUFFER : UInt32 := MAX_WRITE + 4096

-- the INIT flags asked for: what libfuse negotiates for pyfuse3, and so for the Python view --
-- listings always with attributes, a file's cached pages dropped when its size or mtime is seen
-- to change, O_TRUNC sent with the open, lookups beside listings
def bit (n : UInt32) : UInt32 := (1 : UInt32) <<< n

def ASYNC_READ : UInt32 := bit 0
def ATOMIC_O_TRUNC : UInt32 := bit 3
def BIG_WRITES : UInt32 := bit 5
def AUTO_INVAL_DATA : UInt32 := bit 12
def DO_READDIRPLUS : UInt32 := bit 13
def PARALLEL_DIROPS : UInt32 := bit 18

def FATTR_FH : UInt32 := bit 6
def FOPEN_KEEP_CACHE : UInt32 := bit 1
def FSYNC_FDATASYNC : UInt32 := 1

abbrev buffer (capacity : Nat) : ByteArray := ByteArray.emptyWithCapacity capacity

/-- A cache time, as the kernel takes one. -/
structure Ttl where
  sec : UInt64
  nsec : UInt32
  deriving Inhabited

/-- How long the kernel may cache a name, a directory's attributes, a file's. -/
structure Ttls where
  entry : Ttl
  dirs : Ttl
  files : Ttl
  deriving Inhabited

def Ttls.attr (t : Ttls) (st : Stat) : Ttl := if st.isDir then t.dirs else t.files

def header (unique : UInt64) (bodyLen : Nat) : ByteArray :=
  wr64 (wr32 (wr32 (buffer 16) (16 + bodyLen).toUInt32) 0) unique

def errorHeader (unique : UInt64) (e : Errno) : ByteArray :=
  wr64 (wr32 (wr32 (buffer 16) 16) (0 - e)) unique

/-- `struct fuse_attr`: 88 bytes. The inode number is the view's, not the backing file's. -/
def attr (b : ByteArray) (ino : UInt64) (st : Stat) : ByteArray :=
  let b := wr64 b ino
  let b := wr64 b st.size
  let b := wr64 b st.blocks
  let b := wr64 b st.atime
  let b := wr64 b st.mtime
  let b := wr64 b st.ctime
  let b := wr32 b st.atimeNs
  let b := wr32 b st.mtimeNs
  let b := wr32 b st.ctimeNs
  let b := wr32 b st.mode
  let b := wr32 b st.nlink.toUInt32
  let b := wr32 b st.uid
  let b := wr32 b st.gid
  let b := wr32 b st.rdev.toUInt32
  let b := wr32 b st.blksize.toUInt32
  wr32 b 0

/-- `struct fuse_entry_out`: 128 bytes. -/
def entry (b : ByteArray) (ino : UInt64) (st : Stat) (entryTtl attrTtl : Ttl) : ByteArray :=
  let b := wr64 b ino
  let b := wr64 b 0  -- generation
  let b := wr64 b entryTtl.sec
  let b := wr64 b attrTtl.sec
  let b := wr32 b entryTtl.nsec
  let b := wr32 b attrTtl.nsec
  attr b ino st

def entryOut (ino : UInt64) (st : Stat) (ttls : Ttls) : ByteArray :=
  entry (buffer 128) ino st ttls.entry (ttls.attr st)

/-- `struct fuse_attr_out`: 104 bytes. -/
def attrOut (ino : UInt64) (st : Stat) (ttls : Ttls) : ByteArray :=
  let ttl := ttls.attr st
  attr (wr32 (wr32 (wr64 (buffer 104) ttl.sec) ttl.nsec) 0) ino st

/-- `struct fuse_open_out`: 16 bytes. -/
def openOut (b : ByteArray) (fh : UInt64) (flags : UInt32) : ByteArray :=
  wr32 (wr32 (wr64 b fh) flags) 0

/-- CREATE's reply: the entry, then the open file. -/
def createOut (ino : UInt64) (st : Stat) (ttls : Ttls) (fh : UInt64) (flags : UInt32) : ByteArray :=
  openOut (entry (buffer 144) ino st ttls.entry (ttls.attr st)) fh flags

def writeOut (n : UInt32) : ByteArray := wr32 (wr32 (buffer 8) n) 0

/-- `struct fuse_statfs_out` from the shim's eight u64s (blocks bfree bavail files ffree bsize
namemax frsize): 80 bytes. -/
def statfsOut (v : ByteArray) : ByteArray :=
  let b := buffer 80
  let b := wr64 b (rd64 v 0)
  let b := wr64 b (rd64 v 8)
  let b := wr64 b (rd64 v 16)
  let b := wr64 b (rd64 v 24)
  let b := wr64 b (rd64 v 32)
  let b := wr32 b (rd64 v 40).toUInt32  -- bsize
  let b := wr32 b (rd64 v 48).toUInt32  -- namelen
  let b := wr32 b (rd64 v 56).toUInt32  -- frsize
  zeros b 28  -- padding, spare[6]

/-- `struct fuse_init_out`: 64 bytes. *kernelMinor*, *readahead*, *offered*: what the kernel's
INIT said. -/
def initOut (kernelMinor readahead offered : UInt32) : ByteArray :=
  let wanted := ASYNC_READ ||| ATOMIC_O_TRUNC ||| BIG_WRITES ||| AUTO_INVAL_DATA ||| DO_READDIRPLUS ||| PARALLEL_DIROPS
  let b := buffer 64
  let b := wr32 b 7
  let b := wr32 b (min kernelMinor MINOR)
  let b := wr32 b readahead
  let b := wr32 b (wanted &&& offered)
  let b := wr16 b 0  -- max_background: the kernel's default
  let b := wr16 b 0  -- congestion_threshold: likewise
  let b := wr32 b MAX_WRITE
  let b := wr32 b 1  -- time_gran: nanoseconds
  let b := wr16 b 0  -- max_pages: not asked for
  let b := wr16 b 0  -- map_alignment
  let b := wr32 b 0  -- flags2
  zeros b 28         -- unused[7]

def pad8 (n : Nat) : Nat := (n + 7) / 8 * 8

/-- The room a listed entry takes: `FUSE_DIRENTPLUS_SIZE`. -/
def direntplusSize (nameLen : Nat) : Nat := pad8 (152 + nameLen)

/-- `struct fuse_direntplus`, padded to eight bytes; *off* is where the next listing page starts. -/
def direntplus (b : ByteArray) (ino : UInt64) (st : Stat) (entryTtl attrTtl : Ttl) (off : UInt64)
    (name : Name) : ByteArray :=
  let b := entry b ino st entryTtl attrTtl
  let b := wr64 b ino
  let b := wr64 b off
  let b := wr32 b name.bytes.size.toUInt32
  let b := wr32 b ((st.mode &&& S_IFMT) >>> 12)  -- the dirent type: DT_DIR, DT_REG, ...
  let b := b ++ name.bytes
  zeros b (direntplusSize name.bytes.size - (152 + name.bytes.size))

end Fuseview.Proto
