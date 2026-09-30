import Std.Data.HashMap
import Fuseview.Sys
import Fuseview.Filter
import Fuseview.Spec
import Fuseview.Proto

/-!
The view (`fuseview.View`), request for request: a passthrough keyed by backing-file reference --
a directory inode holds an O_PATH descriptor and its path, a file inode the directory it was found
in and its name there -- every name decided by the filter, and every use of a descriptor preceded
by the check that the object is still where it was recorded, as the kernel reports it
(/proc/self/fd). The docstring of certorail/fuseview.py is the specification, the contract
included.

An operation is an `Op`: the tables as state, and an errno as the way out. The state is outside the
errors, so what an operation changed before it failed stays changed, as in the Python view.
-/
namespace Fuseview

inductive Place where
  /-- a directory: an O_PATH descriptor, its path below the served directory, and the path the
  kernel reports it at -/
  | dir (fd : Fd) (path : Path) (at_ : ByteArray)
  /-- anything else: the directory inode it was found in, and its name there -/
  | file (parent : UInt64) (name : Name)
  deriving Inhabited

structure Inode where
  place : Place
  key : Key
  refs : UInt64
  deriving Inhabited

/-- An entry as the kernel is told of it. -/
structure Entry where
  ino : UInt64
  st : Stat
  deriving Inhabited

structure Listing where
  inode : UInt64
  /-- the visible entries, as the scan that began the listing found them -/
  entries : Option (Array (Name × Stat))
  deriving Inhabited

/-- A lock the kernel asks for (`struct fuse_lk_in`): through the open file *fh*, for *owner*, over
[*start*, *end_*] (`Proto.OFFSET_MAX`: to the end of the file), of *type* (`F.RDLCK`, `F.WRLCK`,
`F.UNLCK`); flock(2)'s when *flock*, else fcntl(2)'s. -/
structure Lock where
  fh : UInt64
  owner : UInt64
  start : UInt64
  end_ : UInt64
  type : UInt32
  flock : Bool
  deriving Inhabited

/-- `struct flock`'s length for the lock's span: 0 is to the end. -/
def Lock.len (l : Lock) : UInt64 := if l.end_ == Proto.OFFSET_MAX then 0 else l.end_ - l.start + 1

/-- A `SETLKW` the lock was not free for: its request, the file, the lock. -/
structure Waiter where
  unique : UInt64
  ino : UInt64
  lock : Lock
  deriving Inhabited

structure Core where
  rules : Filter
  /-- the served directory's path, and where the kernel reports it to be -/
  source : ByteArray
  inodes : Std.HashMap UInt64 Inode
  -- directories by identity, since a directory has one name; files by where they were found,
  -- since a file may have several
  byKey : Std.HashMap Key UInt64
  byPlace : Std.HashMap (UInt64 × Name) UInt64
  nextInode : UInt64
  /-- a directory handle (the descriptor the listing reads) -> the directory, its entries -/
  listings : Std.HashMap UInt64 Listing
  -- the handles open on each file, and the file each is on: an open file still has attributes
  -- when no name leads to it any more
  openHandles : Std.HashMap UInt64 (Array UInt64)
  handleInodes : Std.HashMap UInt64 UInt64
  -- locks. A POSIX lock owner (a process, to the kernel) holds its locks on a file through one
  -- descriptor of its own, reopened from a handle on the file, as open-file-description locks: so
  -- two owners conflict, as two processes do, and an owner never conflicts with itself
  owners : Std.HashMap (UInt64 × UInt64) Fd
  /-- the `SETLKW`s set aside until their lock is free: the loop never waits in a call -/
  parked : Array Waiter
  /-- interrupts that came before their request (the kernel delivers them first): a `SETLKW` among
  them is answered EINTR on arrival. The newest few: request ids only grow -/
  interrupted : Array UInt64
  /-- replies to requests other than the one being answered: a waiter's lock had, or interrupted -/
  outbox : Array (ByteArray × ByteArray)

abbrev Op := ExceptT Errno (StateT Core IO)

def ROOT : UInt64 := 1

def sys {α : Type} (act : IO (Except Errno α)) : Op α := do
  match ← act with
  | .ok a => pure a
  | .error e => throw e

/-- What cannot happen, if it does: logged, and answered EIO. -/
def bug {α : Type} (what : String) : Op α := do
  IO.eprintln s!"fuseview-lean: {what}"
  throw EIO

/-- A descriptor to act through: one an inode holds, or one opened for the occasion. -/
inductive Handle where
  | held (fd : Fd)
  | opened (fd : Fd)

def Handle.fd : Handle → Fd
  | .held fd => fd
  | .opened fd => fd

def Handle.release : Handle → IO Unit
  | .held _ => pure ()
  | .opened fd => Sys.close fd

-- paths and helpers ------------------------------------------------------------------------------

def node (ino : UInt64) : Op Inode := do
  match (← get).inodes[ino]? with
  | some n => pure n
  | none => bug s!"inode {ino} is not known"

partial def pathOf (ino : UInt64) : Op Path := do
  let n ← node ino
  match n.place with
  | .dir _ path _ => return path
  | .file parent name => return (← pathOf parent).push name

def childPath (parent : UInt64) (name : Name) : Op Path := do
  return (← pathOf parent).push name

def deletedMark : ByteArray := " (deleted)".toUTF8

/-- Is the object *fd* refers to at *expected*, as the kernel reports it -- the whole path,
computed at one instant from real directory entries, so no symbolic link is on it? Not if it has
no path any more. -/
def isAt (fd : Fd) (expected : ByteArray) : Op Bool := do
  let path ← sys (Sys.readlinkFd fd)
  if endsWith path deletedMark then
    if (← sys (Sys.fstat fd)).nlink == 0 then return false
  return bytesEq path expected

/-- A descriptor for the directory at *source* now, reached without a symbolic link, or none. -/
def served (source : ByteArray) : Op (Option Fd) := do
  match ← Sys.openPath source (O.PATH ||| O.DIRECTORY ||| O.NOFOLLOW) with
  | .error e => if e == ENOENT || e == ENOTDIR then return none else throw e
  | .ok fd =>
    let here ← tryCatch (isAt fd source) fun e => do
      Sys.close fd
      throw e
    if here then return some fd
    Sys.close fd  -- a link above it
    return none

/-- The served directory's descriptor, while the directory it holds is at the served path; else
the directory there now, reached without a symbolic link; with none there, ESTALE. -/
def anchor : Op Fd := do
  let root ← node ROOT
  let .dir fd _ _ := root.place | bug "the root inode is not a directory"
  let source := (← get).source
  if ← isAt fd source then return fd
  let some new ← served source | throw ESTALE
  let key := (← sys (Sys.fstat new)).key
  modify fun c =>
    let byKey := if c.byKey[root.key]? == some ROOT then c.byKey.erase root.key else c.byKey
    { c with byKey := byKey.insert key ROOT,
             inodes := c.inodes.insert ROOT { root with place := .dir new #[] source, key := key } }
  Sys.close fd
  return new

/-- The descriptor the directory *ino* holds, while the object it refers to is at the inode's
recorded path; else ESTALE, and the kernel looks the path up again. -/
def held (ino : UInt64) : Op Fd := do
  if ino == ROOT then return ← anchor
  let n ← node ino
  let .dir fd _ at_ := n.place | bug s!"inode {ino} is not a directory"
  if ← isAt fd at_ then return fd
  throw ESTALE

/-- The kernel names children only of directories, which hold a descriptor. -/
def parentFd (parent : UInt64) : Op Fd := held parent

/-- The descriptor the directory *ino* holds, unchecked: for opening a child whose own path is
checked next, which vouches for every directory above it. -/
def uncheckedFd (ino : UInt64) : Op Fd := do
  let n ← node ino
  let .dir fd _ _ := n.place | bug s!"inode {ino} is not a directory"
  return fd

/-- A live O_PATH descriptor for *ino*: held, for a directory still at its path; opened, for a
file, by the name it was found under in its held parent, and refused (ESTALE) if what is there now
is a different file. -/
def fdOf (ino : UInt64) : Op Handle := do
  let n ← node ino
  match n.place with
  | .dir .. => return .held (← held ino)
  | .file parent name =>
    let dir ← parentFd parent
    let fd ← match ← Sys.openat dir name.bytes (O.PATH ||| O.NOFOLLOW) 0 with
      | .ok fd => pure fd
      | .error e => if e == ENOENT then throw ESTALE else throw e
    let st ← tryCatch (sys (Sys.fstat fd)) fun e => do
      Sys.close fd
      throw e
    if st.key != n.key then
      Sys.close fd
      throw ESTALE
    return .opened fd

/-- *ino*'s attributes: a directory's through its checked descriptor; a file's at its name, while
the object there is the one recorded -- else through a handle still open on it, else ESTALE. -/
def statOf (ino : UInt64) : Op Stat := do
  let n ← node ino
  match n.place with
  | .dir .. => sys (Sys.fstat (← held ino))
  | .file parent name =>
    let atName : Op (Option Stat) := do
      match ← Sys.fstatat (← parentFd parent) name with
      | .ok st => return if st.key == n.key then some st else none
      | .error e => if e == ENOENT then return none else throw e
    let found ← tryCatch atName fun e => if e == ESTALE then pure none else throw e
    if let some st := found then return st
    match (← get).openHandles[ino]?.bind (·[0]?) with
    | some fh => sys (Sys.fstat fh.toUInt32)
    | none => throw ESTALE

/-- *name* under *parent* may be created, replaced or removed, or EPERM. -/
def writableName (parent : UInt64) (name : Name) : Op Unit := do
  if !((← get).rules.mayWrite (← childPath parent name)) then throw EPERM

/-- The file itself may be written: its one name may, or EPERM. -/
def writableInode (ino : UInt64) : Op Unit := do
  if ino == ROOT then throw EPERM
  if !((← get).rules.mayWrite (← pathOf ino)) then throw EPERM
  let st ← statOf ino
  if !st.isDir && st.nlink > 1 then throw EPERM

/-- Is *name*, which resolves under *parent*, the spelling the directory stores? -/
def spelledAsStored (parent : UInt64) (name : Name) : Op Bool := do
  let fd ← parentFd parent
  if ← Sys.exactLookups fd then return true
  return (← sys (Sys.listdir fd)).any fun n => bytesEq n name.bytes

/-- EEXIST when the backing filesystem resolves *name* to an entry it stores under another
spelling. -/
def refuseAlias (parent : UInt64) (name : Name) : Op Unit := do
  match ← Sys.fstatat (← parentFd parent) name with
  | .error e => if e == ENOENT then return else throw e
  | .ok _ => if !(← spelledAsStored parent name) then throw EEXIST

def freshInode : Op UInt64 :=
  modifyGet fun c => (c.nextInode, { c with nextInode := c.nextInode + 1 })

/-- The entry *name* under the directory inode *parent* as an inode the kernel may hold: the one
recorded for it there, or a new one; its count bumped. A directory is recorded only if the object
opened is the one *st* describes (default: a stat now), at the path its name says; one replaced or
moved between the two is ENOENT.

Only a stat taken here checks the parent (it is taken through the parent's descriptor and judged by
its path). One the caller hands over was taken so already -- by a listing's scan, a lookup, a
create -- and admitting acts on nothing more: a file is recorded untouched, and every later use of
it checks its parent again; a directory's own path check vouches for every directory above it.
(The Python view checks the parent here every time: one readlink per listed entry.) -/
def admit (parent : UInt64) (name : Name) (st? : Option Stat) : Op Entry := do
  let st ← match st? with
    | some st => pure st
    | none => do sys (Sys.fstatat (← parentFd parent) name)
  let key := st.key
  if st.isDir then
    let path ← childPath parent name
    if let some ino := (← get).byKey[key]? then
      if let some n := (← get).inodes[ino]? then
        if let .dir _ recorded _ := n.place then
          if recorded == path then
            modify fun c => { c with inodes := c.inodes.insert ino { n with refs := n.refs + 1 } }
            return ⟨ino, st⟩
    let dir ← uncheckedFd parent
    let fd ← match ← Sys.openat dir name.bytes (O.PATH ||| O.NOFOLLOW ||| O.DIRECTORY) 0 with
      | .ok fd => pure fd
      | .error e => if e == ENOENT || e == ENOTDIR then throw ENOENT else throw e
    let at_ := joinPath (← get).source path
    let same ← tryCatch (do return (← sys (Sys.fstat fd)).key == key && (← isAt fd at_)) fun e => do
      Sys.close fd
      throw e
    if !same then
      Sys.close fd
      throw ENOENT
    let ino ← freshInode
    -- an older inode with this key stays, unfindable, until forgotten
    modify fun c => { c with inodes := c.inodes.insert ino ⟨.dir fd path at_, key, 1⟩,
                             byKey := c.byKey.insert key ino }
    return ⟨ino, st⟩
  else
    let place := (parent, name)
    if let some ino := (← get).byPlace[place]? then
      if let some n := (← get).inodes[ino]? then
        if n.key == key then
          modify fun c => { c with inodes := c.inodes.insert ino { n with refs := n.refs + 1 } }
          return ⟨ino, st⟩
    let ino ← freshInode
    modify fun c =>
      let inodes := c.inodes.insert ino ⟨.file parent name, key, 1⟩
      -- a file pins the directory it was found in
      let inodes := match inodes[parent]? with
        | some p => inodes.insert parent { p with refs := p.refs + 1 }
        | none => inodes
      { c with inodes := inodes, byPlace := c.byPlace.insert place ino }
    return ⟨ino, st⟩

/-- Every lock owner's descriptor on *ino*, closed: the kernel has forgotten the file. -/
def dropOwners (ino : UInt64) : Op Unit := do
  for ((i, o), fd) in (← get).owners.toList do
    if i == ino then
      Sys.close fd
      modify fun c => { c with owners := c.owners.erase (i, o) }

/-- *count* of the kernel's references to *ino* let go. -/
partial def unref (ino : UInt64) (count : UInt64) : Op Unit := do
  if ino == ROOT then return
  let some n := (← get).inodes[ino]? | return
  let refs := if n.refs ≥ count then n.refs - count else 0
  if refs > 0 then
    modify fun c => { c with inodes := c.inodes.insert ino { n with refs := refs } }
    return
  modify fun c => { c with inodes := c.inodes.erase ino }
  dropOwners ino
  match n.place with
  | .dir fd _ _ =>
    -- not if a newer inode took the key
    modify fun c => if c.byKey[n.key]? == some ino then { c with byKey := c.byKey.erase n.key } else c
    Sys.close fd
  | .file parent name =>
    modify fun c =>
      if c.byPlace[(parent, name)]? == some ino then { c with byPlace := c.byPlace.erase (parent, name) } else c
    unref parent 1

def opened (ino fh : UInt64) : Op Unit :=
  modify fun c => { c with
    openHandles := c.openHandles.insert ino ((c.openHandles.getD ino #[]).push fh),
    handleInodes := c.handleInodes.insert fh ino }

def closed (fh : UInt64) : Op Unit := do
  let some ino := (← get).handleInodes[fh]? | return
  modify fun c =>
    let handles := (c.openHandles.getD ino #[]).filter (· != fh)
    { c with handleInodes := c.handleInodes.erase fh,
             openHandles := if handles.isEmpty then c.openHandles.erase ino else c.openHandles.insert ino handles }

/-- The visible entries of the directory *fh* reads, read afresh from its start (a new listing, or
a rewinddir); the listing's later pages index them. -/
def scan (fh parent : UInt64) : Op (Array (Name × Stat)) := do
  let base ← pathOf parent
  let fd := fh.toUInt32
  if !(← isAt fd (joinPath (← get).source base)) then
    throw ESTALE  -- the directory is not where it was opened any more
  let names ← sys (Sys.listdir fd)
  let rules := (← get).rules
  let mut entries := #[]
  for raw in names do
    let name : Name := ⟨raw⟩
    match ← Sys.fstatat fd name with
    | .error e => if e == ENOENT then continue else throw e  -- vanished mid-scan
    | .ok st =>
      if rules.visible (base.push name) st.isDir then
        entries := entries.push (name, st)
  modify fun c => { c with listings := c.listings.insert fh ⟨parent, some entries⟩ }
  return entries

-- names: the filter lives here -------------------------------------------------------------------

def lookup (parent : UInt64) (name : Name) : Op Entry := do
  -- inside a hidden directory: may not look, and the refusal says so
  if (← get).rules.hidden (← pathOf parent) then throw EACCES
  let st ← sys (Sys.fstatat (← parentFd parent) name)
  if !(← spelledAsStored parent name) then throw ENOENT  -- another spelling of an entry: not this name
  if !((← get).rules.visible (← childPath parent name) st.isDir) then
    throw ENOENT  -- the name does not exist, not "may not"
  admit parent name (some st)

def opendir (ino : UInt64) : Op Fd := do
  -- a hidden directory shows its name and lists nothing, loudly; a directory merely on the way
  -- to a grant lists what is visible in it
  if (← get).rules.hidden (← pathOf ino) then throw EACCES
  let h ← fdOf ino
  let fd ← tryFinally (sys (Sys.reopen h.fd (O.RDONLY ||| O.DIRECTORY))) h.release
  modify fun c => { c with listings := c.listings.insert fd.toUInt64 ⟨ino, none⟩ }
  return fd

/-- One page of the listing on *fh* from *offset*, at most *size* bytes. Entries are admitted, since
the kernel then skips a lookup; one it is not sent is let go again, since the kernel never forgets
what it never saw. -/
def readdirplus (fh offset : UInt64) (size : Nat) (ttls : Proto.Ttls) : Op ByteArray := do
  let some listing := (← get).listings[fh]? | bug s!"no listing on handle {fh}"
  let entries ← match listing.entries with
    | some es => if offset != 0 then pure es else scan fh listing.inode
    | none => scan fh listing.inode
  let mut body := Proto.buffer size
  let mut sent : Array UInt64 := #[]
  let mut i := offset.toNat
  while i < entries.size do
    let (name, st) := entries[i]!
    let admitted ← tryCatch (some <$> admit listing.inode name (some st)) fun e => do
      if e == ENOENT then return none  -- gone, or replaced, since the scan
      for ino in sent do
        unref ino 1  -- the kernel discards the page with the error
      throw e
    if let some ent := admitted then
      if body.size + Proto.direntplusSize name.bytes.size > size then
        unref ent.ino 1
        break
      body := Proto.direntplus body ent.ino st ttls.entry (ttls.attr st) (i + 1).toUInt64 name
      sent := sent.push ent.ino
    i := i + 1
  return body

def releasedir (fh : UInt64) : Op Unit := do
  modify fun c => { c with listings := c.listings.erase fh }
  Sys.close fh.toUInt32

def create (parent : UInt64) (name : Name) (mode flags : UInt32) : Op (Entry × Fd) := do
  writableName parent name
  refuseAlias parent name
  let h ← fdOf parent
  let fd ← tryFinally (sys (Sys.openat h.fd name.bytes (flags ||| O.CREAT ||| O.EXCL) mode)) h.release
  -- the inode is the file the handle is on, not whatever is at the name by now
  let ent ← tryCatch (do admit parent name (some (← sys (Sys.fstat fd)))) fun e => do
    Sys.close fd
    throw e
  opened ent.ino fd.toUInt64
  return (ent, fd)

def mkdir (parent : UInt64) (name : Name) (mode : UInt32) : Op Entry := do
  writableName parent name
  refuseAlias parent name
  let h ← fdOf parent
  tryFinally (sys (Sys.mkdirat h.fd name.bytes mode)) h.release
  admit parent name none

def symlink (parent : UInt64) (name target : Name) : Op Entry := do
  writableName parent name
  refuseAlias parent name
  let h ← fdOf parent
  tryFinally (sys (Sys.symlinkat target.bytes h.fd name.bytes)) h.release
  admit parent name none

def link (ino newParent : UInt64) (newName : Name) : Op Entry := do
  writableName newParent newName
  refuseAlias newParent newName
  -- a new name for a file is a way to write it later: only for a file that may be written
  writableInode ino
  let h ← fdOf ino
  tryFinally (do
      let d ← fdOf newParent
      tryFinally (sys (Sys.linkFd h.fd d.fd newName.bytes)) d.release)
    h.release
  admit newParent newName none

/-- The directories the kernel holds at or below *src*, recorded now at or below *dst*: their
paths are what every check below them compares against. -/
def moveDirs (src dst : Path) : Op Unit :=
  modify fun c =>
    let inodes := c.inodes.fold (init := c.inodes) fun acc ino n =>
      match n.place with
      | .dir fd path _ =>
        if isPrefix src path then
          let moved := dst ++ path.extract src.size path.size
          acc.insert ino { n with place := .dir fd moved (joinPath c.source moved) }
        else acc
      | .file .. => acc
    { c with inodes := inodes }

def rename (parent : UInt64) (name : Name) (newParent : UInt64) (newName : Name) : Op Unit := do
  writableName parent name  -- removing the old name is a write there
  writableName newParent newName
  refuseAlias newParent newName  -- renaming onto another spelling replaces that entry
  let src ← childPath parent name
  let dst ← childPath newParent newName
  let rules := (← get).rules
  let old ← fdOf parent
  let st ← tryFinally (do
      let st ← sys (Sys.fstatat old.fd name)
      -- a directory's path is every path beneath it: it moves only where each of those is
      -- decided alike before and after
      if st.isDir && !rules.mayMoveDir src dst then throw EPERM
      let new ← fdOf newParent
      tryFinally (sys (Sys.renameat old.fd name.bytes new.fd newName.bytes)) new.release
      return st)
    old.release
  if st.isDir then
    moveDirs src dst
    return
  let some moved := (← get).byPlace[(parent, name)]? | return
  let some n := (← get).inodes[moved]? | return
  if n.key != st.key then return
  modify fun c =>
    -- the new directory is pinned before the old one is let go: they may be the same
    let inodes := match c.inodes[newParent]? with
      | some p => c.inodes.insert newParent { p with refs := p.refs + 1 }
      | none => c.inodes
    { c with inodes := inodes.insert moved { n with place := .file newParent newName },
             byPlace := (c.byPlace.erase (parent, name)).insert (newParent, newName) moved }
  unref parent 1

def remove (parent : UInt64) (name : Name) (flags : UInt32) : Op Unit := do
  writableName parent name
  let h ← fdOf parent
  tryFinally (sys (Sys.unlinkat h.fd name.bytes flags)) h.release

-- inodes: no names involved ----------------------------------------------------------------------

/-- What a setattr asks: `valid` says which fields count (FATTR_*). -/
structure Change where
  valid : UInt32
  fh : UInt64
  mode : UInt32
  uid : UInt32
  gid : UInt32
  size : UInt64
  atime : UInt64
  atimeNs : UInt32
  mtime : UInt64
  mtimeNs : UInt32

def setattr (ino : UInt64) (ch : Change) : Op Stat := do
  writableInode ino
  if ch.valid &&& Proto.FATTR_FH != 0 then
    -- the handle the call came through: an unlinked file has no name
    sys (Sys.setattr ch.fh.toUInt32 0 ch.valid ch.mode ch.uid ch.gid ch.size ch.atime ch.atimeNs ch.mtime ch.mtimeNs)
  else
    let h ← fdOf ino
    tryFinally
      (sys (Sys.setattr h.fd 1 ch.valid ch.mode ch.uid ch.gid ch.size ch.atime ch.atimeNs ch.mtime ch.mtimeNs))
      h.release
  statOf ino

def readlink (ino : UInt64) : Op ByteArray := do
  -- the link text passes through; the kernel resolves it inside the view
  let n ← node ino
  let .file parent name := n.place | throw EINVAL  -- a directory is never a link
  if !((← get).rules.readable (← pathOf ino)) then throw EACCES
  discard <| statOf ino  -- identity check
  sys (Sys.readlinkat (← parentFd parent) name.bytes)

def openFile (ino : UInt64) (flags : UInt32) : Op Fd := do
  let writing := flags &&& (O.WRONLY ||| O.RDWR ||| O.APPEND ||| O.TRUNC) != 0
  if writing then writableInode ino
  else if !((← get).rules.readable (← pathOf ino)) then
    throw EACCES  -- listed by name under a readable directory only
  -- promote the reference to an I/O descriptor; truncating waits until the descriptor is known
  -- to be on the file checked
  let opening := flags &&& ~~~(O.CREAT ||| O.TRUNC)
  let n ← node ino
  let fd ← match n.place with
    | .dir .. => do sys (Sys.reopen (← held ino) (opening &&& ~~~O.NOFOLLOW))
    | .file parent name => do
      let fd ← match ← Sys.openat (← parentFd parent) name.bytes (opening ||| O.NOFOLLOW) 0 with
        | .ok fd => pure fd
        | .error e => if e == ENOENT then throw ESTALE else throw e
      let st ← tryCatch (sys (Sys.fstat fd)) fun e => do
        Sys.close fd
        throw e
      if st.key != n.key then
        Sys.close fd
        throw ESTALE
      if writing && st.nlink > 1 then
        Sys.close fd
        throw EPERM  -- a name was added since the check
      pure fd
  if flags &&& O.TRUNC != 0 then
    tryCatch (sys (Sys.ftruncate fd 0)) fun e => do
      Sys.close fd
      throw e
  opened ino fd.toUInt64
  return fd

-- locks: held on the backing files -----------------------------------------------------------

/-- The object *fh* is on, reopened as widely as it allows: read-write, else write-only, else
read-only. A write lock is only ever asked through a handle open for writing, which one of these
then matches. -/
def reopenWidest (fh : Fd) : IO (Except Errno Fd) := do
  if let .ok fd ← Sys.reopen fh O.RDWR then return .ok fd
  if let .ok fd ← Sys.reopen fh O.WRONLY then return .ok fd
  Sys.reopen fh O.RDONLY

/-- The descriptor that holds *l*'s owner's POSIX locks on *ino*: made once, from the handle the
request came through. -/
def ownerFd (ino : UInt64) (l : Lock) : Op Fd := do
  if let some fd := (← get).owners[(ino, l.owner)]? then return fd
  let fd ← sys (reopenWidest l.fh.toUInt32)
  modify fun c => { c with owners := c.owners.insert (ino, l.owner) fd }
  return fd

/-- *l* tried now, never waiting: EAGAIN when another holds a lock that conflicts. A flock(2) lock
is the open file's own, so it is taken on the handle itself (one backing descriptor per open); a
POSIX one on its owner's descriptor. -/
def tryLock (ino : UInt64) (l : Lock) : Op Unit := do
  if l.flock then
    let op := if l.type == F.RDLCK then LOCK.SH else if l.type == F.WRLCK then LOCK.EX else LOCK.UN
    sys (Sys.flock l.fh.toUInt32 (op ||| LOCK.NB))
  else if l.type == F.UNLCK && !(← get).owners.contains (ino, l.owner) then
    return  -- an owner with no descriptor here holds nothing to let go of
  else
    let fd ← ownerFd ino l
    tryCatch (sys (Sys.ofdLock fd l.type l.start l.len)) fun e =>
      throw (if e == EACCES then EAGAIN else e)  -- POSIX lets a conflict be either

/-- The lock that would conflict with *l* (`GETLK`): its type (`F.UNLCK`: none), span, holder. -/
def testLock (ino : UInt64) (l : Lock) : Op (UInt32 × UInt64 × UInt64 × UInt32) := do
  let r ← sys (Sys.ofdTest (← ownerFd ino l) l.type l.start l.len)
  let start := rd64 r 8
  let len := rd64 r 16
  return ((rd64 r 0).toUInt32, start, if len == 0 then Proto.OFFSET_MAX else start + len - 1, (rd64 r 24).toUInt32)

/-- *owner* lets go of every POSIX lock it holds on *ino*: its descriptor closed, which releases
them, as a close of any descriptor a process has on a file does (FLUSH). -/
def dropOwner (ino owner : UInt64) : Op Unit := do
  let some fd := (← get).owners[(ino, owner)]? | return
  Sys.close fd
  modify fun c => { c with owners := c.owners.erase (ino, owner) }

/-- A reply to a request other than the one being answered. -/
def reply (unique : UInt64) (result : Except Errno ByteArray) : Op Unit :=
  let message := match result with
    | .ok body => (Proto.header unique body.size, body)
    | .error e => (Proto.errorHeader unique e, ByteArray.empty)
  modify fun c => { c with outbox := c.outbox.push message }

/-- A `SETLKW` for *l*: had now, or set aside for the loop to try again -- none, no reply yet --
unless its interrupt came first. -/
def waitLock (unique ino : UInt64) (l : Lock) : Op (Option ByteArray) := do
  if (← get).interrupted.contains unique then
    modify fun c => { c with interrupted := c.interrupted.filter (· != unique) }
    throw EINTR
  try
    tryLock ino l
    return some .empty
  catch e =>
    if e != EAGAIN then throw e
    modify fun c => { c with parked := c.parked.push ⟨unique, ino, l⟩ }
    return none

/-- The kernel's INTERRUPT of *unique*: a waiter answered EINTR; or, for a request not read yet
(interrupts are delivered first), remembered. One already answered is forgotten with the rest. -/
def interrupt (unique : UInt64) : Op Unit := do
  let c ← get
  match c.parked.find? (·.unique == unique) with
  | some w =>
    set { c with parked := c.parked.filter (·.unique != unique) }
    reply w.unique (.error EINTR)
  | none =>
    let kept := if c.interrupted.size ≥ 64 then c.interrupted.extract 1 c.interrupted.size else c.interrupted
    set { c with interrupted := kept.push unique }

/-- Every waiter tried again: those whose lock is free now answered, the rest kept, in order. -/
def retryParked : Op Unit := do
  let waiting := (← get).parked
  if waiting.isEmpty then return
  modify fun c => { c with parked := #[] }
  for w in waiting do
    try
      tryLock w.ino w.lock
      reply w.unique (.ok .empty)
    catch e =>
      if e == EAGAIN then modify fun c => { c with parked := c.parked.push w }
      else reply w.unique (.error e)

def release (fh : UInt64) : Op Unit := do
  -- a waiter through the handle let go of has nothing left to lock through; the handle's own
  -- flock(2) lock goes with its descriptor
  for w in (← get).parked do
    if w.lock.fh == fh then reply w.unique (.error EBADF)
  modify fun c => { c with parked := c.parked.filter (·.lock.fh != fh) }
  closed fh
  Sys.close fh.toUInt32

def statfs : Op ByteArray := do
  let h ← fdOf ROOT
  tryFinally (sys (Sys.statvfsRaw h.fd)) h.release

/-- The tables for *spec*'s directory, served from now on; or why it cannot be. -/
def Core.new (spec : Spec) : IO (Except String Core) := do
  let source := spec.directory.toUTF8
  match ← Sys.openPath source (O.PATH ||| O.DIRECTORY ||| O.NOFOLLOW) with
  | .error e => return .error s!"{spec.directory}: cannot open it (errno {e})"
  | .ok fd =>
    match ← Sys.readlinkFd fd, ← Sys.fstat fd with
    | .ok at_, .ok st =>
      if !bytesEq at_ source then
        return .error s!"{spec.directory}: not a directory reached without a symbolic link"
      let root : Inode := ⟨.dir fd #[] source, st.key, 1⟩
      return .ok {
        rules := spec.filter
        source := source
        inodes := ({} : Std.HashMap UInt64 Inode).insert ROOT root
        byKey := ({} : Std.HashMap Key UInt64).insert st.key ROOT
        byPlace := {}
        nextInode := ROOT + 1
        listings := {}
        openHandles := {}
        handleInodes := {}
        owners := {}
        parked := #[]
        interrupted := #[]
        outbox := #[] }
    | _, _ => return .error s!"{spec.directory}: cannot tell where it is"

end Fuseview
