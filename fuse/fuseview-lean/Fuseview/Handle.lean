import Fuseview.View

/-!
The requests, opcode by opcode, as `include/uapi/linux/fuse.h` lays them out: each read where its
fields lie (the header is 40 bytes), answered by the view, and the answer encoded. The loop that
reads them from the device and writes the replies back is `serve`.
-/
namespace Fuseview

structure Config where
  ttls : Proto.Ttls := { entry := ⟨1, 0⟩, dirs := ⟨1, 0⟩, files := ⟨0, 0⟩ }
  keepCache : Bool := false

/-- The name at *i* in the request, and the index past it. -/
def nameAt (req : ByteArray) (i : Nat) : Op (Name × Nat) :=
  match cstr req i with
  | some r => pure r
  | none => throw EINVAL

/-- The reply body to *req*, none for a request that takes no reply; a thrown errno is the error
reply. -/
def handle (cfg : Config) (req : ByteArray) : Op (Option ByteArray) := do
  let opcode := rd32 req 4
  let nodeid := rd64 req 16
  let fileFlags := if cfg.keepCache then Proto.FOPEN_KEEP_CACHE else 0
  match opcode.toNat with
  | 1 => -- LOOKUP
    Sys.count 0
    let (name, _) ← nameAt req 40
    let e ← lookup nodeid name
    return some (Proto.entryOut e.ino e.st cfg.ttls)
  | 2 => -- FORGET
    unref nodeid (rd64 req 40)
    return none
  | 42 => -- BATCH_FORGET
    let count := (rd32 req 40).toNat
    for k in List.range count do
      unref (rd64 req (48 + 16 * k)) (rd64 req (56 + 16 * k))
    return none
  | 3 => -- GETATTR
    Sys.count 1
    return some (Proto.attrOut nodeid (← statOf nodeid) cfg.ttls)
  | 4 => -- SETATTR
    let st ← setattr nodeid {
      valid := rd32 req 40, fh := rd64 req 48, size := rd64 req 56,
      atime := rd64 req 72, mtime := rd64 req 80, atimeNs := rd32 req 96, mtimeNs := rd32 req 100,
      mode := rd32 req 108, uid := rd32 req 116, gid := rd32 req 120 }
    return some (Proto.attrOut nodeid st cfg.ttls)
  | 5 => -- READLINK
    return some (← readlink nodeid)
  | 6 => -- SYMLINK: the name, then the target
    let (name, j) ← nameAt req 40
    let (target, _) ← nameAt req j
    let e ← symlink nodeid name target
    return some (Proto.entryOut e.ino e.st cfg.ttls)
  | 8 => -- MKNOD
    throw EPERM  -- no device nodes or fifos through the view
  | 9 => -- MKDIR
    let (name, _) ← nameAt req 48
    let e ← mkdir nodeid name (rd32 req 40)
    return some (Proto.entryOut e.ino e.st cfg.ttls)
  | 10 => -- UNLINK
    let (name, _) ← nameAt req 40
    remove nodeid name 0
    return some .empty
  | 11 => -- RMDIR
    let (name, _) ← nameAt req 40
    remove nodeid name AT_REMOVEDIR
    return some .empty
  | 12 => -- RENAME
    let (old, j) ← nameAt req 48
    let (new, _) ← nameAt req j
    rename nodeid old (rd64 req 40) new
    return some .empty
  | 45 => -- RENAME2
    if rd32 req 48 != 0 then throw EINVAL
    let (old, j) ← nameAt req 56
    let (new, _) ← nameAt req j
    rename nodeid old (rd64 req 40) new
    return some .empty
  | 13 => -- LINK: the header's node is the new parent
    let (name, _) ← nameAt req 48
    let e ← link (rd64 req 40) nodeid name
    return some (Proto.entryOut e.ino e.st cfg.ttls)
  | 14 => -- OPEN
    Sys.count 3
    let fd ← openFile nodeid (rd32 req 40)
    return some (Proto.openOut (Proto.buffer 16) fd.toUInt64 fileFlags)
  | 15 => -- READ
    Sys.count 4
    return some (← sys (Sys.pread (rd64 req 40).toUInt32 (rd32 req 56) (rd64 req 48)))
  | 16 => -- WRITE
    let n ← sys (Sys.pwrite (rd64 req 40).toUInt32 req 80 (rd32 req 56) (rd64 req 48))
    return some (Proto.writeOut n)
  | 17 => -- STATFS
    return some (Proto.statfsOut (← statfs))
  | 18 => -- RELEASE
    release (rd64 req 40)
    return some .empty
  | 20 => -- FSYNC
    let datasync : UInt8 := if rd32 req 48 &&& Proto.FSYNC_FDATASYNC != 0 then 1 else 0
    sys (Sys.fsync (rd64 req 40).toUInt32 datasync)
    return some .empty
  | 21 | 24 => throw ENOTSUP  -- SETXATTR, REMOVEXATTR
  | 25 => return some .empty  -- FLUSH
  | 27 => -- OPENDIR
    let fd ← opendir nodeid
    return some (Proto.openOut (Proto.buffer 16) fd.toUInt64 0)
  | 29 => -- RELEASEDIR
    releasedir (rd64 req 40)
    return some .empty
  | 35 => -- CREATE
    let (name, _) ← nameAt req 56
    let (e, fd) ← create nodeid name (rd32 req 44) (rd32 req 40)
    return some (Proto.createOut e.ino e.st cfg.ttls fd.toUInt64 fileFlags)
  | 36 => return none  -- INTERRUPT: every request here is answered at once
  | 38 => return some .empty  -- DESTROY
  | 44 => -- READDIRPLUS
    Sys.count 2
    return some (← readdirplus (rd64 req 40) (rd64 req 48) (rd32 req 56).toNat cfg.ttls)
  | _ => throw ENOSYS

/-- *req* answered against *core*: the reply to write (none for none), and the tables after. -/
def answer (cfg : Config) (core : Core) (req : ByteArray) : IO (Option (ByteArray × ByteArray) × Core) := do
  let unique := rd64 req 8
  let (result, core) ← ((handle cfg req).run).run core
  let reply := match result with
    | .ok none => none
    | .ok (some body) => some (Proto.header unique body.size, body)
    | .error e => some (Proto.errorHeader unique e, .empty)
  return (reply, core)

/-- Answer requests until the view is unmounted. *buf* is the last request's buffer, handed back to
be read into again: nothing holds it once its request is answered. -/
partial def serve (cfg : Config) (fd : Fd) (core : Core) (buf : ByteArray) : IO Unit := do
  match ← Sys.fuseRead fd buf Proto.REQUEST_BUFFER with
  | .error e =>
    if e == ENODEV then return  -- unmounted
    if e == EINTR || e == ENOENT || e == EAGAIN then return ← serve cfg fd core .empty
    throw (IO.userError s!"reading the FUSE device: errno {e}")
  | .ok req =>
    if req.size < 40 then return ← serve cfg fd core req
    let (reply, core) ← answer cfg core req
    if let some (head, body) := reply then
      discard <| Sys.writev fd head body  -- ENOENT: the request was interrupted meanwhile
    serve cfg fd core req

/-- The kernel's first request is INIT: answered here, before anything else is served. -/
def answerInit (fd : Fd) : IO (Except String Unit) := do
  match ← Sys.fuseRead fd .empty Proto.REQUEST_BUFFER with
  | .error e => return .error s!"reading the FUSE device: errno {e}"
  | .ok req =>
    if req.size < 56 || rd32 req 4 != 26 then return .error "the first request is not INIT"
    if rd32 req 40 < 7 then return .error s!"the kernel speaks FUSE {rd32 req 40}, not 7"
    let body := Proto.initOut (rd32 req 44) (rd32 req 48) (rd32 req 52)
    match ← Sys.writev fd (Proto.header (rd64 req 8) body.size) body with
    | .error e => return .error s!"answering INIT: errno {e}"
    | .ok _ => return .ok ()

end Fuseview
