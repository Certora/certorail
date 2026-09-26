import Fuseview

/-!
certorail's FUSE view (`certorail/fuseview.py`), in Lean: the Rust port's question
(`scratch/fuseview-rs`) asked again -- what does native execution buy -- with the protocol spoken
directly, request by request, over a /dev/fuse descriptor someone else mounted
(`scripts/native_view.py` mounts it, and jails this).

    fuseview-lean [--entry-ttl S] [--attr-ttl-dirs S] [--attr-ttl-files S] [--keep-cache] --fd N VIEW.JSON

It prints "ready" once the kernel has connected, a JSON line of request counts for each line on
stdin, and exits when the view is unmounted.
-/
open Fuseview

structure Args where
  fd : Option Fd := none
  spec : Option String := none
  cfg : Config := {}

def usage : String :=
  "usage: fuseview-lean [--entry-ttl S] [--attr-ttl-dirs S] [--attr-ttl-files S] [--keep-cache] --fd N VIEW.JSON"

/-- Seconds, as `1`, `0` or `0.25`. -/
def parseTtl (s : String) : Option Proto.Ttl := do
  match s.splitOn "." with
  | [whole] => return ⟨(← whole.toNat?).toUInt64, 0⟩
  | [whole, frac] =>
    let w ← whole.toNat?
    let f ← frac.toNat?
    if frac.length > 9 then failure
    return ⟨w.toUInt64, (f * 10 ^ (9 - frac.length)).toUInt32⟩
  | _ => failure

def ttl (option value : String) : Except String Proto.Ttl :=
  match parseTtl value with
  | some t => .ok t
  | none => .error s!"{option}: not a number of seconds: {value}"

partial def parseArgs (args : List String) (acc : Args) : Except String Args := do
  let ttls := acc.cfg.ttls
  match args with
  | [] => return acc
  | "--fd" :: n :: rest =>
    match n.toNat? with
    | some fd => parseArgs rest { acc with fd := some fd.toUInt32 }
    | none => throw s!"--fd: not a descriptor: {n}"
  | "--entry-ttl" :: v :: rest =>
    parseArgs rest { acc with cfg := { acc.cfg with ttls := { ttls with entry := ← ttl "--entry-ttl" v } } }
  | "--attr-ttl-dirs" :: v :: rest =>
    parseArgs rest { acc with cfg := { acc.cfg with ttls := { ttls with dirs := ← ttl "--attr-ttl-dirs" v } } }
  | "--attr-ttl-files" :: v :: rest =>
    parseArgs rest { acc with cfg := { acc.cfg with ttls := { ttls with files := ← ttl "--attr-ttl-files" v } } }
  | "--keep-cache" :: rest => parseArgs rest { acc with cfg := { acc.cfg with keepCache := true } }
  | arg :: rest =>
    if arg.startsWith "-" then throw s!"unknown option {arg}\n{usage}"
    if acc.spec.isSome then throw usage
    parseArgs rest { acc with spec := some arg }

def fail (message : String) : IO UInt32 := do
  IO.eprintln s!"fuseview-lean: {message}"
  return 2

def main (argv : List String) : IO UInt32 := do
  if argv.contains "--help" || argv.contains "-h" then
    IO.println usage
    return 0
  match parseArgs argv {} with
  | .error message => fail message
  | .ok args =>
    let (some fd, some specPath) := (args.fd, args.spec) | fail usage
    let text ← try IO.FS.readFile specPath catch e => return ← fail s!"{specPath}: {e}"
    let spec ← match Spec.parse text with
      | .ok spec => pure spec
      | .error message => return ← fail s!"{specPath}: {message}"
    if !(← Sys.fdOpen fd) then return ← fail s!"descriptor {fd} is not open"
    Sys.setup
    let core ← match ← Core.new spec with
      | .ok core => pure core
      | .error message => return ← fail s!"cannot serve: {message}"
    Sys.startReporter
    match ← answerInit fd with
    | .error message => fail message
    | .ok () =>
      let out ← IO.getStdout
      out.putStrLn "ready"
      out.flush
      serve args.cfg fd core .empty
      return 0
