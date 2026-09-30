import Fuseview

/-!
tests/test_fuseview.py's TestFilter and TestLayers, case for case (as the Rust port's), a decoded
specification, the regex -- Python's fullmatch where it is supported, a refusal where it is not --
and the protocol: requests as the kernel lays them out, answered by the view over a small tree
under `.lake/build`, with no kernel involved.
-/
open Fuseview

def at_ (parts : List String) : Path := parts.toArray.map Name.ofString

def named (s : String) : Component := .named (Name.ofString s)

def matching (p : String) : Component :=
  match NamePattern.compile p with
  | .ok r => .matching r
  | .error e => panic! s!"{p}: {e}"

/-- `pre/**`, or `pre/**/leaf`, under *anchor*. -/
def splat (anchor : String) (pre : List Component) (leaf : Option Component) : Region :=
  .pattern (.splat pre.toArray leaf) (splitPath anchor)

def exactPath (anchor : String) (cs : List Component) : Region := .pattern (.path cs.toArray) (splitPath anchor)
def subtree (p : String) : Region := .subtree (splitPath p)
def exactly (p : String) : Region := .exactly (splitPath p)

def READ : Says := .grant .readOnly
def WRITE : Says := .grant .writable
def NO_WRITE : Says := .restrict .noWrite
def HIDDEN : Says := .restrict .hidden

def filter (dir : String) (layers : List (Says × Region)) : Filter := Filter.make (splitPath dir) layers

abbrev T := StateT (Array String) IO

def check (name : String) (cond : Bool) : T Unit :=
  if cond then pure () else modify (·.push name)

/-- read src/**/<.*\.py> and docs/**, write out/**, no-write out/**/.git -/
def section_ : Filter := filter "/r" [
  (READ, splat "/r" [named "src"] (some (matching ".*\\.py"))),
  (READ, splat "/r" [named "docs"] none),
  (WRITE, splat "/r" [named "out"] none),
  (NO_WRITE, splat "/r" [named "out"] (some (named ".git")))]

def dirVisible (f : Filter) (parts : List String) : Bool := (f.isDirVisible (at_ parts)).getD false

def filterCases : T Unit := do
  let f := section_
  -- files
  check "src/a.py readable" (f.readable (at_ ["src", "a.py"]))
  check "src/pkg/deep/b.py readable" (f.readable (at_ ["src", "pkg", "deep", "b.py"]))
  check "src/a.txt unreadable" (!f.readable (at_ ["src", "a.txt"]))
  check "docs/x/y.txt readable" (f.readable (at_ ["docs", "x", "y.txt"]))
  check "a write grant reads too" (f.readable (at_ ["out", "artifact"]))
  check "secrets/key.pem unreadable" (!f.readable (at_ ["secrets", "key.pem"]))
  check "a.py unreadable" (!f.readable (at_ ["a.py"]))
  -- directories
  check "the root is visible" (dirVisible f [])
  check "src is on the way" (dirVisible f ["src"])
  check "src/pkg is on the way" (dirVisible f ["src", "pkg"])
  check "docs is visible" (dirVisible f ["docs"])
  check "notes is invisible" (!dirVisible f ["notes"])
  check "notes/sub is invisible" (!dirVisible f ["notes", "sub"])
  check "secrets is invisible" (!dirVisible f ["secrets"])
  -- writes
  check "out/new writable" (f.mayWrite (at_ ["out", "new"]))
  check "out/deep/new writable" (f.mayWrite (at_ ["out", "deep", "new"]))
  check "out/.git protected" (!f.mayWrite (at_ ["out", ".git"]))
  check "below a protection" (!f.mayWrite (at_ ["out", "x", ".git", "config"]))
  check "a read grant is not writable" (!f.mayWrite (at_ ["src", "a.py"]))
  check "elsewhere unwritable" (!f.mayWrite (at_ ["elsewhere"]))
  check "the mountpoint unwritable" (!f.mayWrite (at_ []))
  -- names are matched exactly
  check "DOCS is not docs" (!f.readable (at_ ["DOCS", "readme"]))
  check "a long name matches" (f.readable (at_ ["src", "abcdefghijklmnopqrstuvwxyz.py"]))
  let narrow := filter "/r" [(READ, exactPath "/r" [named "pub", matching "[a-z]\\.txt"])]
  check "A.txt is not [a-z]" (!narrow.readable (at_ ["pub", "A.txt"]))
  check "a long name is not one letter" (!narrow.readable (at_ ["pub", "abcdefghijklmnopqrstuvwxyz.txt"]))
  check "a.txt is" (narrow.readable (at_ ["pub", "a.txt"]))
  -- a literal directory lists its names but opens none
  let lit := filter "/r" [(READ, exactPath "/r" [named "src"])]
  check "it lists" (lit.readable (at_ ["src"]))
  check "its entries show by name" (lit.visible (at_ ["src", "a.py"]) false)
  check "but do not open" (!lit.readable (at_ ["src", "a.py"]))
  check "deeper does not show" (!lit.visible (at_ ["src", "sub", "b.py"]) false)

def layerCases : T Unit := do
  let f := filter "/r" [(WRITE, subtree "/r/out"), (NO_WRITE, subtree "/r/out/keep"), (WRITE, subtree "/r/out/keep/open")]
  check "later wins: out/x" (f.mayWrite (at_ ["out", "x"]))
  check "later wins: keep/x" (!f.mayWrite (at_ ["out", "keep", "x"]))
  check "later wins: keep/x reads" (f.readable (at_ ["out", "keep", "x"]))
  check "later wins: open/y" (f.mayWrite (at_ ["out", "keep", "open", "y"]))
  let abs := filter "/opt/data" [(READ, splat "/" [named "opt", named "data", matching "[a-z]+"] none),
                                 (READ, exactly "/opt/data/README")]
  check "no root: the root" (dirVisible abs [])
  check "no root: abc/x" (abs.readable (at_ ["abc", "x"]))
  check "no root: ABC" (!abs.visible (at_ ["ABC"]) true)
  check "no root: README" (abs.readable (at_ ["README"]))
  check "no root: README.old" (!abs.readable (at_ ["README.old"]))
  let home := filter "/h" [(READ, exactly "/h"), (WRITE, subtree "/h/proj"), (HIDDEN, subtree "/h/.ssh")]
  check "hidden: notes.txt shows" (home.visible (at_ ["notes.txt"]) false)
  check "hidden: notes.txt does not open" (!home.readable (at_ ["notes.txt"]))
  check "hidden: proj shows" (home.visible (at_ ["proj"]) true)
  check "hidden: .ssh shows its name" (home.visible (at_ [".ssh"]) true)
  check "hidden: .ssh does not list" (!home.readable (at_ [".ssh"]))
  check "hidden: .ssh is hidden, though nothing granted it" (home.hidden (at_ [".ssh"]))
  check "hidden: proj is not" (!home.hidden (at_ ["proj"]))
  check "hidden: .ssh/id does not show (inside a hidden directory)" (!home.visible (at_ [".ssh", "id_ed25519"]) false)
  check "hidden: .ssh/id unwritable" (!home.mayWrite (at_ [".ssh", "id_ed25519"]))
  let known := filter "/h" [(READ, subtree "/h"), (HIDDEN, subtree "/h/.ssh"), (READ, exactly "/h/.ssh/known_hosts")]
  check "on the way to known_hosts" (known.visible (at_ [".ssh"]) true)
  check "the hidden listing shows that alone" (!known.readable (at_ [".ssh"]))
  check ".ssh, granted then hidden, is hidden" (known.hidden (at_ [".ssh"]))
  check "known_hosts reads" (known.readable (at_ [".ssh", "known_hosts"]))
  check "id_ed25519 stays hidden" (!known.visible (at_ [".ssh", "id_ed25519"]) false)
  let before := filter "/h" [(READ, exactly "/h/.ssh/known_hosts"), (READ, subtree "/h"), (HIDDEN, subtree "/h/.ssh")]
  check "a grant before the hide: .ssh shows, hidden" (before.visible (at_ [".ssh"]) true && before.hidden (at_ [".ssh"]))
  check "a grant before the hide: known_hosts" (!before.readable (at_ [".ssh", "known_hosts"]))
  -- a name no regex can read fails closed: a hide by pattern hides it, a grant by pattern does not grant it
  let odd : Name := ⟨"key".toUTF8 ++ ⟨#[0xff]⟩ ++ ".pem".toUTF8⟩
  let hide := filter "/r" [(READ, subtree "/r"), (HIDDEN, splat "/r" [] (some (matching ".*\\.pem")))]
  check "an odd name under a hide by pattern is hidden" (!hide.visible #[Name.ofString "keys", odd] false)
  let grant := filter "/r" [(READ, splat "/r" [] (some (matching ".*\\.pem")))]
  check "an odd name is not granted by pattern" (!grant.readable #[Name.ofString "keys", odd])
  check "a plain one is" (grant.readable (at_ ["keys", "a.pem"]))

def moveCases : T Unit := do
  let rw := filter "/r" [(READ, splat "/r" [] none), (WRITE, splat "/r" [] none)]
  check "move: a sibling name under ** alone" (rw.mayMoveDir (at_ ["a", "x"]) (at_ ["a", "y"]))
  check "move: across the tree under ** alone" (rw.mayMoveDir (at_ ["a", "x"]) (at_ ["b", "x"]))
  let git := filter "/r" [(WRITE, splat "/r" [] none), (NO_WRITE, splat "/r" [] (some (named ".git")))]
  check "move: a later protection reaching below refuses" (!git.mayMoveDir (at_ ["a", "x"]) (at_ ["a", "y"]))
  let out := filter "/r" [(READ, splat "/r" [] none), (WRITE, subtree "/r/out")]
  check "move: within the writable subtree" (out.mayMoveDir (at_ ["out", "a"]) (at_ ["out", "b"]))
  check "move: out of it is refused" (!out.mayMoveDir (at_ ["out", "a"]) (at_ ["src", "a"]))
  let hide := filter "/r" [(WRITE, splat "/r" [] none), (HIDDEN, subtree "/r/secret")]
  check "move: a hide elsewhere does not matter" (hide.mayMoveDir (at_ ["src", "x"]) (at_ ["src", "y"]))
  check "move: into the hidden subtree is refused" (!hide.mayMoveDir (at_ ["src", "x"]) (at_ ["secret", "x"]))
  let again := filter "/r" [(WRITE, subtree "/r"), (NO_WRITE, subtree "/r/keep"), (WRITE, subtree "/r")]
  check "move: a later whole grant settles it" (again.mayMoveDir (at_ ["keep", "x"]) (at_ ["keep", "y"]))
  let leaf := filter "/r" [(WRITE, splat "/r" [] (some .any))]
  check "move: a pattern with a leaf is not whole" (!leaf.mayMoveDir (at_ ["a", "x"]) (at_ ["a", "y"]))

/-- A document as `ViewSpec.document()` writes one, every kind of region and component in it. -/
def document : String :=
  "{\"directory\":\"/r\",\"format\":2,\"layers\":[" ++
  "{\"grant\":\"read-only\",\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"leaf\":{\"regex\":\".*\\\\.py\"},\"prefix\":[\"src\"]}}}," ++
  "{\"grant\":\"read-only\",\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"leaf\":null,\"prefix\":[{\"one_of\":[\"docs\",\"notes\"]}]}}}," ++
  "{\"grant\":\"writable\",\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"leaf\":null,\"prefix\":[\"out\"]}}}," ++
  "{\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"leaf\":\".git\",\"prefix\":[\"out\"]}},\"restrict\":\"no-write\"}," ++
  "{\"region\":{\"subtree\":\"/r/docs/private\"},\"restrict\":\"hidden\"}," ++
  "{\"grant\":\"read-only\",\"region\":{\"exactly\":\"/r/README\"}}," ++
  "{\"grant\":\"read-only\",\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"path\":[\"pub\",{\"any\":true},{\"regex\":\"[a-z]\\\\.txt\"}]}}}" ++
  "]}"

def specCases : T Unit := do
  match Spec.parse document with
  | .error e => check s!"the document decodes: {e}" false
  | .ok spec =>
    check "the directory" (spec.directory == "/r")
    let f := spec.filter
    check "spec: src/a/b.py" (f.readable (at_ ["src", "a", "b.py"]))
    check "spec: src/a.txt" (!f.readable (at_ ["src", "a.txt"]))
    check "spec: notes/x" (f.readable (at_ ["notes", "x"]))
    check "spec: other/x" (!f.readable (at_ ["other", "x"]))
    check "spec: out/new" (f.mayWrite (at_ ["out", "new"]))
    check "spec: out/x/.git/config" (!f.mayWrite (at_ ["out", "x", ".git", "config"]))
    check "spec: docs/private shows, hidden" (f.visible (at_ ["docs", "private"]) true && f.hidden (at_ ["docs", "private"]))
    check "spec: docs/private/key" (!f.visible (at_ ["docs", "private", "key"]) false)
    check "spec: README" (f.readable (at_ ["README"]))
    check "spec: README.old" (!f.readable (at_ ["README.old"]))
    check "spec: pub/any/a.txt" (f.readable (at_ ["pub", "any", "a.txt"]))
    check "spec: pub/any/ab.txt" (!f.readable (at_ ["pub", "any", "ab.txt"]))
    check "spec: pub is on the way" (f.visible (at_ ["pub"]) true)
  check "format 1 is refused" (Spec.parse "{\"directory\":\"/r\",\"format\":1,\"layers\":[]}" matches .error _)
  check "an unknown grant is refused"
    (Spec.parse "{\"directory\":\"/r\",\"format\":2,\"layers\":[{\"grant\":\"everything\",\"region\":{\"subtree\":\"/r\"}}]}" matches .error _)
  check "a lookaround is refused"
    (Spec.parse "{\"directory\":\"/r\",\"format\":2,\"layers\":[{\"grant\":\"read-only\",\"region\":{\"anchor\":\"/r\",\"pattern\":{\"absolute\":false,\"path\":[{\"regex\":\"(?!x).*\"}]}}}]}" matches .error _)

def fullmatch (pattern name : String) : Option Bool :=
  match NamePattern.compile pattern with
  | .ok r => r.fullmatch (Name.ofString name)
  | .error _ => none

def compiles (pattern : String) : Bool := NamePattern.compile pattern matches .ok _

def regexCases : T Unit := do
  check "literal" (fullmatch "abc" "abc" == some true)
  check "fullmatch, not search" (fullmatch "abc" "abcd" == some false)
  check "dot" (fullmatch "a.c" "abc" == some true)
  check "a name holding a newline has no answer" (fullmatch "a.c" "a\nc" == none)
  check "star" (fullmatch "ab*c" "ac" == some true && fullmatch "ab*c" "abbbc" == some true)
  check "plus" (fullmatch "ab+c" "ac" == some false && fullmatch "ab+c" "abc" == some true)
  check "optional" (fullmatch "colou?r" "color" == some true && fullmatch "colou?r" "colour" == some true)
  check "bounds" (fullmatch "a{2,3}" "aa" == some true && fullmatch "a{2,3}" "aaaa" == some false)
  check "exact bound" (fullmatch "a{3}" "aaa" == some true && fullmatch "a{3}" "aa" == some false)
  check "open bound" (fullmatch "a{2,}" "aaaaa" == some true && fullmatch "a{,2}" "aaa" == some false)
  check "a brace that is no bound is literal" (fullmatch "a{x}" "a{x}" == some true)
  check "alternation" (fullmatch "cat|dog" "dog" == some true && fullmatch "cat|dog" "cow" == some false)
  check "groups" (fullmatch "(ab)+" "ababab" == some true && fullmatch "(?:ab)+" "aba" == some false)
  check "named group" (fullmatch "(?P<x>a|b)c" "bc" == some true)
  check "sets" (fullmatch "[a-c]+" "abcab" == some true && fullmatch "[a-c]+" "abd" == some false)
  check "negated set" (fullmatch "[^.]+" "abc" == some true && fullmatch "[^.]+" "a.b" == some false)
  check "a set's ] first and - last" (fullmatch "[]a-]+" "]-a" == some true)
  check "escapes" (fullmatch "a\\.b" "a.b" == some true && fullmatch "a\\.b" "axb" == some false)
  check "digits" (fullmatch "\\d+" "0123" == some true && fullmatch "\\d+" "12a" == some false)
  check "words" (fullmatch "\\w+\\.py" "my_mod.py" == some true)
  check "a class on a non-ASCII name has no answer" (fullmatch "\\w+" "café" == none)
  check "a literal on a non-ASCII name has one" (fullmatch "caf." "café" == some true)
  check "nor under $, which Python lets match before a final newline" (fullmatch "a$" "a\n" == none)
  check "dot is anything but a newline, as Python's" (fullmatch "a.c" "a-c" == some true)
  check "an empty alternative" (fullmatch "a|" "" == some true && fullmatch "a|" "a" == some true)
  check "a non-ASCII literal, spelled for lean-regex" (fullmatch "é+" "éé" == some true)
  check "a vertical tab under \\s has no answer" (fullmatch "a\\sb" (String.ofList ['a', Char.ofNat 11, 'b']) == none)
  check "special characters stay literal" (fullmatch "a\\.b\\+c" "a.b+c" == some true && fullmatch "a\\.b\\+c" "aXbbc" == some false)
  check "^ and \\Z" (fullmatch "^ab\\Z" "ab" == some true)
  check "lazy is the same language" (fullmatch "a+?b" "aaab" == some true)
  check "an empty loop terminates" (fullmatch "(a*)*b" "aaab" == some true && fullmatch "(a*)*b" "aaa" == some false)
  check "blowup is linear" (fullmatch "(a|aa)*c" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab" == some false)
  check "lookahead refused" (!compiles "(?=a)a")
  check "backreference refused" (!compiles "(a)\\1")
  check "flags refused" (!compiles "(?i)abc")
  check "word boundary refused" (!compiles "\\bab")
  check "possessive refused" (!compiles "a++")
  check "nothing to repeat refused" (!compiles "*a")
  check "unbalanced refused" (!compiles "(ab")

-- the protocol ---------------------------------------------------------------------------------

def AT_FDCWD : Fd := UInt32.ofNat (4294967296 - 100)

/-- A request as the kernel sends one: the 40-byte header, then *body*. -/
def request (opcode : UInt32) (nodeid : UInt64) (body : ByteArray) (unique : UInt64 := 7) : ByteArray :=
  let h := Proto.buffer (40 + body.size)
  let h := wr32 h (40 + body.size).toUInt32
  let h := wr32 h opcode
  let h := wr64 h unique
  let h := wr64 h nodeid
  let h := wr32 h 1000
  let h := wr32 h 1000
  let h := wr32 h 1
  let h := wr16 h 0
  let h := wr16 h 0
  h ++ body

def cname (s : String) : ByteArray := s.toUTF8.push 0

/-- The reply to *req*: its errno (0: none) and its body. -/
def ask (core : Core) (req : ByteArray) : IO (UInt32 × ByteArray × Core) := do
  let (replies, core) ← answer {} core req
  match replies.find? (fun (head, _) => rd64 head 8 == rd64 req 8) with
  | some (head, body) => return (0 - rd32 head 4, body, core)
  | none => return (0, .empty, core)

/-- Every reply *req* brings, its own and others': (request id, errno, body). -/
def askAll (core : Core) (req : ByteArray) : IO (Array (UInt64 × UInt32 × ByteArray) × Core) := do
  let (replies, core) ← answer {} core req
  return (replies.map fun (head, body) => (rd64 head 8, 0 - rd32 head 4, body), core)

def readIn (fh offset : UInt64) (size : UInt32) : ByteArray :=
  zeros (wr32 (wr64 (wr64 .empty fh) offset) size) 20

/-- The names a READDIRPLUS page lists. -/
partial def listed (body : ByteArray) (p : Nat) (acc : Array String) : Array String :=
  if p + 152 > body.size then acc else
  let len := (rd32 body (p + 144)).toNat
  let name := String.fromUTF8? (body.extract (p + 152) (p + 152 + len)) |>.getD "?"
  listed body (p + Proto.direntplusSize len) (acc.push name)

def protocolCases : T Unit := do
  let some bin := (← IO.appPath).parent | check "the test binary has a directory" false
  let base := (bin.parent.getD bin) / "test-tree"
  if ← base.pathExists then IO.FS.removeDirAll base
  IO.FS.createDirAll (base / "sub")
  IO.FS.createDirAll (base / "hidden")
  IO.FS.writeFile (base / "a.txt") "hello"
  IO.FS.writeFile (base / "sub" / "b.txt") "bee"
  IO.FS.writeFile (base / "hidden" / "secret") "psst"
  let dir := (← IO.FS.realPath base).toString
  let made ← Sys.symlinkat "a.txt".toUTF8 AT_FDCWD (dir ++ "/link").toUTF8
  check "a link is made" (made matches .ok _)
  let spec : Spec := { directory := dir, layers := #[
    (.grant .readOnly, .pattern (.splat #[] none) (splitPath dir)),
    (.restrict .hidden, .subtree (splitPath (dir ++ "/hidden")))] }
  let core ← match ← Core.new spec with
    | .ok core => pure core
    | .error e => do check s!"the tree is served: {e}" false; return
  -- LOOKUP
  let (err, body, core) ← ask core (request 1 ROOT (cname "a.txt"))
  check "lookup a.txt answers an entry" (err == 0 && body.size == 128)
  let aIno := rd64 body 0
  check "a.txt's size" (rd64 body 48 == 5)
  check "a.txt is a regular file" (rd32 body 100 &&& S_IFMT == 0o100000)
  check "its name keeps a second" (rd64 body 16 == 1)
  check "its attributes keep none" (rd64 body 24 == 0)
  let (err, body, core) ← ask core (request 1 ROOT (cname "hidden"))
  check "hidden looks up: its name shows" (err == 0 && rd32 body 100 &&& S_IFMT == S_IFDIR)
  let hiddenIno := rd64 body 0
  let (err, _, core) ← ask core (request 27 hiddenIno (zeros .empty 8))
  check "hidden does not open for listing: EACCES" (err == EACCES)
  let (err, _, core) ← ask core (request 1 hiddenIno (cname "secret"))
  check "inside hidden, a lookup is EACCES" (err == EACCES)
  let (err, _, core) ← ask core (request 1 ROOT (cname "nothing"))
  check "a name not there does not look up" (err == ENOENT)
  -- GETATTR
  let (err, body, core) ← ask core (request 3 aIno (zeros .empty 16))
  check "getattr a.txt" (err == 0 && body.size == 104 && rd64 body 24 == 5)
  -- OPEN, READ, RELEASE
  let (err, body, core) ← ask core (request 14 aIno (zeros .empty 8))
  check "open a.txt" (err == 0 && body.size == 16)
  let fh := rd64 body 0
  let (err, body, core) ← ask core (request 15 aIno (readIn fh 0 100))
  check "read a.txt" (err == 0 && bytesEq body "hello".toUTF8)
  let (err, _, core) ← ask core (request 18 aIno (zeros (wr64 .empty fh) 16))
  check "release a.txt" (err == 0)
  -- OPENDIR, READDIRPLUS, RELEASEDIR
  let (err, body, core) ← ask core (request 27 ROOT (zeros .empty 8))
  check "opendir the root" (err == 0 && body.size == 16)
  let dh := rd64 body 0
  let (err, body, core) ← ask core (request 44 ROOT (readIn dh 0 4096))
  check "a listing answers" (err == 0)
  let names := (listed body 0 #[]).qsort (· < ·)
  check s!"the listing shows a.txt, hidden (by name), link and sub: {names}" (names == #["a.txt", "hidden", "link", "sub"])
  let (err, body, core) ← ask core (request 44 ROOT (readIn dh 4 4096))
  check "the listing's end is empty" (err == 0 && body.size == 0)
  let (err, _, core) ← ask core (request 29 ROOT (zeros (wr64 .empty dh) 16))
  check "releasedir" (err == 0)
  -- READLINK
  let (_, body, core) ← ask core (request 1 ROOT (cname "link"))
  let linkIno := rd64 body 0
  let (err, body, core) ← ask core (request 5 linkIno .empty)
  check "readlink link" (err == 0 && bytesEq body "a.txt".toUTF8)
  -- nothing may be written under a read grant
  let createIn := wr32 (wr32 (wr32 (wr32 .empty 0o101) 0o644) 0) 0
  let (err, _, core) ← ask core (request 35 ROOT (createIn ++ cname "new"))
  check "create is refused" (err == EPERM)
  let (err, _, core) ← ask core (request 9 ROOT (wr32 (wr32 .empty 0o755) 0 ++ cname "newdir"))
  check "mkdir is refused" (err == EPERM)
  -- a directory, and what is below it
  let (err, body, core) ← ask core (request 1 ROOT (cname "sub"))
  check "lookup sub" (err == 0 && rd32 body 100 &&& S_IFMT == S_IFDIR)
  let subIno := rd64 body 0
  check "a directory's attributes keep a second" (rd64 body 24 == 1)
  let (err, _, core) ← ask core (request 1 subIno (cname "b.txt"))
  check "lookup sub/b.txt" (err == 0)
  -- STATFS, an unknown request
  let (err, body, core) ← ask core (request 17 ROOT .empty)
  check "statfs" (err == 0 && body.size == 80)
  let (err, _, core) ← ask core (request 99 ROOT .empty)
  check "an unknown request is ENOSYS" (err == ENOSYS)
  -- a listing's later pages serve what its first page found, even once its directory has moved;
  -- a lookup under it is stale
  IO.FS.createDirAll (base / "many")
  for f in ["f1", "f2", "f3"] do
    IO.FS.writeFile (base / "many" / f) f
  let (_, body, core) ← ask core (request 1 ROOT (cname "many"))
  let manyIno := rd64 body 0
  let (_, body, core) ← ask core (request 27 manyIno (zeros .empty 8))
  let mh := rd64 body 0
  let (err, body, core) ← ask core (request 44 manyIno (readIn mh 0 (Proto.direntplusSize 2).toUInt32))
  check "a first page with room for one entry" (err == 0 && (listed body 0 #[]).size == 1)
  IO.FS.rename (base / "many") (base / "many-moved")
  let (err, body, core) ← ask core (request 44 manyIno (readIn mh 1 4096))
  check s!"the later pages still serve (errno {err})" (err == 0 && (listed body 0 #[]).size == 2)
  let (err, _, core) ← ask core (request 1 manyIno (cname "f1"))
  check "a lookup under the moved directory is stale" (err == ESTALE)
  -- a directory moved behind the view's back is stale where it was
  IO.FS.rename (base / "sub") (base / "moved")
  let (err, _, core) ← ask core (request 1 subIno (cname "b.txt"))
  check "a moved directory is stale" (err == ESTALE)
  let (err, _, _) ← ask core (request 1 ROOT (cname "moved"))
  check "and is served where it is now" (err == 0)

def errnoOf {α : Type} : Except Errno α → Option Errno
  | .error e => some e
  | .ok _ => none

/-- The shim's own guards, and a read through the handed-back buffer. -/
def shimCases : T Unit := do
  let some bin := (← IO.appPath).parent | check "the test binary has a directory" false
  let base := (bin.parent.getD bin) / "test-shim"
  if ← base.pathExists then IO.FS.removeDirAll base
  IO.FS.createDirAll base
  IO.FS.writeFile (base / "f") "fuse bytes"
  let dir := (← IO.FS.realPath base).toString
  check "a plain open refuses O_CREAT" (errnoOf (← Sys.openPath (dir ++ "/g").toUTF8 (O.WRONLY ||| O.CREAT)) == some EINVAL)
  match ← Sys.openPath dir.toUTF8 (O.PATH ||| O.DIRECTORY ||| O.NOFOLLOW) with
  | .error e => check s!"an O_DIRECTORY open is no O_TMPFILE (errno {e})" false
  | .ok dfd =>
    check "reopen refuses O_NOFOLLOW" (errnoOf (← Sys.reopen dfd (O.RDONLY ||| O.DIRECTORY ||| O.NOFOLLOW)) == some EINVAL)
    match ← Sys.reopen dfd (O.RDONLY ||| O.DIRECTORY) with
    | .ok listing => Sys.close listing
    | .error e => check s!"a directory reopens for listing (errno {e})" false
    check "a name too long is ENAMETOOLONG" (errnoOf (← Sys.fstatat dfd ⟨("".pushn 'a' 5000).toUTF8⟩) == some 36)
    check "a name holding a NUL is EINVAL" (errnoOf (← Sys.fstatat dfd ⟨("a".toUTF8.push 0) ++ "b".toUTF8⟩) == some EINVAL)
    Sys.close dfd
  match ← Sys.openPath (dir ++ "/f").toUTF8 O.RDONLY with
  | .error e => check s!"open f (errno {e})" false
  | .ok fd =>
    let read ← Sys.fuseRead fd .empty 4096
    check "a read into a fresh buffer" (match read with | .ok b => bytesEq b "fuse bytes".toUTF8 | .error _ => false)
    Sys.close fd

def renameIn (newdir : UInt64) (old new : String) : ByteArray := wr64 .empty newdir ++ cname old ++ cname new

def renameCases : T Unit := do
  let some bin := (← IO.appPath).parent | check "the test binary has a directory" false
  let base := (bin.parent.getD bin) / "test-tree-w"
  if ← base.pathExists then IO.FS.removeDirAll base
  IO.FS.createDirAll (base / "dir1")
  IO.FS.writeFile (base / "dir1" / "f.txt") "eff"
  let dir := (← IO.FS.realPath base).toString
  let everything := [(READ, splat dir [] none), (WRITE, splat dir [] none)]
  let spec : Spec := { directory := dir, layers := everything.toArray }
  let core ← match ← Core.new spec with
    | .ok core => pure core
    | .error e => do check s!"the writable tree is served: {e}" false; return
  let (_, body, core) ← ask core (request 1 ROOT (cname "dir1"))
  let dIno := rd64 body 0
  let (err, _, core) ← ask core (request 1 dIno (cname "f.txt"))
  check "lookup dir1/f.txt" (err == 0)
  let (err, _, core) ← ask core (request 12 ROOT (renameIn ROOT "dir1" "dir2"))
  check s!"a directory renames under ** (errno {err})" (err == 0)
  let (err, _, core) ← ask core (request 1 dIno (cname "f.txt"))
  check s!"its inode follows it (errno {err})" (err == 0)
  check "the move is on disk" (← (base / "dir2" / "f.txt").pathExists)
  -- cargo's target directory: made under a temporary name, renamed into place
  let (err, _, core) ← ask core (request 9 ROOT (wr32 (wr32 .empty 0o755) 0 ++ cname "targetXYZ"))
  check "mkdir the temporary" (err == 0)
  let (err, _, _) ← ask core (request 12 ROOT (renameIn ROOT "targetXYZ" "target"))
  check s!"and rename it into place (errno {err})" (err == 0)
  -- a later protection reaching below refuses
  let guarded : Spec := { directory := dir, layers := (everything ++ [(NO_WRITE, splat dir [] (some (named ".git")))]).toArray }
  let core ← match ← Core.new guarded with
    | .ok core => pure core
    | .error e => do check s!"the guarded tree is served: {e}" false; return
  let (err, _, _) ← ask core (request 12 ROOT (renameIn ROOT "dir2" "dir3"))
  check "under a later protection a directory does not rename" (err == EPERM)

/-- `struct fuse_lk_in`: 48 bytes. -/
def lkIn (fh owner : UInt64) (type : UInt32) (flock : Bool) (start : UInt64 := 0) (end_ : UInt64 := Proto.OFFSET_MAX) : ByteArray :=
  let b := wr64 (wr64 (wr64 (wr64 .empty fh) owner) start) end_
  wr32 (wr32 (wr32 (wr32 b type) 0) (if flock then Proto.LK_FLOCK else 0)) 0

/-- `struct fuse_flush_in` and `struct fuse_release_in` share their shape: 24 bytes. -/
def closeIn (fh : UInt64) (flags : UInt32) (owner : UInt64) : ByteArray :=
  wr64 (wr32 (wr32 (wr64 .empty fh) 0) flags) owner

def has (replies : Array (UInt64 × UInt32 × ByteArray)) (unique : UInt64) (errno : UInt32) : Bool :=
  replies.any fun (u, e, _) => u == unique && e == errno

def lockCases : T Unit := do
  let some bin := (← IO.appPath).parent | check "the test binary has a directory" false
  let base := (bin.parent.getD bin) / "test-tree-l"
  if ← base.pathExists then IO.FS.removeDirAll base
  IO.FS.createDirAll base
  IO.FS.writeFile (base / "f.txt") "locked\n"
  let dir := (← IO.FS.realPath base).toString
  let spec : Spec := { directory := dir, layers := #[(READ, splat dir [] none), (WRITE, splat dir [] none)] }
  let core ← match ← Core.new spec with
    | .ok core => pure core
    | .error e => do check s!"the lock tree is served: {e}" false; return
  let (_, body, core) ← ask core (request 1 ROOT (cname "f.txt"))
  let ino := rd64 body 0
  let (err, body, core) ← ask core (request 14 ino (wr32 (wr32 .empty O.RDWR) 0))
  let fh1 := rd64 body 0
  let (err2, body, core) ← ask core (request 14 ino (wr32 (wr32 .empty O.RDWR) 0))
  let fh2 := rd64 body 0
  check "two opens of f.txt" (err == 0 && err2 == 0)
  let .ok outside ← Sys.openPath (dir ++ "/f.txt").toUTF8 O.RDONLY | check "the test opens f.txt itself" false
  -- flock(2): the open file's own, held on the backing file
  let (err, _, core) ← ask core (request 32 ino (lkIn fh1 1 F.WRLCK true))
  check "flock through one open" (err == 0)
  let (err, _, core) ← ask core (request 32 ino (lkIn fh2 2 F.WRLCK true))
  check "flock through another conflicts" (err == EAGAIN)
  check "and a process outside the view meets it" (errnoOf (← Sys.flock outside (LOCK.SH ||| LOCK.NB)) == some EAGAIN)
  let (rs, core) ← askAll core (request 33 ino (lkIn fh2 2 F.WRLCK true) 101)
  check "a waiting flock is set aside, unanswered" (rs.isEmpty && core.parked.size == 1)
  let (rs, core) ← askAll core (request 32 ino (lkIn fh1 1 F.UNLCK true) 102)
  check "letting go answers the waiter" (has rs 102 0 && has rs 101 0 && core.parked.isEmpty)
  let (err, _, core) ← ask core (request 32 ino (lkIn fh2 2 F.UNLCK true))
  check "the waiter lets go" (err == 0)
  -- POSIX locks: owners conflict with each other, never with themselves, and with processes outside
  let (err, _, core) ← ask core (request 32 ino (lkIn fh1 10 F.WRLCK false 0 99))
  check "a POSIX write lock" (err == 0)
  let (err, _, core) ← ask core (request 32 ino (lkIn fh2 10 F.RDLCK false 50 149))
  check "its owner, through another open, converts part of it" (err == 0)
  let (err, _, core) ← ask core (request 32 ino (lkIn fh2 20 F.WRLCK false 0 9))
  check "another owner conflicts" (err == EAGAIN)
  let (err, body, core) ← ask core (request 31 ino (lkIn fh2 20 F.WRLCK false 0 9))
  check s!"getlk names the conflict (errno {err})" (err == 0 && body.size == 24 && rd32 body 16 == F.WRLCK && rd64 body 0 == 0 && rd64 body 8 == 49)
  let (err, body, core) ← ask core (request 31 ino (lkIn fh2 20 F.RDLCK false 200 299))
  check "and none where there is none" (err == 0 && rd32 body 16 == F.UNLCK)
  check "a process outside meets it" (errnoOf (← Sys.ofdLock outside F.RDLCK 0 10) == some EAGAIN)
  let (err, _, core) ← ask core (request 25 ino (closeIn fh1 0 10))
  check "a close lets go of the owner's locks" (err == 0 && !core.owners.contains (ino, 10))
  let (err, _, core) ← ask core (request 32 ino (lkIn fh2 20 F.WRLCK false 0 9))
  check "so another owner has it" (err == 0)
  -- an interrupt answers a waiter EINTR, and one that came first answers its request at once
  let (rs, core) ← askAll core (request 33 ino (lkIn fh1 30 F.WRLCK false 0 9) 201)
  check "a waiting POSIX lock is set aside" (rs.isEmpty && core.parked.size == 1)
  let (rs, core) ← askAll core (request 36 ROOT (wr64 .empty 201) 202)
  check "an interrupt answers it EINTR, and itself nothing" (rs.size == 1 && has rs 201 EINTR && core.parked.isEmpty)
  let (rs, core) ← askAll core (request 36 ROOT (wr64 .empty 301) 302)
  check "an interrupt of a request not here yet is remembered" (rs.isEmpty && core.interrupted.contains 301)
  let (rs, core) ← askAll core (request 33 ino (lkIn fh1 30 F.WRLCK false 0 9) 301)
  check "and its request is answered EINTR on arrival" (has rs 301 EINTR && core.parked.isEmpty)
  -- releases: a flush's owner lets go; a waiter through the handle is answered
  let (rs, core) ← askAll core (request 33 ino (lkIn fh1 30 F.WRLCK false 0 9) 401)
  check "one more waiter" (rs.isEmpty)
  let (rs, core) ← askAll core (request 18 ino (closeIn fh1 0 0) 402)
  check "a release answers the waiters through it" (has rs 402 0 && has rs 401 EBADF && core.parked.isEmpty)
  let (err, _, core) ← ask core (request 18 ino (closeIn fh2 Proto.RELEASE_FLUSH 20))
  check "a release that flushes lets go of its owner's locks" (err == 0 && !core.owners.contains (ino, 20))
  check "and the file is free outside" (errnoOf (← Sys.ofdLock outside F.RDLCK 0 10) == none)
  Sys.close outside

def main : IO UInt32 := do
  let ((), failures) ← (do
      filterCases; layerCases; moveCases; specCases; regexCases; shimCases; protocolCases; renameCases; lockCases : T Unit).run #[]
  if failures.isEmpty then
    IO.println "all cases pass"
    return 0
  for f in failures do
    IO.println s!"FAILED: {f}"
  return 1
