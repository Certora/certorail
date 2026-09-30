import Place

/-!
The checker on small plans: the ones it must certify, and the ones it must refuse -- among them
item 9's, a view only at the first of a pattern's two tops, and every mount nested in a plain bind.
-/
open Place

-- What the proofs rest on: Lean's standard axioms, nothing admitted. A change fails the build.
/-- info: 'Place.sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms sound

/-- info: 'Place.run_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms run_sound

def nothingStable : Stability := ⟨[], [], [], []⟩

/-- Directories, reached without a link. -/
def dirs (ps : List Path) : Facts := ⟨ps.map (·, .directory), ps.map fun p => (p, p)⟩

def plan (base : Base) (layers : List Layer) (views : List View) (mounts : List Mount)
    (facts : Facts) (lifetime : Lifetime := .exec) (stability : Stability := nothingStable) : Plan :=
  ⟨base, layers, views, mounts, lifetime, stability, facts⟩

def ro : Access := .readOnly
def rw : Access := .writable

/-- `/{foo,bar}/beep/.+\.txt` stands for the pattern; its tops are `/foo/beep` and `/bar/beep`. -/
def txt : Region := .pattern "txt" [["foo", "beep"], ["bar", "beep"]]

/-- Reads of `/foo` and `/bar`, the pattern hidden. -/
def grants : List Layer :=
  [⟨.subtree ["foo"], .grant ro⟩, ⟨.subtree ["bar"], .grant ro⟩, ⟨txt, .restrict .hidden⟩]

def viewOf (base : Base) (d : Path) (layers : List Layer) : View := ⟨d, viewLayers base d layers⟩

/-- A view at each grant the pattern lies in. -/
def corrected : Plan :=
  plan .empty grants [viewOf .empty ["foo"] grants, viewOf .empty ["bar"] grants]
    [⟨["foo"], .readOnly, .view 0 []⟩, ⟨["bar"], .readOnly, .view 1 []⟩]
    (dirs [["foo"], ["bar"]])

/-- Item 9: one view, of `/foo`; `/bar` is a plain bind, and shows the hidden files. -/
def oneView : Plan :=
  plan .empty grants [viewOf .empty ["foo"] grants]
    [⟨["foo"], .readOnly, .view 0 []⟩, ⟨["bar"], .readOnly, .own⟩]
    (dirs [["foo"], ["bar"]])

/-- The pattern hidden, and only `/foo` granted: `/bar/beep` is a top no grant reaches, where the
restriction narrows nothing, and needs no view. -/
def bareTop : Plan :=
  plan .empty [⟨.subtree ["foo"], .grant ro⟩, ⟨txt, .restrict .hidden⟩]
    [viewOf .empty ["foo"] [⟨.subtree ["foo"], .grant ro⟩, ⟨txt, .restrict .hidden⟩]]
    [⟨["foo"], .readOnly, .view 0 []⟩] (dirs [["foo"]])

def wrongState : Plan :=
  plan .empty [⟨.subtree ["foo"], .grant ro⟩] [] [⟨["foo"], .writable, .own⟩] (dirs [["foo"]])

def hideX : List Layer := [⟨.subtree ["foo"], .grant ro⟩, ⟨.exactly ["foo", "x"], .restrict .hidden⟩]

def missedHide : Plan := plan .empty hideX [] [⟨["foo"], .readOnly, .own⟩] (dirs [["foo"]])

def ssh : Path := ["home", "me", ".ssh"]
def home : Path := ["home", "me"]
def hideSsh : List Layer := [⟨.subtree ssh, .restrict .hidden⟩]

/-- The read-only host, `~/.ssh` hidden by a view of `~` (a mount on `~/.ssh` itself would
detach when something outside renamed a file over it: the `~/.netrc` case). -/
def readOnlyHostView : Plan :=
  plan (.host false) hideSsh [viewOf (.host false) home hideSsh] [⟨home, .readOnly, .view 0 []⟩]
    (dirs [home]) (stability := ⟨[home], [[]], [], []⟩)

/-- The same, `~/.ssh` held by a mount of its own on the read-only host: refused. -/
def hideOnItself : Plan :=
  plan (.host false) hideSsh [viewOf (.host false) ssh hideSsh] [⟨ssh, .readOnly, .view 0 []⟩]
    (dirs [ssh]) (stability := ⟨[home], [[]], [], []⟩)

/-- The writable host, `~` viewed, `~/proj` bound back over it: a bind back on a view. -/
def boundBack : Plan :=
  plan (.host true) hideSsh [viewOf (.host true) home hideSsh]
    [⟨home, .writable, .view 0 []⟩, ⟨["home", "me", "proj"], .writable, .own⟩]
    (dirs [home, ["home", "me", "proj"]]) (stability := ⟨[home], [[]], [], []⟩)

def writableTxt : List Layer := [⟨.subtree ["foo"], .grant rw⟩, ⟨txt, .restrict .hidden⟩]

def readOnlyView : Plan :=
  plan .empty writableTxt [viewOf .empty ["foo"] writableTxt] [⟨["foo"], .readOnly, .view 0 []⟩]
    (dirs [["foo"]])

/-- The writable host, `~/.ssh` hidden by a view of `~`. -/
def hostView (stability : Stability) : Plan :=
  plan (.host true) hideSsh [viewOf (.host true) home hideSsh] [⟨home, .writable, .view 0 []⟩]
    (dirs [home]) (stability := stability)

/-- The top-level directories, and the home directory: what the host world counts on today. -/
def hostStable : Stability := ⟨[home], [[]], [], []⟩

def runBind (stability : Stability) : Plan :=
  plan .empty [⟨.subtree ["usr"], .grant ro⟩] [] [⟨["usr"], .readOnly, .own⟩] (dirs [["usr"]])
    (lifetime := .run) (stability := stability)

def proj : Path := ["proj"]

/-- A write of `proj`, a read of something inside it, each bound: the jail can rename
`proj/a` and carry the read-only bind of `proj/a/b` off with it, then make `proj/a/b` anew. -/
def carryOff : Plan :=
  plan .empty [⟨.subtree proj, .grant rw⟩, ⟨.subtree ["proj", "a", "b"], .grant ro⟩] []
    [⟨proj, .writable, .own⟩, ⟨["proj", "a", "b"], .readOnly, .own⟩]
    (dirs [proj, ["proj", "a", "b"]])

/-- The same, `proj` a view with `proj/a/b` bound back over it: what the placer makes. -/
def viewedProj : Plan :=
  let layers := [⟨.subtree proj, .grant rw⟩, ⟨.subtree ["proj", "a", "b"], .grant ro⟩]
  plan .empty layers [viewOf .empty proj layers]
    [⟨proj, .writable, .view 0 []⟩, ⟨["proj", "a", "b"], .readOnly, .own⟩]
    (dirs [proj, ["proj", "a", "b"]])

/-- A read-only bind nested in a writable one, a direct child: outside, a rename over it or of it
detaches or moves it, and the name shows the writable bind (MEASURED, part 3). Refused. -/
def directChild : Plan :=
  plan .empty [⟨.subtree proj, .grant rw⟩, ⟨.subtree ["proj", "vendor"], .grant ro⟩] []
    [⟨proj, .writable, .own⟩, ⟨["proj", "vendor"], .readOnly, .own⟩]
    (dirs [proj, ["proj", "vendor"]])

/-- `/lib64` granted, and not on this machine: the bind is skipped, and nothing can be made there. -/
def skippedBind : Plan :=
  plan .empty [⟨.subtree ["lib64"], .grant ro⟩] [] [⟨["lib64"], .readOnly, .own⟩]
    ⟨[(["lib64"], .missing)], []⟩

/-- `proj/.git` read-only and missing, under a writable `proj`: the skipped bind leaves it
writable. -/
def skippedUnderWrite : Plan :=
  plan .empty [⟨.subtree proj, .grant rw⟩, ⟨.subtree ["proj", ".git"], .grant ro⟩] []
    [⟨proj, .writable, .own⟩, ⟨["proj", ".git"], .readOnly, .own⟩]
    ⟨[(proj, .directory), (["proj", ".git"], .missing)], [(proj, proj)]⟩

/-- A merged `/usr`: `/lib` leads to `/usr/lib`, and the toolchain's grant of it is bound as it
leads. -/
def aliasFacts : Facts :=
  ⟨[(["lib"], .symlink), (["usr", "lib"], .directory), (["libx32"], .symlink), (["usr", "libx32"], .missing),
    (["etc"], .directory)],
   [(["lib"], ["usr", "lib"]), (["usr", "lib"], ["usr", "lib"]), (["libx32"], ["usr", "libx32"]),
    (["etc"], ["etc"]), (["etc", "localtime"], ["usr", "lib"])]⟩

def aliased : Plan :=
  plan .empty [⟨.subtree ["lib"], .grant ro⟩] [] [⟨["lib"], .readOnly, .alias ["usr", "lib"]⟩] aliasFacts

/-- `/libx32` leads nowhere: the bind is skipped, and nothing is there. -/
def aliasedToNothing : Plan :=
  plan .empty [⟨.subtree ["libx32"], .grant ro⟩] [] [⟨["libx32"], .readOnly, .alias ["usr", "libx32"]⟩]
    aliasFacts

/-- An alias under another bind: what lies below it would be the other's too. -/
def aliasUnderBind : Plan :=
  plan .empty [⟨.subtree ["etc"], .grant ro⟩, ⟨.subtree ["etc", "localtime"], .grant ro⟩] []
    [⟨["etc"], .readOnly, .own⟩, ⟨["etc", "localtime"], .readOnly, .alias ["usr", "lib"]⟩] aliasFacts

/-- The toolchain `/b` is stable, but a later grant makes it writable: nothing outside replaces
it, and still the jail itself can make the missing `/b/v`, read-only by the grants. -/
def stableMadeWritable : Plan :=
  plan .empty [⟨.subtree ["b"], .grant ro⟩, ⟨.subtree ["b"], .grant rw⟩, ⟨.subtree ["b", "v"], .grant ro⟩] []
    [⟨["b"], .writable, .own⟩, ⟨["b", "v"], .readOnly, .own⟩]
    ⟨[(["b"], .directory), (["b", "v"], .missing)], [(["b"], ["b"])]⟩
    (stability := ⟨[], [], [], [["b"]]⟩)

/-- `/a/w` is a file, bound writable; a read-only grant below it is skipped, and nothing can be
made there. -/
def belowFile : Plan :=
  plan .empty [⟨.subtree ["a", "w"], .grant rw⟩, ⟨.subtree ["a", "w", "g"], .grant ro⟩] []
    [⟨["a", "w"], .writable, .own⟩, ⟨["a", "w", "g"], .readOnly, .own⟩]
    ⟨[(["a", "w"], .file), (["a", "w", "g"], .missing)], [(["a", "w"], ["a", "w"])]⟩

def unrecorded : Plan :=
  plan .empty [⟨.subtree ["foo"], .grant ro⟩] [] [⟨["foo"], .readOnly, .own⟩] ⟨[], []⟩

def throughLink : Plan :=
  plan .empty [⟨.subtree ["foo"], .grant ro⟩] [] [⟨["foo"], .readOnly, .own⟩]
    ⟨[(["foo"], .directory)], [(["foo"], ["elsewhere"])]⟩

def outOfOrder : Plan :=
  plan .empty [⟨.subtree ["foo"], .grant ro⟩, ⟨.subtree ["foo", "x"], .grant rw⟩] []
    [⟨["foo", "x"], .writable, .own⟩, ⟨["foo"], .readOnly, .own⟩]
    (dirs [["foo"], ["foo", "x"]])

def cases : List (String × Plan × Bool) :=
  [("corrected: a view per grant around the pattern", corrected, true),
   ("item 9: one view for two tops", oneView, false),
   ("a restriction's top no grant reaches, left without a view", bareTop, true),
   ("writable bind of a read-only grant", wrongState, false),
   ("hidden entry left bound", missedHide, false),
   ("read-only host, the redline held by a view of home", readOnlyHostView, true),
   ("read-only host, the redline held by a mount on itself", hideOnItself, false),
   ("a bind back on a view", boundBack, true),
   ("read-only view of a writable grant", readOnlyView, false),
   ("host view at a stable home", hostView hostStable, true),
   ("host view, nothing stable: the jail can rename /home", hostView nothingStable, false),
   ("a run's bind of a replaceable path", runBind nothingStable, false),
   ("a run's bind of the stable toolchain", runBind ⟨[], [], [], [["usr"]]⟩, true),
   ("a stable grant made writable, a read-only one skipped in it", stableMadeWritable, false),
   ("a read-only grant below a file, skipped", belowFile, true),
   ("a bind nested in a writable bind, two levels down", carryOff, false),
   ("the same, the outer a view, the inner bound back", viewedProj, true),
   ("a bind nested in a writable bind, a direct child", directChild, false),
   ("a skipped bind over nothing", skippedBind, true),
   ("a skipped bind under a writable one", skippedUnderWrite, false),
   ("a grant through a link, bound as it leads", aliased, true),
   ("a grant through a link to nothing, skipped", aliasedToNothing, true),
   ("a grant through a link, under another bind", aliasUnderBind, false),
   ("a bind of a path never read", unrecorded, false),
   ("a bind of a path reached through a link", throughLink, false),
   ("a mount before its ancestor", outOfOrder, false)]

def main : IO UInt32 := do
  let mut failed := 0
  for (name, pl, expect) in cases do
    let got := pl.check
    if got == expect then
      IO.println s!"ok    {name}"
    else
      IO.println s!"FAIL  {name}: check = {got}, expected {expect}"
      failed := failed + 1
  return if failed == 0 then 0 else 1
