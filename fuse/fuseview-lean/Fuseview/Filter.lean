import Fuseview.Bytes
import Fuseview.NamePattern

/-!
The filter (`fuseview.Filter`, over `grants.covers` and `grants.after`): the layers a view holds,
asked about concrete paths below the directory it serves. A pattern is matched component by
component, as the analysis' ordering matches one whose other side is a real path
(`analysis.location_le`). Paths are absolute, as their components.

`none` is a question with no answer -- a regex that cannot say (see `NamePattern`) -- and every answer
built on one is the closed one: the name is neither visible, readable nor writable.
-/
namespace Fuseview

inductive Component where
  | named (n : Name)
  | any
  | oneOf (ns : Array Name)
  /-- the whole name must match -/
  | matching (re : NamePattern)
  deriving Inhabited

inductive Location where
  /-- exactly these components -/
  | path (cs : Array Component)
  /-- `pre/**` (no leaf): the prefix and everything below it; `pre/**/leaf`: anything strictly
  below it whose last component is the leaf -/
  | splat (pre : Array Component) (leaf : Option Component)
  deriving Inhabited

/-- An absolute path, as its components. -/
abbrev Path := Array Name

inductive Region where
  | subtree (top : Path)
  | exactly (p : Path)
  | pattern (loc : Location) (anchor : Path)
  deriving Inhabited

inductive Access where
  | readOnly
  | writable
  deriving BEq, Inhabited

inductive Narrowing where
  | noWrite
  | hidden
  deriving BEq, Inhabited

/-- What a layer says of the paths it covers: a grant its access, a restriction its narrowing. -/
inductive Says where
  | grant (a : Access)
  | restrict (n : Narrowing)
  deriving BEq, Inhabited

structure Layer where
  region : Region
  says : Says
  deriving Inhabited

inductive State where
  | absent
  | readOnly
  | writable
  | hidden
  deriving BEq, Inhabited

def accepts (c : Component) (name : Name) : Option Bool :=
  match c with
  | .named n => some (n == name)
  | .any => some true
  | .oneOf ns => some (ns.any (· == name))
  | .matching re => re.fullmatch name

/-- Components `cs[k, count)` against the names `path[lo + k, lo + count)`. -/
partial def acceptsFrom (cs : Array Component) (path : Path) (lo count k : Nat) : Option Bool :=
  if k ≥ count then some true
  else match accepts cs[k]! path[lo + k]! with
    | some true => acceptsFrom cs path lo count (k + 1)
    | other => other

def acceptsAll (cs : Array Component) (path : Path) (lo count : Nat) : Option Bool :=
  acceptsFrom cs path lo count 0

partial def prefixFrom (pre full : Path) (i : Nat) : Bool :=
  if i ≥ pre.size then true
  else if pre[i]! == full[i]! then prefixFrom pre full (i + 1)
  else false

/-- Is *pre* a prefix of *full* (at or above it)? -/
def isPrefix (pre full : Path) : Bool :=
  pre.size ≤ full.size && prefixFrom pre full 0

/-- Does *loc* denote the path `path[lo, hi)` spells, relative to its anchor? -/
def denotes (loc : Location) (path : Path) (lo hi : Nat) : Option Bool :=
  let n := hi - lo
  match loc with
  | .path cs => if cs.size != n then some false else acceptsAll cs path lo n
  | .splat pre leaf =>
    if n < pre.size then some false
    else match acceptsAll pre path lo pre.size with
      | some true =>
        if n == pre.size then some leaf.isNone  -- the prefix itself: only the reflexive form
        else match leaf with
          | none => some true
          | some l => accepts l path[hi - 1]!
      | other => other

/-- Does *loc* denote some path strictly below `path[lo, hi)`, relative to its anchor? -/
def namesBelow (loc : Location) (path : Path) (lo hi : Nat) : Option Bool :=
  let n := hi - lo
  match loc with
  | .path cs => if cs.size ≤ n then some false else acceptsAll cs path lo n
  | .splat pre _ => acceptsAll pre path lo (min pre.size n)

/-- The candidates `at[0, k)` from *k* down to *stop*: a restriction reaches below what it names. -/
partial def coversFrom (loc : Location) (at_ : Path) (lo k stop : Nat) : Option Bool :=
  match denotes loc at_ lo k with
  | some true => some true
  | some false => if k ≤ stop then some false else coversFrom loc at_ lo (k - 1) stop
  | none => none

/-- Does *r* cover *at*? With *belowToo* -- a restriction's -- also whatever lies below what it
covers. -/
def covers (r : Region) (at_ : Path) (belowToo : Bool) : Option Bool :=
  match r with
  | .subtree top => some (isPrefix top at_)
  | .exactly p => some (if belowToo then isPrefix p at_ else p.size == at_.size && isPrefix p at_)
  | .pattern loc anchor =>
    if !isPrefix anchor at_ then some false
    else if belowToo then coversFrom loc at_ anchor.size at_.size anchor.size
    else denotes loc at_ anchor.size at_.size

/-- Might *r* name something strictly below *path*? -/
def reachesBelow (r : Region) (path : Path) : Option Bool :=
  match r with
  | .subtree top | .exactly top => some (top.size > path.size && isPrefix path top)
  | .pattern loc anchor =>
    if isPrefix path anchor then some true  -- at or above where the pattern is anchored
    else if isPrefix anchor path then namesBelow loc path anchor.size path.size
    else some false

/-- Does *r* cover *path* and everything below it? A subtree does, and a pattern `pre/**` (no leaf)
that covers the path; nothing else is known to. -/
def coversWholly (r : Region) (path : Path) : Option Bool :=
  match r with
  | .subtree top => some (isPrefix top path)
  | .pattern (.splat pre none) anchor => covers (.pattern (.splat pre none) anchor) path false
  | _ => some false

/-- Might *r* decide anything at or below *path*? -/
def touches (r : Region) (path : Path) (restriction : Bool) : Option Bool := do
  if ← covers r path restriction then return true
  reachesBelow r path

/-- *st*, once a layer saying *says* covers the path: a grant sets its access; no-write turns
writable into read-only; hidden turns anything present into hidden. Neither restriction makes an
absent path appear. -/
def after (st : State) (says : Says) : State :=
  match says with
  | .grant .writable => .writable
  | .grant .readOnly => .readOnly
  | .restrict .noWrite => if st == .writable then .readOnly else st
  | .restrict .hidden => if st == .absent then st else .hidden

def Says.isRestriction : Says → Bool
  | .restrict _ => true
  | .grant _ => false

structure Filter where
  directory : Path
  layers : Array Layer
  deriving Inhabited

namespace Filter

/-- *path*'s state, by the layers in order, and whether a hidden layer has the last word on it --
covers it, with no grant covering it after. -/
def decided (f : Filter) (path : Path) : Option (State × Bool) := do
  let at_ := f.directory ++ path
  let mut st := State.absent
  let mut hidden := false
  for layer in f.layers do
    let restriction := layer.says.isRestriction
    if ← covers layer.region at_ restriction then
      st := after st layer.says
      hidden := layer.says == .restrict .hidden || (hidden && restriction)
  return (st, hidden)

def isReadable (f : Filter) (path : Path) : Option Bool := do
  let (st, _) ← f.decided path
  return st == .readOnly || st == .writable

/-- Does a hidden layer from *j* on cover *at* wholly? -/
partial def hiddenFrom (f : Filter) (at_ : Path) (j : Nat) : Option Bool := do
  if j ≥ f.layers.size then return false
  let later := f.layers[j]!
  if later.says == .restrict .hidden then
    if ← covers later.region at_ true then return true
  hiddenFrom f at_ (j + 1)

partial def onTheWayFrom (f : Filter) (at_ : Path) (i : Nat) : Option Bool := do
  if i ≥ f.layers.size then return false
  let layer := f.layers[i]!
  if !layer.says.isRestriction then
    if ← reachesBelow layer.region at_ then
      if !(← hiddenFrom f at_ (i + 1)) then return true
  onTheWayFrom f at_ (i + 1)

/-- A directory exists for the jail iff it is the served directory, readable, or on the way to
something a grant names below it that no hidden layer after the grant covers wholly. -/
def isDirVisible (f : Filter) (path : Path) : Option Bool := do
  if path.isEmpty then return true
  if ← f.isReadable path then return true
  onTheWayFrom f (f.directory ++ path) 0

def isVisible (f : Filter) (path : Path) (isDir : Bool) : Option Bool := do
  if ← f.isReadable path then return true
  if path.size > 0 then
    if ← f.isReadable path.pop then
      let (_, hidden) ← f.decided path
      if !hidden then return true
  if isDir then f.isDirVisible path else return false

/-- A file's contents open, a directory lists every name. -/
def readable (f : Filter) (path : Path) : Bool := (f.isReadable path).getD false

/-- Does the entry look up and list? Readable; under a readable directory, by name, unless
hidden; or a directory on the way to a grant. -/
def visible (f : Filter) (path : Path) (isDir : Bool) : Bool := (f.isVisible path isDir).getD false

/-- Writable: the name may be created, changed or removed. Never the served directory itself,
which is a mountpoint. -/
def mayWrite (f : Filter) (path : Path) : Bool :=
  path.size > 0 && (match f.decided path with
    | some (.writable, _) => true
    | _ => false)

/-- Does no layer from *j* on cover or reach below *a* or *b*? -/
partial def untouchedFrom (f : Filter) (a b : Path) (j : Nat) : Option Bool := do
  if j ≥ f.layers.size then return true
  let later := f.layers[j]!
  let restriction := later.says.isRestriction
  if (← touches later.region a restriction) || (← touches later.region b restriction) then return false
  untouchedFrom f a b (j + 1)

partial def movableFrom (f : Filter) (a b : Path) (i : Nat) : Option Bool := do
  if i ≥ f.layers.size then return false
  let layer := f.layers[i]!
  if layer.says == .grant .writable then
    if (← coversWholly layer.region a) && (← coversWholly layer.region b) then
      if ← untouchedFrom f a b (i + 1) then return true
  movableFrom f a b (i + 1)

/-- May a directory move from *src* to *dst*? A directory's path is every path beneath it, so only
where each of those is decided alike before and after: a writable grant covers both ends wholly,
and no layer after it covers or reaches below either -- every path below either end is then
writable, by that grant, with nothing else having a say. -/
def mayMoveDir (f : Filter) (src dst : Path) : Bool :=
  (movableFrom f (f.directory ++ src) (f.directory ++ dst) 0).getD false

end Filter
end Fuseview
