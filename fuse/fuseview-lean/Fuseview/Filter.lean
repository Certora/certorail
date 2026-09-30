import Fuseview.Match

/-!
The filter: the layers a view holds, asked about concrete paths below the directory it serves.

What a layer means -- which paths it covers, what it says of them, the state they end in by the
layers in order, and when a directory may move -- is the placement checker's (`Place.Meaning`:
`Layer.covers`, `after`, `stateFrom`, `movable`), run here on the daemon's patterns as the
matcher. The checker's proofs are about exactly this decision, and `Filter.make_wellFormed`
discharges what they ask of the matcher. What stays the daemon's own is what only a daemon needs:
which names *show* (a directory on the way to a grant; every entry of a readable directory), and
that a question no regex can answer gets the closed answer.
-/
namespace Fuseview

export Place (Says State Access Narrowing)

/-- A layer's region as a specification spells it. -/
inductive Region where
  | subtree (top : Path)
  | exactly (p : Path)
  | pattern (loc : Location) (anchor : Path)
  deriving Inhabited

/-- The literal tops of every pattern under *key*, as the checker's layer carries them. -/
def topsFor (patterns : List (String × Pattern)) (k : String) : List Place.Path :=
  (patterns.filter (·.1 == k)).flatMap (·.2.tops)

def mkLayer (patterns : List (String × Pattern)) (key : String) (says : Says) : Region → Place.Layer
  | .subtree top => ⟨.subtree (toPlace top), says⟩
  | .exactly p => ⟨.exactly (toPlace p), says⟩
  | .pattern _ _ => ⟨.pattern key (topsFor patterns key), says⟩

def withIndex : List α → Nat → List (α × Nat)
  | [], _ => []
  | a :: as, i => (a, i) :: withIndex as (i + 1)

/-- The matcher over *patterns*: a pattern's key names it. -/
def matcherOf (patterns : List (String × Pattern)) : Place.Matcher :=
  fun k q => (patterns.filter (·.1 == k)).any fun e => (e.2.denotesAt q).getD false

structure Filter where
  directory : Path
  /-- the checker's layers: a pattern is its key, and its literal tops -/
  layers : List Place.Layer
  /-- the patterns behind the keys -/
  patterns : List (String × Pattern)

instance : Inhabited Filter := ⟨⟨#[], [], []⟩⟩

namespace Filter

def make (directory : Path) (ls : List (Says × Region)) : Filter :=
  let indexed := withIndex ls 0
  let patterns := indexed.filterMap fun e =>
    match e.1.2 with
    | .pattern loc anchor => some (toString e.2, ⟨loc, anchor⟩)
    | _ => none
  { directory, layers := indexed.map fun e => mkLayer patterns (toString e.2) e.1.1 e.1.2, patterns }

def matcher (f : Filter) : Place.Matcher := matcherOf f.patterns

def patternsOf (f : Filter) (k : String) : List Pattern := (f.patterns.filter (·.1 == k)).map (·.2)

theorem wellFormed_matcherOf {patterns : List (String × Pattern)} {layers : List Place.Layer}
    (h : ∀ l ∈ layers, ∀ k ts, l.region = .pattern k ts → ts = topsFor patterns k) :
    Place.WellFormed (matcherOf patterns) layers := by
  intro l hl k ts hr q hq
  rw [h l hl k ts hr]
  simp only [matcherOf, List.any_eq_true] at hq
  obtain ⟨e, he, hd⟩ := hq
  have hsome : e.2.denotesAt q = some true := by
    cases hx : e.2.denotesAt q with
    | none => rw [hx] at hd; cases hd
    | some b => rw [hx] at hd; cases b <;> simp_all
  obtain ⟨t, ht, hpre⟩ := Pattern.denotesAt_top hsome
  exact ⟨t, List.mem_flatMap.2 ⟨e, he, ht⟩, hpre⟩

/-- The filter's matcher keeps within its layers' tops: the placement checker's theorems about
what a view decides (`Place.sound`, `Place.run_sound`) apply to this daemon. -/
theorem make_wellFormed (directory : Path) (ls : List (Says × Region)) :
    Place.WellFormed (make directory ls).matcher (make directory ls).layers := by
  apply wellFormed_matcherOf
  intro l hl k ts hr
  simp only [make, List.mem_map] at hl
  obtain ⟨⟨⟨s, r⟩, i⟩, _, hl⟩ := hl
  subst hl
  cases r with
  | subtree _ => simp [mkLayer] at hr
  | exactly _ => simp [mkLayer] at hr
  | pattern _ _ =>
    simp only [mkLayer, Place.Region.pattern.injEq] at hr
    obtain ⟨hk, hts⟩ := hr
    subst hk
    simp only [make]
    exact hts.symm

-- -- closed answers ------------------------------------------------------------------------------------

def prefixesN : List Name → List (List Name)
  | [] => [[]]
  | n :: ns => [] :: (prefixesN ns).map (n :: ·)

/-- Can some pattern not say whether it covers *names* -- the path, or, for a restriction, a
directory above it? Then every answer about the path is the closed one. -/
def unsure (f : Filter) (names : List Name) : Bool :=
  f.layers.any fun l =>
    match l.region with
    | .pattern k _ =>
      let candidates := if l.says.isRestriction then prefixesN names else [names]
      (f.patternsOf k).any fun pat => candidates.any fun c => (pat.denotesNames c).isNone
    | _ => false

/-- *path*'s state, by the layers in order: the checker's `stateFrom`, on this daemon's patterns. -/
def decided (f : Filter) (path : Path) : Option State :=
  let names := (f.directory ++ path).toList
  if f.unsure names then none
  else some (Place.stateFrom f.matcher .absent f.layers (names.map Name.encode))

def isReadable (f : Filter) (path : Path) : Option Bool := do
  let st ← f.decided path
  return st == .readOnly || st == .writable

/-- Does a hidden layer have the last word on *at*: cover it, with no grant covering it after? -/
def hiddenLastWord (f : Filter) (at_ : Place.Path) : List Place.Layer → Bool → Bool
  | [], acc => acc
  | l :: ls, acc =>
    let acc := if l.covers f.matcher at_
      then l.says == .restrict .hidden || (acc && l.says.isRestriction)
      else acc
    f.hiddenLastWord at_ ls acc

/-- Hidden: the name shows where its directory is readable, and its contents -- a file's data, a
directory's listing and every name below it -- are refused with `EACCES`, not `ENOENT`, so a tool
sees a refusal and not an absence. Files and directories alike; and whether or not anything
granted the path before the hide (a hide over what no grant shows still refuses, rather than
answering "not there"). -/
def hidden (f : Filter) (path : Path) : Bool :=
  let names := (f.directory ++ path).toList
  f.unsure names || f.hiddenLastWord (names.map Name.encode) f.layers false

/-- A file's contents open, a directory lists every name. -/
def readable (f : Filter) (path : Path) : Bool := (f.isReadable path).getD false

/-- Writable: the name may be created, changed or removed. Never the served directory itself,
which is a mountpoint. -/
def mayWrite (f : Filter) (path : Path) : Bool :=
  path.size > 0 && f.decided path == some .writable

-- -- which names show -----------------------------------------------------------------------------------

/-- Might *r* name something strictly below *names*? -/
def reachesBelow (f : Filter) (r : Place.Region) (names : List Name) : Option Bool :=
  match r with
  | .subtree t | .exactly t =>
    some (decide (t.length > names.length) && Place.prefixOf (names.map Name.encode) t)
  | .pattern k _ =>
    (f.patternsOf k).foldlM (init := false) fun acc pat => do return acc || (← pat.belowNames names)

/-- Does a hidden layer among *ls* cover *at*? -/
def hiddenFrom (f : Filter) (at_ : Place.Path) : List Place.Layer → Bool
  | [] => false
  | l :: ls => (l.says == .restrict .hidden && l.covers f.matcher at_) || f.hiddenFrom at_ ls

/-- Is the directory on the way to something a grant names below it, with no hidden layer after
that grant covering it? -/
def onTheWay (f : Filter) (names : List Name) (at_ : Place.Path) : List Place.Layer → Option Bool
  | [] => some false
  | l :: ls => do
    if !l.says.isRestriction then
      if ← f.reachesBelow l.region names then
        if !(f.hiddenFrom at_ ls) then return true
    f.onTheWay names at_ ls

/-- A directory exists for the jail iff it is the served directory, readable, or on the way to
something a grant names below it that no hidden layer after the grant covers wholly. -/
def isDirVisible (f : Filter) (path : Path) : Option Bool := do
  if path.isEmpty then return true
  if ← f.isReadable path then return true
  let names := (f.directory ++ path).toList
  f.onTheWay names (names.map Name.encode) f.layers

/-- Visible: readable; or any entry, hidden or not, of a readable directory (a listing shows every
name it holds; what a hidden one refuses is its contents); or a directory on the way to a grant. -/
def isVisible (f : Filter) (path : Path) (isDir : Bool) : Option Bool := do
  if ← f.isReadable path then return true
  if path.size > 0 then
    if ← f.isReadable path.pop then return true
  if isDir then f.isDirVisible path else return false

/-- Does the entry look up and list? Readable; under a readable directory, by name, hidden or
not; or a directory on the way to a grant. -/
def visible (f : Filter) (path : Path) (isDir : Bool) : Bool := (f.isVisible path isDir).getD false

-- -- moving a directory -------------------------------------------------------------------------------

/-- What the daemon knows of its patterns for the rename rule. -/
def reach (f : Filter) : Place.Reach where
  wholly k a := (f.patternsOf k).any fun pat => (pat.whollyAt a).getD false
  below k a := (f.patternsOf k).any fun pat => (pat.belowAt a).getD false

/-- Can some pattern not answer what the rename rule asks of *names*? -/
def unsureMove (f : Filter) (names : List Name) : Bool :=
  f.unsure names || f.layers.any fun l =>
    match l.region with
    | .pattern k _ => (f.patternsOf k).any fun pat =>
        (pat.whollyNames names).isNone || (pat.belowNames names).isNone
          || (prefixesN names).any fun c => (pat.denotesNames c).isNone
    | _ => false

/-- May a directory move from *src* to *dst*? The checker's `movable`, on this daemon's patterns:
some writable grant covers both ends wholly, and no layer after it covers or reaches below either.
A question no regex can answer refuses the move. -/
def mayMoveDir (f : Filter) (src dst : Path) : Bool :=
  let a := (f.directory ++ src).toList
  let b := (f.directory ++ dst).toList
  !f.unsureMove a && !f.unsureMove b
    && Place.movable f.matcher f.reach f.layers (a.map Name.encode) (b.map Name.encode)

/-- A move this daemon allows, the placement checker's blind rule allows at both ends: a directory
the checker holds still for a bind back on a view (`Place.Plan.footing`: `!dirRule noPatterns
blind`) is one this daemon never moves -- the checker's assumption about the kernel
(`Place.Kernel.mounts`), made good here. Tops play no part in the blind rule, so it reads the same
over the checker's layers as over this filter's. -/
theorem mayMoveDir_blind (f : Filter) {src dst : Path} (h : f.mayMoveDir src dst = true) :
    Place.dirRule Place.noPatterns Place.blind f.layers ((f.directory ++ src).toList.map Name.encode) = true
    ∧ Place.dirRule Place.noPatterns Place.blind f.layers ((f.directory ++ dst).toList.map Name.encode) = true := by
  unfold mayMoveDir at h
  simp only [Bool.and_eq_true] at h
  exact Place.movable_blind h.2

end Filter
end Fuseview
