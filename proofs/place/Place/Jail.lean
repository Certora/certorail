import Place.Meaning

/-!
A jail as bubblewrap builds it (`sandbox/tree.py`, `emit.py`): a base, then mounts, each at a
path with a state and a source -- the host's own path there, or a view. A path is what the mount
nearest it, at or above it, makes it: the longest one whose path
is its prefix. That is bubblewrap's order-of-mounts semantics when no later mount is at or above
an earlier one, which the flattened list keeps (ancestors first) and the checker insists on
(`ordered`).

A view (`viewdaemon.ViewSpec`) holds layers and decides every name below its directory by them,
over nothing; the host world's view starts with a grant of the host base over its directory
(`place.FromHost`). Mounted read-only, what it decides writable is read-only.

A bind of a path the host has nothing at is skipped (`--bind-try`): the jail keeps the path as
*missing*, where nothing is, and the checker holds it to showing nothing (`Check.lean`).
-/
namespace Place

inductive Source where
  /-- the host's own path, at itself -/
  | own
  /-- the host's *target*, at a path that leads there through a link: bubblewrap follows every
  link on a bind's source, so a stable grant spelled through one is bound as it leads -/
  | alias (target : Path)
  /-- *rel* inside the view of that index -/
  | view (v : Nat) (rel : Path)
  deriving DecidableEq, Repr

structure Mount where
  path : Path
  state : State
  source : Source
  deriving DecidableEq, Repr

structure View where
  dir : Path
  layers : List Layer
  deriving DecidableEq, Repr

inductive Base where
  /-- the policy world: an empty, read-only tmpfs -/
  | empty
  /-- the host's `/`, writable or read-only -/
  | host (writable : Bool)
  deriving DecidableEq, Repr

def Base.state : Base → State
  | .empty => .absent
  | .host true => .writable
  | .host false => .readOnly

structure Jail where
  base : Base
  /-- the grants, as the front end states them: the meaning -/
  layers : List Layer
  views : List View
  /-- the mounts bubblewrap makes, as flattened: ancestors first -/
  mounts : List Mount
  /-- where a bind was skipped, and where the host has nothing: its path, and where that leads
  (itself, or an alias's target) -/
  missing : List (Path × Path)
  /-- binds of a file, with nothing mounted below them: its path, and where that leads. Below a
  file nothing is, in the jail or on the host -/
  leaves : List (Path × Path)
  deriving Repr

def Jail.meaning (M : Matcher) (j : Jail) (p : Path) : State := stateFrom M j.base.state j.layers p

/-- The mount nearest *p*, at or above it. -/
def nearest (ms : List Mount) (p : Path) : Option Mount :=
  argmax (fun m => m.path.length) (ms.filter fun m => prefixOf m.path p)

/-- What a mount's own state leaves of what a view decides: a read-only mount, nothing writable. -/
def cap (mount decided : State) : State :=
  if mount = .readOnly ∧ decided = .writable then .readOnly else decided

def Jail.built (M : Matcher) (j : Jail) (p : Path) : State :=
  match nearest j.mounts p with
  | none => j.base.state
  | some m =>
    match m.source with
    | .own => m.state
    | .alias _ => m.state
    | .view v _ =>
      match j.views[v]? with
      | none => .absent
      | some view => cap m.state (stateFrom M .absent view.layers p)

/-- The layers a view of *d* must hold: every layer that might decide something at or below it, in
order -- after, in the host world, the host base itself over *d*. -/
def viewLayers (base : Base) (d : Path) (layers : List Layer) : List Layer :=
  let absorbed := layers.filter fun l => overlaps l.region d
  match base with
  | .empty => absorbed
  | .host w => ⟨.subtree d, .grant (if w then .writable else .readOnly)⟩ :: absorbed

/-- Below *d*, a view holding `viewLayers` decides exactly what the grants mean. -/
theorem viewLayers_agree {M : Matcher} {base : Base} {d p : Path} {layers : List Layer}
    (hwf : WellFormed M layers) (hdp : prefixOf d p = true) :
    stateFrom M .absent (viewLayers base d layers) p = stateFrom M base.state layers p := by
  cases base with
  | empty =>
    simp only [viewLayers, Base.state]
    exact stateFrom_filter_overlaps hdp _ hwf
  | host w =>
    simp only [viewLayers, stateFrom, Layer.covers, Region.covers, hdp, if_true]
    cases w <;> simp only [after, Base.state] <;> exact stateFrom_filter_overlaps hdp _ hwf

def hasWritableGrant (layers : List Layer) : Bool :=
  layers.any fun l => l.says == .grant .writable

/-- Might *p* be writable in the jail, whatever the patterns match? The mount's word, or a view's
that can grant a write and is mounted to let one through. -/
def Jail.mayWrite (j : Jail) (p : Path) : Bool :=
  match nearest j.mounts p with
  | none => j.base.state == .writable
  | some m =>
    match m.source with
    | .own => m.state == .writable
    | .alias _ => m.state == .writable
    | .view v _ =>
      match j.views[v]? with
      | none => false
      | some view => m.state != .readOnly && hasWritableGrant view.layers

theorem mayWrite_of_built {M : Matcher} {j : Jail} {p : Path} (h : j.built M p = .writable) :
    j.mayWrite p = true := by
  unfold Jail.built at h
  unfold Jail.mayWrite
  cases hn : nearest j.mounts p with
  | none => rw [hn] at h; simp [h]
  | some m =>
    rw [hn] at h
    dsimp only at h ⊢
    cases hs : m.source with
    | own => rw [hs] at h; simp [h]
    | alias t => rw [hs] at h; simp [h]
    | view v rel =>
      rw [hs] at h
      dsimp only at h ⊢
      cases hv : j.views[v]? with
      | none => rw [hv] at h; cases h
      | some view =>
        rw [hv] at h
        dsimp only at h ⊢
        unfold cap at h
        split at h
        · cases h
        · rename_i hnot
          have hw : hasWritableGrant view.layers = true := by
            rcases writable_of_stateFrom h with h' | ⟨l, hl, hsays⟩
            · cases h'
            · exact List.any_eq_true.2 ⟨l, hl, by simp [hsays]⟩
          have hro : m.state ≠ .readOnly := fun hro => hnot ⟨hro, h⟩
          simp [hw, hro]

end Place
