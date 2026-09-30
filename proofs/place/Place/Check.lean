import Place.Jail

/-!
The checker's static half: a jail certified against its grants, by obligations it decides with no
filesystem and no regex. `Plan.lean` adds the rest -- the facts, and what may change during a run.

1. **A fresh name.** `/` is no component of any path the jail names (it is never one of a real
   path's), so a path's child by that name is past every breakpoint.
2. **Views hold what they must.** A view is mounted at its own path (its directory, with what
   lies inside it after); it holds exactly `viewLayers`; and it is mounted writable wherever it
   could decide something writable, read-only only where it cannot.
3. **Patterns are held by views.** Below every top of every pattern, and at the top itself, the
   nearest mount is a view: nothing but a view lies at or below the top, and the longest mount at
   or above it is one. So a pattern -- grant or restriction -- is decided by name, by a daemon.
   Except a restriction's top that no grant reaches, on the empty root: nothing is there to
   narrow.
4. **Agreement at the representatives.** Outside the views, whether a path is covered depends only
   on which *breakpoints* (every subtree's and exact path's, every mount's path, every skipped
   bind's) it lies at or below, so finitely many paths stand for all of them: every prefix of a
   breakpoint, and each of those with the fresh name after it. At each one whose nearest mount is
   no view, the jail builds what the grants mean, patterns aside (obligation 3 keeps them off such
   paths) -- or, below a skipped bind on the empty root, where nothing is, the grants may not
   write; or it is below a bind of a file, where nothing can be.

`Sound.lean` proves that a jail passing all four builds, at every path, what its grants mean,
for every matcher that keeps within its patterns' tops.
-/
namespace Place

def Mount.isView (m : Mount) : Bool :=
  match m.source with
  | .view _ _ => true
  | _ => false

def isViewAt : Option Mount → Bool
  | some m => m.isView
  | none => false

/-- The paths at or below which a path's fate can change, outside the views. -/
def breakpoints (j : Jail) : List Path :=
  (j.layers.filterMap fun l =>
    match l.region with
    | .subtree p => some p
    | .exactly p => some p
    | .pattern _ _ => none)
  ++ j.mounts.map (·.path) ++ j.missing.map (·.1) ++ j.leaves.map (·.1)

/-- `/`, and every prefix of every breakpoint. -/
def tree (j : Jail) : List Path := [] :: (breakpoints j).flatMap prefixes

def fresh : String := "/"

def representatives (j : Jail) : List Path := tree j ++ (tree j).map (· ++ [fresh])

def freshIsFresh (j : Jail) : Bool := (breakpoints j).all fun b => decide (fresh ∉ b)

def viewHolds (j : Jail) (m : Mount) : Bool :=
  match m.source with
  | .view v rel =>
    match j.views[v]? with
    | none => false
    | some view =>
      view.dir ++ rel == m.path
        && view.layers == viewLayers j.base view.dir j.layers
        && (m.state == .writable || (m.state == .readOnly && !hasWritableGrant view.layers))
  | _ => true

def viewsHold (j : Jail) : Bool := j.mounts.all (viewHolds j)

/-- Every top of every pattern lies in a view: nothing but a view at or below it, and a view at or
above it longer than anything else there. -/
def viewedTop (j : Jail) (t : Path) : Bool :=
  (j.mounts.all fun m => !prefixOf t m.path || m.isView)
    && (j.mounts.any fun m₀ => m₀.isView && prefixOf m₀.path t
      && j.mounts.all fun m => !prefixOf m.path t || m.isView || decide (m.path.length < m₀.path.length))

def Region.isPattern : Region → Bool
  | .pattern _ _ => true
  | _ => false

/-- A top no grant reaches, on the policy world's empty root: nothing is below it, and a
restriction there narrows nothing. -/
def Jail.bare (j : Jail) (t : Path) : Bool :=
  j.base == .empty && !(j.layers.any fun g => !g.says.isRestriction && overlaps g.region t)

def patternsViewed (j : Jail) : Bool :=
  j.layers.all fun l =>
    match l.region with
    | .pattern _ ts => ts.all fun t => viewedTop j t || (l.says.isRestriction && j.bare t)
    | _ => true

/-- Is *p* at or below a skipped bind, with no mount at all above it: on the empty root, where
nothing is and nothing comes to be? -/
def Jail.nothingAt (j : Jail) (p : Path) : Bool :=
  j.missing.any (prefixOf ·.1 p) && (nearest j.mounts p).isNone

/-- Is *p* below a bind of a file, where nothing can be? -/
def Jail.belowLeaf (j : Jail) (p : Path) : Bool := j.leaves.any fun e => prefixOf e.1 p && e.1 != p

def agreesAt (j : Jail) (r : Path) : Bool :=
  isViewAt (nearest j.mounts r) || j.built noPatterns r == j.meaning noPatterns r
    || (j.nothingAt r && j.meaning noPatterns r != .writable)
    || j.belowLeaf r

def agreesAtRepresentatives (j : Jail) : Bool := (representatives j).all (agreesAt j)

def Jail.check (j : Jail) : Bool :=
  freshIsFresh j && viewsHold j && patternsViewed j && agreesAtRepresentatives j

/-- What the jail builds agrees with what the grants mean: the same state; or, below a skipped
bind on the empty root, where nothing is, a meaning that may not write, so that nothing comes to
be; or below a file, where nothing can. -/
def Agree (built meaning : State) (nothing below : Bool) : Prop :=
  built = meaning ∨ (nothing = true ∧ meaning ≠ .writable) ∨ below = true

end Place
