import Place.Sound

/-!
What the checker is handed (`sandbox/certify.py`): the plan -- base, grants, views and flattened
mounts -- with what it rests on: the facts the placer read (`facts.Recorded`), how long the jail
lives (`grants.Lifetime`), and which names nothing replaces (the stability model). Two
obligations join `Check.lean`'s four:

5. **Every mount has a footing** a replacement from outside cannot take from under it. MEASURED
   (`scripts/probe_bind_semantics.py`, 2026-09-29): a mount goes with its directory when that is
   renamed away, and detaches when it is removed or renamed over; a mount on the jail's own empty
   root stays, pinned to the object it captured. So a mount sits
   - on the empty root (`root`): nothing outside touches bubblewrap's tmpfs; a bind there keeps
     showing the object it captured, wherever the host now names it -- stale, never wider, and for
     a whole run only at a name nothing outside replaces;
   - or it is a view on the host base at a name nothing replaces (`fixedView`: `$HOME`, a
     top-level directory);
   - or it is a bind back on a view (`onView`): when the host replaces the name under it, it
     detaches and the view decides the name -- so the view's daemon must never move a directory
     above it (`dirRule`), which the daemon would not carry the bind along with.
   Anything else -- a mount nested in a plain bind, on the host base at a replaceable name -- is
   refused: narrower detaches into wider, wider moves to a name the grants did not give.
6. **Mounts sit on what the facts say.** A bind's source exists, as a file or a directory reached
   without a link, or is missing (and skipped); an alias stands alone; a view's mountpoint is a
   directory; the mounts come ancestors first.
-/
namespace Place

inductive Lifetime where
  | exec
  | run
  deriving DecidableEq, Repr

/-- The names nothing replaces while a jail lives: the stability model, trusted, not checked. It is
the user's judgment about the machine (`world.toml`'s `stable`: the home directory and the
top-level directories by default, the dot directories of home, the sandbox root, named paths), as
`certify.stability` spells it out per world, with the working directory and the stable grants of
a policy world. Some nothing replaces at all, the jail included -- only root could, or the jail's
own root is a read-only tmpfs -- and on those a view may sit; the rest nothing outside the jail
replaces, and a whole run may bind them. -/
structure Stability where
  /-- these names, which nothing replaces (the home directory) -/
  names : List Path
  /-- every name in these directories, likewise (`/`: the top-level directories) -/
  childrenOf : List Path
  /-- these names, which nothing outside the jail replaces (the working directory) -/
  kept : List Path
  /-- everything at or below these, likewise (a stable grant's: the toolchain, the interpreter) -/
  subtrees : List Path
  deriving Repr

/-- Nothing replaces *q*, the jail included. -/
def Stability.fixed (s : Stability) (q : Path) : Bool :=
  s.names.contains q || (!q.isEmpty && s.childrenOf.contains q.dropLast)

/-- Nothing outside the jail replaces *q*. -/
def Stability.holds (s : Stability) (q : Path) : Bool :=
  s.fixed q || s.kept.contains q || s.subtrees.any (prefixOf · q)

inductive Kind where
  | file
  | directory
  | symlink
  | missing
  deriving DecidableEq, Repr

/-- What the placer read of the filesystem (`facts.Recorded`): a path's kind, as `lstat` says;
where it resolves, every link followed. What was not read is unknown. -/
structure Facts where
  kinds : List (Path × Kind)
  resolutions : List (Path × Path)
  deriving Repr

def Facts.kind? (f : Facts) (p : Path) : Option Kind := (f.kinds.find? (·.1 == p)).map (·.2)

/-- Reached without a link, at it or above it: it resolves to itself. -/
def Facts.plain (f : Facts) (p : Path) : Bool := f.resolutions.contains (p, p)

/-- A file or a directory, reached without a link. -/
def Facts.present (f : Facts) (p : Path) : Bool :=
  f.plain p && (f.kind? p == some .file || f.kind? p == some .directory)

structure Plan where
  base : Base
  layers : List Layer
  views : List View
  mounts : List Mount
  lifetime : Lifetime
  stability : Stability
  facts : Facts
  deriving Repr

def Source.isBind : Source → Bool
  | .own => true
  | .alias _ => true
  | _ => false

def Mount.target? (m : Mount) : Option Path :=
  match m.source with
  | .alias t => some t
  | _ => none

/-- Where a bind leads: its path, or an alias's target. -/
def Mount.leads (m : Mount) : Path := m.target?.getD m.path

/-- A bind bubblewrap skips: the host has nothing where its path leads. -/
def Plan.skipped (pl : Plan) (m : Mount) : Bool :=
  match m.source with
  | .own => pl.facts.kind? m.path == some .missing
  | .alias t => pl.facts.kind? t == some .missing
  | _ => false

/-- The mounts bubblewrap makes. -/
def Plan.made (pl : Plan) : List Mount := pl.mounts.filter fun m => !pl.skipped m

/-- The binds of a file with nothing made below them. -/
def Plan.leafMounts (pl : Plan) : List Mount :=
  pl.made.filter fun m =>
    m.source.isBind && pl.facts.kind? m.leads == some .file
      && pl.made.all fun m' => m' == m || !prefixOf m.path m'.path

/-- The mount nearest strictly above *p*. -/
def parentMount (ms : List Mount) (p : Path) : Option Mount :=
  nearest (ms.filter fun m => decide (m.path.length < p.length)) p

/-- The jail bubblewrap builds from the plan. What is known missing is what a skipped bind leaves
to no view and to no file: below a view, the view decides by name, whatever is there; below a
file, nothing can be. -/
def Plan.jail (pl : Plan) : Jail where
  base := pl.base
  layers := pl.layers
  views := pl.views
  mounts := pl.made
  missing := (pl.mounts.filter fun m =>
    pl.skipped m && !isViewAt (nearest pl.made m.path)
      && !pl.leafMounts.any fun l => prefixOf l.path m.path && l.path != m.path).map
      fun m => (m.path, m.leads)
  leaves := pl.leafMounts.map fun m => (m.path, m.leads)

-- -- obligation 5: footings ------------------------------------------------------------------------

inductive Footing where
  /-- on the jail's own empty root -/
  | root
  /-- a view on the host base, at a name nothing replaces -/
  | fixedView
  /-- a bind back on a view, which decides the name once the bind is gone -/
  | onView
  deriving DecidableEq, Repr

/-- What *m* stands on, if anything a replacement cannot take from under it. -/
def Plan.footing (pl : Plan) (m : Mount) : Option Footing :=
  match parentMount pl.made m.path with
  | none =>
    if pl.base == .empty then some .root
    else if m.isView && pl.stability.fixed m.path then some .fixedView
    else none
  | some p =>
    match p.source with
    | .view v _ =>
      match pl.views[v]? with
      | some view =>
        -- the host's own path, and no directory the daemon may move between the view and it:
        -- the daemon's own rule, knowing nothing of its patterns -- which moves whatever the
        -- daemon's does (`movable_blind`), so what it holds still, the daemon holds still
        if m.source == .own
            && (prefixes m.path).all (fun a => !(prefixOf p.path a && a != p.path && a != m.path)
                                            || !dirRule noPatterns blind view.layers a)
        then some .onView else none
      | none => none
    | _ => none

/-- Is *m* a skipped bind below a bind of a file, where nothing is or comes to be? -/
def Plan.skippedBelowLeaf (pl : Plan) (m : Mount) : Bool :=
  pl.skipped m && pl.leafMounts.any fun l => prefixOf l.path m.path && l.path != m.path

/-- Every mount has a footing -- but a bind skipped below a bind of a file, which needs none. -/
def Plan.footed (pl : Plan) : Bool := pl.mounts.all fun m => (pl.footing m).isSome || pl.skippedBelowLeaf m

/-- Does a writable grant cover *a* from above? Then the grants may make *a* writable. -/
def Plan.grantsWriteAbove (pl : Plan) (a : Path) : Bool :=
  pl.layers.any fun l => l.says == .grant .writable && l.region.tops.any (prefixOf · a)

/-- For a whole run, a bind on the empty root leads to a name nothing replaces: nothing outside
does (`holds`), and the jail cannot, since no grant makes it or a directory above it writable --
its own mountpoint aside, which the kernel refuses to move -- and none of those lies below a bind
of a file. Else the bind would pin an object the host has moved on from, for the run's whole
life. -/
def Plan.rootBindsStable (pl : Plan) : Bool :=
  pl.lifetime == .exec || pl.made.all fun m =>
    !(pl.footing m == some .root && m.source.isBind)
      || (pl.stability.holds m.leads
          && (prefixes m.leads).all fun a => a == m.path || (!pl.grantsWriteAbove a && !pl.jail.belowLeaf a))

-- -- obligation 6: the facts -----------------------------------------------------------------------

/-- No mount comes after one at or below it. -/
def ordered : List Mount → Bool
  | [] => true
  | m :: ms => ms.all (fun m' => !prefixOf m'.path m.path) && ordered ms

/-- A bind's source, per the facts: missing, or a file or a directory reached without a link, bound
as bubblewrap can bind it. -/
def Plan.bindsFrom (pl : Plan) (m : Mount) (source : Path) : Bool :=
  pl.facts.kind? source == some .missing
    || (pl.facts.present source && (m.state == .readOnly || m.state == .writable))

def Plan.sitsOn (pl : Plan) (m : Mount) : Bool :=
  match m.source with
  | .own => pl.bindsFrom m m.path
  | .alias t => pl.facts.resolutions.contains (m.path, t) && pl.bindsFrom m t
  | .view _ _ => pl.facts.plain m.path && pl.facts.kind? m.path == some .directory

/-- An alias stands alone, on the policy world's empty root: nothing else is mounted at, above or
below it -- so what lies below it is the alias's, or, skipped, nothing. -/
def Plan.aliasAlone (pl : Plan) (m : Mount) : Bool :=
  match m.source with
  | .alias _ => pl.base == .empty && pl.mounts.all fun m' =>
    m' == m || (!prefixOf m.path m'.path && !prefixOf m'.path m.path)
  | _ => true

def Plan.sits (pl : Plan) : Bool :=
  pl.mounts.all pl.sitsOn && pl.mounts.all pl.aliasAlone && ordered pl.mounts

def Plan.check (pl : Plan) : Bool := pl.jail.check && pl.sits && pl.footed && pl.rootBindsStable

end Place
