# The placement checker

The Python placer (`certorail/sandbox/place.py`) decides how bubblewrap holds a jail's grants:
binds and views. This package certifies each plan it makes before anything runs in it. The proof
covers the checker, not the placer, so the placer stays free to change: a plan it gets wrong is
refused (`certorail/sandbox/certify.py`), never run.

    lake -d proofs/place build place-check     # the checker certorail runs
    lake -d proofs/place exe place-tests       # hand-built plans, accepted and refused

The binary carries Lean's runtime (Apache-2.0) and, through Lean's toolchain, a static GMP
(LGPL v3): what that means for shipping it is in `THIRD_PARTY.md` at the repository root.

## What is proved

`Place.run_sound` (`Place/Run.lean`) covers any plan `check` accepts, run on a kernel that behaves
as `Kernel` says, in a world that keeps `Trust` and `FactsHold`. At every step of the run, at
every path, the jail shows what the grants mean of what the host has there then (`Shows`). It
holds for every pattern matcher that keeps within its patterns' tops, and so for whatever the
views' daemon runs. The static half, a single moment, is `Place.sound` (`Place/Sound.lean`). Both
rest on Lean's standard axioms alone (`Tests.lean` guards the list).

"What the jail shows" is one of four outcomes:
- the same state as the grants, and the object the host has at that name where that state is
  present -- nothing where it is absent or hidden. Through a view that last part is what the daemon
  is *claimed* to do (`ENOENT`, `EACCES`; `Plan.content`), stated so the claim is in the theorem,
  and not proved of the daemon (below);
- or nothing, on the empty root below a skipped bind, where the grants may not write;
- or nothing, below a bind of a file;
- or, for one exec only, a bind on the empty root whose host name has been replaced: it shows the
  object it captured, wherever the host now names it, in the grants' state (`Stale`). Never wider
  than the grants; the only staleness the model admits, and the theorem says so.

## The model of mounts: measured, not assumed

Everything the model says about what a replacement does to a mount is a row of
`scripts/probe_bind_semantics.py` (kernel 6.8, 2026-09-29):
- a mount on a host name goes with its directory when the directory is renamed away, and detaches
  when the name is removed or renamed over -- host world and policy world alike;
- a mount on the jail's own empty root (bubblewrap's tmpfs) stays; a bind there keeps its object;
- the jail sees the change at once;
- a nested user and mount namespace cannot unmount a jail mount.

So the checker allows a mount only with a *footing* (obligation 5): on the empty root; or a view on
the host base at a name only root replaces (`$HOME`, a top-level directory: `fixed`, trusted); or
a bind back on a view, where the daemon may move no directory above it. A bind back is `live`
while the host still names, at its path, the object it was made over; gone, its view decides the
name. That too is measured (`scripts/probe_view_bindback.py`, 2026-09-29): a file bind back
detaches at once, a directory one when the kernel next revalidates the entry -- within the
daemon's 1 s directory entry cache -- and until then it is pinned to the moved object. That bounded
window is the one staleness the model rounds to zero. Nothing else is assumed about replacement,
and there is no "accepted race".

## The obligations

1. A fresh name: no path the plan names has `/` as a component.
2. Views hold what they must: each is mounted at its own path, holds exactly the layers that
   reach its directory, and is writable wherever it could grant a write.
3. Patterns are held by views: every top of every pattern lies in one, but a restriction's top
   no grant reaches on the empty root.
4. Agreement at the representatives: finitely many paths stand for all, and at each the jail
   builds what the grants mean.
5. Footings, as above; and for a whole run, a bind on the empty root leads only to a name nothing
   outside replaces (`holds`) that no grant makes writable, so it never goes stale.
6. Mounts sit on what the facts say: sources exist, reached without a link, or are missing and
   skipped; aliases stand alone on the empty root; mounts come ancestors first.

## What is trusted

- **The kernel** (`Kernel`): the trace applies each step; nothing lies below what is missing or
  below a file; an object holds what lies below its name; the jail changes only entries its mounts
  make writable (`EROFS`, `EACCES`, the daemon's `writableName`); and it never touches a live
  mount's own name or a directory above it (`EBUSY` at a mountpoint; the read-only tmpfs root;
  and the daemon's `mayMoveDir`, which is proved to refuse every directory the footing holds
  still: `movable_blind` here, `Fuseview.Filter.mayMoveDir_blind` in the daemon -- the one piece
  of this assumption that is a theorem rather than a property of the kernel).
- **The stability model** (`Trust`): nothing touches a `fixed` name or a directory above it --
  which is what keeps a view at one where it is (`view_live`: the model has a view live only
  while the host names its directory as it did, like any mount on a host name); nothing outside
  the jail touches a stable one (`kept`, `subtrees`), which is what keeps a whole run's bind
  naming what it did (`root_leads_stays`). It is `world.toml`'s `stable`: the user's judgment
  about the machine, spelled out per world by `certify.stability`.
- **The facts** (`FactsHold`): what the placer read was true when the jail was made. Each spawn
  asks again (`Recorded.changed`).
- **The views' daemon**: it decides each name by `stateFrom` over its layers, shows the host's
  object at a name it decides present and nothing at one it decides absent or hidden, and refuses
  a directory rename by `movable`. The Lean daemon (`fuse/fuseview-lean`) runs these very
  definitions -- `Filter.decided` is `Place.stateFrom`, `Filter.mayMoveDir` is `Place.movable` --
  and two facts about its code are theorems: its matcher keeps within its tops
  (`Filter.make_wellFormed`), and it moves no directory the footing holds still
  (`Filter.mayMoveDir_blind`). Everything else about it is trusted: that its request handlers
  consult those decisions before answering, its name policy (every entry of a readable directory
  shows by name; a directory on the way to a grant exists; a hide has the last word even over
  nothing), and its closed answer where a regex cannot say. Those are code and protocol tests, not
  proofs.
- **Outside the model entirely:**
  - the link step's additions (the spawn's executable and scratch directory);
  - mounts the host makes after the jail starts (not measured: needs root);
  - bubblewrap's rendering of mounts as flags (`emit.py`);
  - the JSON boundary (`Place/Decode.lean`, `certify.document`);
  - Seatbelt, which has no mounts to certify.
