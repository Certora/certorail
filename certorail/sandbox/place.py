"""The Place pass: each layer of a jail held by a bind, placed in a view, or refused -- per
backend, from the grants and what ``Facts`` says of the filesystem, and nothing else.

Bubblewrap. A host jail is the host's ``/``, and nothing to place. In a policy jail a view is
correct by definition, and a bind stands in for it only where the two cannot disagree for as long
as the jail lives:

- A bind cannot say a pattern, a path named exactly (what is there may change kind, or not exist
  yet), a write grant whose path does not exist (a bind cannot let one new name be created), or a
  grant spelled through a link, at its top or above it (the bind would show where it leads).
- A policy-world bind keeps its source when its path is replaced: acceptable for one exec, not for
  a whole run, whose grants are held in views -- except what a run does not replace: the stable
  grants (the toolchain, the interpreter), the working directory, and the names the machine's
  stability model says nothing replaces (``world.toml``'s ``stable``, ``sandbox.stable``). Every
  restriction is held in a view.
- A mount sits only where nothing replaces the name under it (MEASURED, ``scripts/
  probe_bind_semantics.py``, 2026-09-29: a mount nested in a bind goes with its directory when
  that is renamed away, and detaches when it is removed or renamed over -- in the host world and
  the policy world alike -- so whatever surrounds it shows at its name). So a mount sits on the
  jail's own empty root, which nothing touches; or it is a view at a name the stability model
  says nothing replaces (``$HOME``, a top-level directory, by default); or it is bound back over
  a view, whose daemon decides the name by itself once the bind is gone. Nothing is ever nested
  inside a plain bind: a grant that would be -- inside another of a different state -- turns the
  outer bind into a view, its uniform children bound back. Each plan is then certified
  (``certify``).

Seatbelt matches names at every access: every layer is a rule, and there are no views.
"""
import pathlib
from collections.abc import Sequence
from dataclasses import dataclass

from certorail import sbpl
from certorail.locations import enumerable_prefixes
from certorail.sandbox.facts import Facts, Kind
from certorail.sandbox.grants import (
    Access, Exactly, Grant, Grants, HostGrants, Layer, Lifetime, Narrowing, Origin, Pattern, PolicyGrants,
    Region, Restriction, State, Subtree, state_at, within,
)
from certorail.sandbox.seatbelt import NOT_ERE, pattern_regex
from certorail.sandbox.stable import StableNames, expand

__all__ = [
    "Bind", "BwrapPlan", "CompileError", "EmptyBase", "HostBase", "Refusal", "Rule", "SeatbeltPlan",
    "Serve", "Served", "place_bubblewrap", "place_seatbelt", "region_tops",
]


# -- results ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Refusal:
    origin: Origin
    reason: str

    def describe(self) -> str:
        return f"{self.origin.describe()}: {self.reason}"


@dataclass(frozen=True)
class CompileError:
    """The jail cannot be held as configured: every reason, before anything runs."""

    refusals: tuple[Refusal, ...]


@dataclass(frozen=True)
class HostBase:
    writable: bool


@dataclass(frozen=True)
class EmptyBase:
    pass


type Base = HostBase | EmptyBase


@dataclass(frozen=True)
class Serve:
    """A view of *directory*: everything under it is the daemon's, which holds *layers* by name
    over nothing. The bubblewrap backend's one special op."""

    directory: pathlib.Path
    layers: tuple[Layer[Region], ...]


@dataclass(frozen=True)
class Bind:
    """The host's *path* at *path*."""

    path: pathlib.Path
    access: Access


@dataclass(frozen=True)
class Served:
    """A view's mountpoint at its directory: *access* is what the jail may do through it, the
    daemon deciding each name."""

    view: Serve
    access: Access

    @property
    def path(self) -> pathlib.Path:
        return self.view.directory


type Placed = Bind | Served


@dataclass(frozen=True)
class BwrapPlan:
    """What bubblewrap mounts, in application order, over the base."""

    base: Base
    items: tuple[Placed, ...]

    @property
    def views(self) -> tuple[Serve, ...]:
        return tuple(i.view for i in self.items if isinstance(i, Served))


@dataclass(frozen=True)
class SubpathRule:
    path: pathlib.Path


@dataclass(frozen=True)
class LiteralRule:
    path: pathlib.Path


@dataclass(frozen=True)
class RegexRule:
    regex: str


@dataclass(frozen=True)
class Rule:
    filter: SubpathRule | LiteralRule | RegexRule
    effect: Grant | Restriction


@dataclass(frozen=True)
class SeatbeltPlan:
    """What Seatbelt allows and denies, in application order (later rules win), over the base."""

    base: Base
    rules: tuple[Rule, ...]


# -- helpers ------------------------------------------------------------------------------------


def region_tops(region: Region) -> tuple[pathlib.Path, ...]:
    """The literal directories a region lies under: its path, or a pattern's literal prefixes."""
    match region:
        case Subtree(path=p) | Exactly(path=p):
            return (p,)
        case Pattern(location=loc, anchor=anchor):
            return tuple(anchor.joinpath(*names) for names in enumerable_prefixes(loc))


def _overlaps(region: Region, directory: pathlib.Path) -> bool:
    """Might *region* reach anything at or below *directory*?"""
    return any(within(t, directory) or within(directory, t) for t in region_tops(region))


def _plain(path: pathlib.Path, facts: Facts) -> bool:
    """Is *path* reached without a link, at it or above it? ``kind`` follows the links above a
    path (``lstat``), so only the resolution tells -- and a link in a loop resolves no further than
    itself, so its own kind says it is one."""
    return facts.resolve(path) == path and facts.kind(path) is not Kind.SYMLINK


def _existing_directory(path: pathlib.Path, facts: Facts) -> pathlib.Path:
    """*path* or its nearest ancestor that is a directory reached without a link: where a view of
    it can sit (a view's daemon opens its directory, and would follow a link)."""
    for candidate in (path, *path.parents):
        if facts.kind(candidate) is Kind.DIRECTORY and _plain(candidate, facts):
            return candidate
    return pathlib.Path("/")


def _check_needs(grants: PolicyGrants) -> list[Refusal]:
    out: list[Refusal] = []
    for layer in grants.layers:
        if not (isinstance(layer.effect, Restriction) and layer.effect.narrowing is Narrowing.HIDDEN):
            continue
        for need in (*grants.needs, *grants.listings):
            if _overlaps(layer.region, need):
                out.append(Refusal(layer.origin, f"hides {need}, which the jail cannot run without"))
    return out


def _access(state: State) -> Access:
    return Access.WRITABLE if state is State.WRITABLE else Access.READ_ONLY


def _uniform(grants: Grants, path: pathlib.Path) -> bool:
    """Does every layer that reaches *path* cover all of it, from at or above it, and leave it
    there, read-only or writable? Then one bind says it, and nothing below it needs a mount of its
    own."""
    return all(not _overlaps(layer.region, path)
               or (isinstance(layer.region, Subtree) and within(path, layer.region.path))
               for layer in grants.layers) and state_at(grants, path) in (State.READ_ONLY, State.WRITABLE)


def _wholly(region: Region, path: pathlib.Path) -> bool:
    match region:
        case Subtree(path=top):
            return within(path, top)
        case Exactly():
            return False
        case Pattern():
            return True  # as the checker takes it: erring toward moving


def _reaches(layer: Layer[Region], path: pathlib.Path) -> bool:
    """Does *layer* cover *path*, or reach below it? A pattern is taken to reach nothing."""
    match layer.region:
        case Subtree(path=top):
            return within(path, top) or within(top, path)
        case Exactly(path=exact):
            return within(exact, path) or (isinstance(layer.effect, Restriction) and within(path, exact))
        case Pattern():
            return False


def _dir_moves(layers: Sequence[Layer[Region]], path: pathlib.Path) -> bool:
    """Might a view holding *layers* move the directory *path*? Its daemon's rule, at one end
    (``Fuseview.Filter.mayMoveDir``): a writable grant covers it wholly, and no layer after that
    grant covers or reaches below it -- erring toward moving on a pattern, as the checker does
    (``Place.dirRule``)."""
    return any(
        isinstance(layer.effect, Grant) and layer.effect.access is Access.WRITABLE and _wholly(layer.region, path)
        and not any(_reaches(later, path) for later in layers[i + 1:])
        for i, layer in enumerate(layers)
    )


def _bindable_back(grants: Grants, layers: Sequence[Layer[Region]], directory: pathlib.Path, path: pathlib.Path,
                   facts: Facts) -> bool:
    """May *path*, inside the view of *directory* holding *layers*, be bound back over it? It must be
    uniform (one bind says all of it), be a plain file or directory, and sit where the view's
    daemon moves no directory above it: a bind back on the daemon's directory is not carried
    along by its renames, so none may happen. (What the host does to the name from outside
    detaches the bind, and the view decides the name then: that is why binding back is safe.)"""
    if path == directory or not within(path, directory):
        return False
    if not _uniform(grants, path) or facts.kind(path) not in (Kind.DIRECTORY, Kind.FILE) or not _plain(path, facts):
        return False
    between = [a for a in path.parents if within(a, directory) and a != directory]
    return not any(_dir_moves(layers, a) for a in between)


def _merge(wanted: Sequence[pathlib.Path]) -> list[pathlib.Path]:
    """Nested view directories merge into the outermost."""
    return [d for d in wanted if not any(o != d and within(d, o) for o in wanted)]


# -- bubblewrap: the policy world ---------------------------------------------------------------


def _kept(grants: PolicyGrants, names: StableNames, path: pathlib.Path) -> bool:
    """Does nothing outside the jail replace *path* during a run? The working directory, and the
    stability model's names."""
    return path == grants.workdir or names.fixed(path)


def _needs_view(layer: Layer[Region], grants: PolicyGrants, names: StableNames, facts: Facts) -> bool:
    region, effect = layer.region, layer.effect
    if isinstance(effect, Restriction) or not isinstance(region, Subtree):
        return True   # a restriction, a path named exactly, a pattern
    if effect.stable:
        return False  # bound as it leads: what a run does not replace
    if not _plain(region.path, facts):
        return True   # spelled through a link: a bind would show where it leads
    if grants.lifetime is Lifetime.RUN and not _kept(grants, names, region.path):
        return True   # the run's tools could replace it, and a bind would keep the old
    return effect.access is Access.WRITABLE and facts.kind(region.path) is Kind.MISSING


def _view_directories(layer: Layer[Region], grants: PolicyGrants, facts: Facts) -> list[pathlib.Path]:
    """Where the views holding *layer* sit, one for each of its literal tops (a pattern's
    ``{a,b}`` prefix has several): the root for what lies under it; for an absolute grant the
    nearest real directory at or above the top (strictly above, for a path named or linked, whose
    own entry the view must show); for an absolute restriction, the outermost grant the top lies
    in -- or, where grants lie in it instead, its own directory, and nowhere at a top no grant
    reaches, since a restriction on nothing is nothing."""
    tops = region_tops(layer.region)
    if all(within(t, grants.root) for t in tops):
        return [grants.root]
    out: dict[pathlib.Path, None] = {}
    for top in tops:
        match layer.effect:
            case Restriction():
                around = [
                    g.region.path for g in grants.layers
                    if isinstance(g.effect, Grant) and isinstance(g.region, Subtree) and within(top, g.region.path)
                ]
                if around:
                    out[_existing_directory(min(around, key=lambda p: len(p.parts)), facts)] = None
                elif any(isinstance(g.effect, Grant) and _overlaps(g.region, top) for g in grants.layers):
                    out[_existing_directory(top, facts)] = None
            case Grant():
                if isinstance(layer.region, Subtree) and facts.kind(top) is Kind.DIRECTORY and _plain(top, facts):
                    out[top] = None
                else:
                    out[_existing_directory(top.parent if not isinstance(layer.region, Pattern) else top, facts)] = None
    return list(out)


def _place_policy(grants: PolicyGrants, facts: Facts, view_unavailable: str | None) -> BwrapPlan | CompileError:
    refusals = _check_needs(grants)
    names = expand(grants.stable, grants.root, facts)
    wanted: dict[pathlib.Path, None] = {}
    needing: list[Layer[Region]] = []
    for layer in grants.layers:
        if not _needs_view(layer, grants, names, facts):
            continue
        directories = _view_directories(layer, grants, facts)
        if not directories:
            continue  # a restriction on nothing any grant makes exist
        if pathlib.Path("/") in directories:
            refusals.append(Refusal(layer.origin, "would need a view of / itself"))
            continue
        if view_unavailable is not None:
            refusals.append(Refusal(layer.origin, f"needs a filesystem view, and none can be had: {view_unavailable}"))
            continue
        wanted.update(dict.fromkeys(directories))
        needing.append(layer)

    def bindable(layer: Layer[Region]) -> bool:
        return isinstance(layer.effect, Grant) and isinstance(layer.region, Subtree) and not _needs_view(layer, grants, names, facts)

    def top_of(layer: Layer[Region]) -> pathlib.Path:
        return region_tops(layer.region)[0]

    def held_back(layer: Layer[Region]) -> bool:
        """Bound back over its view: a plain grant nothing needing a view overlaps -- for a whole
        run only what the run does not replace, the stable grants and the kept names."""
        if not bindable(layer) or any(_overlaps(n.region, top_of(layer)) for n in needing):
            return False
        assert isinstance(layer.effect, Grant)
        return layer.effect.stable or grants.lifetime is Lifetime.EXEC or _kept(grants, names, top_of(layer))

    # Nothing nests inside a plain bind: a plain grant with a view inside it, or another grant of a
    # different final state -- a mount, or a skipped one whose name could then be made -- is held
    # in a view instead, its uniform children bound back (``split``). Below a file nothing is, so
    # nothing nests in a bind of one. A new view may enclose others, so this runs to a fixpoint.
    split: set[pathlib.Path] = set()
    while True:
        directories = _merge(list(wanted))
        binds = [top_of(l) for l in grants.layers if bindable(l) and not any(within(top_of(l), d) for d in directories)]
        nested = {
            outer for outer in binds
            if facts.kind(facts.resolve(outer)) is not Kind.FILE
            and (any(inner != outer and within(inner, outer) and state_at(grants, inner) is not state_at(grants, outer)
                     for inner in binds)
                 or any(d != outer and within(d, outer) for d in directories))
        }
        if not nested - set(wanted):
            break
        if view_unavailable is not None:
            for outer in sorted(nested - set(wanted)):
                origin = next(l.origin for l in grants.layers if bindable(l) and top_of(l) == outer)
                refusals.append(Refusal(origin, "holds a grant of another access inside it, so needs a filesystem view, "
                                                f"and none can be had: {view_unavailable}"))
            break
        wanted.update(dict.fromkeys(nested))
        split |= nested
    if refusals:
        return CompileError(tuple(refusals))

    def viewed(path: pathlib.Path) -> bool:
        return any(within(path, d) for d in directories)

    items: list[Placed] = []
    for layer in grants.layers:
        if bindable(layer) and not viewed(top_of(layer)):
            assert isinstance(layer.effect, Grant)
            items.append(Bind(top_of(layer), layer.effect.access))
    for directory in directories:
        # a grant bound back over the view stays in it too: bubblewrap mounts the bind at a name
        # the view must show, and what the view says below it the bind covers
        absorbed = tuple(layer for layer in grants.layers if _overlaps(layer.region, directory))
        writable = any(isinstance(layer.effect, Grant) and layer.effect.access is Access.WRITABLE for layer in absorbed)
        items.append(Served(Serve(directory, absorbed), Access.WRITABLE if writable else Access.READ_ONLY))
        backs: dict[pathlib.Path, None] = {}
        for layer in grants.layers:
            if held_back(layer) and _bindable_back(grants, absorbed, directory, top_of(layer), facts):
                backs[top_of(layer)] = None
        for parent in sorted(split, key=lambda p: len(p.parts)):
            if within(parent, directory):
                for name in facts.children(parent):
                    child = parent / name
                    if _bindable_back(grants, absorbed, directory, child, facts):
                        backs[child] = None
        # its final state, not its own access: a grant around it, applied later, is in the view
        # now; no restriction reaches it, or it would not be uniform
        items.extend(Bind(top, _access(state_at(grants, top))) for top in backs)
    return BwrapPlan(EmptyBase(), tuple(items))


# -- bubblewrap: the host world under redlines -----------------------------------------------------


@dataclass(frozen=True)
class FromHost:
    """The host's own filesystem at *path*: the first layer of a host world's view, standing for
    the base inside the directory the view serves."""

    path: pathlib.Path

    def describe(self) -> str:
        return f"the host's {self.path}"


def _anchored(path: pathlib.Path, names: StableNames, facts: Facts) -> pathlib.Path | None:
    """Where a host world's view of a redline at *path* sits: the innermost directory strictly
    above it that the stability model says nothing replaces (``world.toml``'s ``stable``: by
    default ``$HOME`` and the top-level directories), so that neither the tool nor anything
    outside it moves the view or the name it sits on -- and that is a directory reached without
    a link, since a view's daemon opens its directory and would follow one. Strictly above, since
    a view does not hide the directory it serves. None: no stable directory lies above *path*. A
    redline held by a mount of its own would detach when something outside renamed a file over it
    (MEASURED: ``scripts/probe_bind_semantics.py``, the ``~/.netrc`` case), and the base would
    show through."""
    fit = [a for a in names.above(path) if facts.kind(a) is Kind.DIRECTORY and _plain(a, facts)]
    return max(fit, key=lambda a: len(a.parts), default=None)


def _place_host(grants: HostGrants, facts: Facts, view_unavailable: str | None) -> BwrapPlan | CompileError:
    """A host jail with redlines over it: every redline and lift is held in a view at the
    innermost stable directory above it, writable or read-only base alike (``never-write`` under
    a read-only base says nothing the base does not, and needs no view). In each view's directory
    the children no deciding layer reaches are bound back over it: speed, and a Unix socket, which
    does not connect through a view; a bind back the host replaces from outside detaches, and the
    view decides the name."""
    access = Access.WRITABLE if grants.writable else Access.READ_ONLY
    names = expand(grants.stable, grants.root, facts)
    refusals: list[Refusal] = []
    wanted: dict[pathlib.Path, None] = {}
    # what can decide anything: under a read-only base, never-write says nothing the base does not
    deciding = [
        layer for layer in grants.layers
        if grants.writable or not (isinstance(layer.effect, Restriction) and layer.effect.narrowing is Narrowing.NO_WRITE)
    ]
    for layer in deciding:
        if isinstance(layer.effect, Grant):
            continue  # a lift: held with what it lifts
        assert isinstance(layer.region, Subtree), "a redline is a path and everything below it"
        directory = _anchored(layer.region.path, names, facts)
        if directory is None:
            refusals.append(Refusal(
                layer.origin, f"no stable directory lies above it to hold its view (world.toml: stable = {grants.stable.describe()})",
            ))
        elif view_unavailable is not None:
            refusals.append(Refusal(layer.origin, f"needs a filesystem view, and none can be had: {view_unavailable}"))
        else:
            wanted[directory] = None
    if refusals:
        return CompileError(tuple(refusals))
    items: list[Placed] = []
    for directory in _merge(list(wanted)):
        # every layer that reaches the directory, the ones that decide nothing here included: a
        # view holds what the grants say there, exactly (``certify``)
        absorbed = tuple(layer for layer in grants.layers if _overlaps(layer.region, directory))
        host = Layer(Subtree(directory), Grant(access), FromHost(directory))
        layers = (host, *absorbed)
        items.append(Served(Serve(directory, layers), access))
        for name in facts.children(directory):
            child = directory / name
            if (not any(_overlaps(layer.region, child) for layer in deciding)
                    and _bindable_back(grants, layers, directory, child, facts)):
                items.append(Bind(child, access))
    return BwrapPlan(HostBase(grants.writable), tuple(items))


def place_bubblewrap(grants: Grants, facts: Facts, *, view_unavailable: str | None = None) -> BwrapPlan | CompileError:
    """*grants* as bubblewrap holds them. *view_unavailable*: why no view can be had, when none
    can (this machine cannot serve one, or no run attaches one); a layer that needs one is then
    refused."""
    match grants:
        case HostGrants(writable=writable, layers=()):
            return BwrapPlan(HostBase(writable), ())  # the host's own /, as unix permissions have it
        case HostGrants():
            return _place_host(grants, facts, view_unavailable)
        case PolicyGrants():
            return _place_policy(grants, facts, view_unavailable)


# -- Seatbelt -----------------------------------------------------------------------------------


def _spelled(path: pathlib.Path, facts: Facts, *, follow: bool) -> pathlib.Path:
    """*path* as Seatbelt matches it: the links above it followed, and with *follow* its own too
    (what a run relies on, as it is). Without, a link at the path itself leads to its target's
    real path, which the rule does not name."""
    if follow or path == pathlib.Path("/"):
        return facts.resolve(path)
    return facts.resolve(path.parent) / path.name


def _rules(layers: Sequence[Layer[Region]], facts: Facts, refusals: list[Refusal]) -> list[Rule]:
    out: list[Rule] = []
    for layer in layers:
        follow = isinstance(layer.effect, Grant) and layer.effect.stable
        match layer.region:
            case Subtree(path=p):
                out.append(Rule(SubpathRule(_spelled(p, facts, follow=follow)), layer.effect))
            case Exactly(path=p):
                out.append(Rule(LiteralRule(_spelled(p, facts, follow=follow)), layer.effect))
            case Pattern(location=loc, anchor=anchor):
                below = isinstance(layer.effect, Restriction)
                regex = pattern_regex(loc, anchor, below=below, resolve=lambda p: str(facts.resolve(p)))
                if regex is None or sbpl.regex(regex) is None:
                    refusals.append(Refusal(layer.origin, NOT_ERE))
                else:
                    out.append(Rule(RegexRule(regex), layer.effect))
    return out


def place_seatbelt(grants: Grants, facts: Facts) -> SeatbeltPlan | CompileError:
    """*grants* as Seatbelt rules, in order: it matches names at each access, so every layer is a
    rule, and a pattern outside the dialect Seatbelt shares with Python is refused. A host jail's
    redlines and lifts are rules over the host's base, missing paths included."""
    refusals: list[Refusal] = []
    if isinstance(grants, HostGrants):
        host_rules = _rules(grants.layers, facts, refusals)
        return CompileError(tuple(refusals)) if refusals else SeatbeltPlan(HostBase(grants.writable), tuple(host_rules))
    refusals = _check_needs(grants)
    # a listing: the directory itself, read, and nothing below it
    rules = [Rule(LiteralRule(facts.resolve(p)), Grant(Access.READ_ONLY, stable=True)) for p in grants.listings]
    rules += _rules(grants.layers, facts, refusals)
    if refusals:
        return CompileError(tuple(refusals))
    return SeatbeltPlan(EmptyBase(), tuple(rules))
