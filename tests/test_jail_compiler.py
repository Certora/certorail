"""The jail compiler's pure passes (LOWERING2.md): the front end, Place and Flatten, against a
simulated filesystem -- no bubblewrap, no Seatbelt, no FUSE."""
import pathlib
import random
import unittest

from certorail.childjail import View
from certorail.confinement import Additions, SystemJail
from certorail.locations import parse_location
from certorail.policy import Policy, program
from certorail.sandbox.facts import Kind, Recorded
from certorail.sandbox.front import program_host, program_policy, tool
from certorail.sandbox.grants import (
    Access, Exactly, Grant, HostGrants, Layer, Lifetime, Narrowing, Pattern, PolicyGrants, Process,
    Restriction, State, Subtree, covers, state_at, within,
)
from certorail.sandbox.interpreter import InterpreterWorld, Need, Stdlib
from certorail.sandbox.place import (
    Bind, BwrapPlan, CompileError, EmptyBase, HostBase, LiteralRule, RegexRule, Rule, SeatbeltPlan,
    Serve, Served, SubpathRule, place_bubblewrap, place_seatbelt,
)
from certorail.sandbox.stable import StableNames, expand
from certorail.sandbox.tree import Mount, Own, Through, flatten, state_of
from certorail.world import Floor, Selector, Stable

P = pathlib.Path
PROCESS = Process(network=False, spawn=False, exec_=False)


class Say:
    """An origin for hand-built layers."""

    def __init__(self, text: str) -> None:
        self.text = text

    def describe(self) -> str:
        return self.text


class FakeFS:
    """A filesystem that does not exist: files, directories (every ancestor of anything named is
    one) and symbolic links, each named by its real path. ``kind`` answers as ``lstat`` does: the
    links above a path are followed, a link at it is not."""

    def __init__(self, files: tuple[str, ...] = (), dirs: tuple[str, ...] = (), links: dict[str, str] | None = None) -> None:
        self.links = {P(k): P(v) for k, v in (links or {}).items()}
        self.kinds: dict[P, Kind] = {P("/"): Kind.DIRECTORY}
        for d in dirs:
            self._declare(P(d), Kind.DIRECTORY)
        for f in files:
            self._declare(P(f), Kind.FILE)
        for link in self.links:
            self._declare(link, Kind.SYMLINK)

    def _declare(self, path: P, kind: Kind) -> None:
        for parent in path.parents:
            self.kinds.setdefault(parent, Kind.DIRECTORY)
        self.kinds[path] = kind

    def kind(self, path: pathlib.Path) -> Kind:
        if path == P("/"):
            return Kind.DIRECTORY
        return self.kinds.get(self.resolve(path.parent) / path.name, Kind.MISSING)

    def resolve(self, path: pathlib.Path, depth: int = 0) -> pathlib.Path:
        out = P("/")
        for part in path.parts[1:]:
            out = out / part
            if out in self.links and depth < 40:  # a loop resolves no further, as realpath's does
                out = self.resolve(self.links[out], depth + 1)
        return out

    def children(self, path: pathlib.Path) -> tuple[str, ...]:
        real = self.resolve(path)
        if self.kinds.get(real) is not Kind.DIRECTORY:
            return ()
        return tuple(sorted(p.name for p in self.kinds if p != P("/") and p.parent == real))


def plan(result: BwrapPlan | CompileError) -> BwrapPlan:
    assert isinstance(result, BwrapPlan), [r.describe() for r in result.refusals] if isinstance(result, CompileError) else result
    return result


def refused(result: object) -> list[str]:
    assert isinstance(result, CompileError), result
    return [r.describe() for r in result.refusals]


def grant(path: str, access: Access = Access.READ_ONLY, *, exact: bool = False, stable: bool = False) -> Layer:
    region = Exactly(P(path)) if exact else Subtree(P(path))
    return Layer(region, Grant(access, stable), Say(f"grant {path}"))


def restrict(path: str, narrowing: Narrowing = Narrowing.NO_WRITE, *, sole: bool = True) -> Layer:
    return Layer(Subtree(P(path)), Restriction(narrowing, sole), Say(f"restriction {path}"))


# ---------------------------------------------------------------------------------------------


class TestMeaning(unittest.TestCase):
    def test_a_host_jail_is_its_base(self) -> None:
        self.assertEqual(state_at(HostGrants(False, Lifetime.EXEC, PROCESS), P("/etc")), State.READ_ONLY)
        self.assertEqual(state_at(HostGrants(True, Lifetime.RUN, PROCESS), P("/etc")), State.WRITABLE)

    def test_layers_apply_in_order(self) -> None:
        policy = PolicyGrants((grant("/r", Access.WRITABLE), restrict("/r/keep"), grant("/r/keep/open", Access.WRITABLE)),
                              Lifetime.EXEC, PROCESS, P("/r"))
        self.assertEqual(state_at(policy, P("/r/x")), State.WRITABLE)
        self.assertEqual(state_at(policy, P("/r/keep/x")), State.READ_ONLY)
        self.assertEqual(state_at(policy, P("/r/keep/open/y")), State.WRITABLE)

    def test_patterns_are_part_of_the_meaning(self) -> None:
        # a grant's pattern covers the paths it matches; a restriction's, what lies below them too
        texts = Layer(Pattern(parse_location("notes/<[a-z]+\\.txt>"), P("/r")), Grant(Access.WRITABLE), Say("texts"))
        versions = Layer(Pattern(parse_location("/opt/<v[0-9]+>/**"), P("/")), Grant(Access.READ_ONLY), Say("versions"))
        keep = Layer(Pattern(parse_location("out/<k.*>"), P("/r")), Restriction(Narrowing.NO_WRITE, sole=True), Say("keep"))
        policy = PolicyGrants((grant("/r/out", Access.WRITABLE), texts, versions, keep), Lifetime.EXEC, PROCESS, P("/r"))
        self.assertEqual(state_at(policy, P("/r/notes/a.txt")), State.WRITABLE)
        self.assertEqual(state_at(policy, P("/r/notes/A.txt")), State.ABSENT)
        self.assertEqual(state_at(policy, P("/r/notes/sub/a.txt")), State.ABSENT)
        self.assertEqual(state_at(policy, P("/opt/v12/lib/x")), State.READ_ONLY)
        self.assertEqual(state_at(policy, P("/opt/vx/lib/x")), State.ABSENT)
        self.assertEqual(state_at(policy, P("/r/out/kept/x")), State.READ_ONLY)
        self.assertEqual(state_at(policy, P("/r/out/other/x")), State.WRITABLE)

    def test_a_restriction_never_makes_a_path_exist(self) -> None:
        policy = PolicyGrants((grant("/r/src"), restrict("/r/secret"), restrict("/r/src/key", Narrowing.HIDDEN)),
                              Lifetime.EXEC, PROCESS, P("/r"))
        self.assertEqual(state_at(policy, P("/r/secret")), State.ABSENT)
        self.assertEqual(state_at(policy, P("/r/src/key")), State.HIDDEN)
        self.assertEqual(state_at(policy, P("/r/src/a.py")), State.READ_ONLY)


class TestFlatten(unittest.TestCase):
    def test_a_mount_that_changes_nothing_is_dropped(self) -> None:
        items = (Bind(P("/usr"), Access.READ_ONLY), Bind(P("/usr/bin/cat"), Access.READ_ONLY), Bind(P("/w"), Access.WRITABLE))
        self.assertEqual(flatten(HostBase(False), items), (Mount(P("/w"), State.WRITABLE, Own()),))

    def test_a_bind_under_a_view_is_kept(self) -> None:
        view = Serve(P("/r"), ())
        items = (Served(view, Access.READ_ONLY), Bind(P("/r/src"), Access.READ_ONLY))
        mounts = flatten(EmptyBase(), items)
        self.assertEqual([m.path for m in mounts], [P("/r"), P("/r/src")])
        self.assertEqual(mounts[0].source, Through(view, pathlib.PurePosixPath(".")))
        self.assertEqual(mounts[1].source, Own())

    def test_agrees_with_applying_the_items_in_order(self) -> None:
        # the oracle: every path's state and source, by the items in order, equals what the
        # flattened mounts give it
        paths = [P(p) for p in ("/a", "/a/b", "/a/b/c", "/a/d", "/e", "/e/f")]
        probes = [*paths, P("/a/b/c/z"), P("/a/x"), P("/q")]
        view = Serve(P("/a/b"), ())
        rng = random.Random(20260924)
        for _ in range(400):
            base = rng.choice([HostBase(True), HostBase(False), EmptyBase()])
            items: list = []
            for _ in range(rng.randint(0, 6)):
                if rng.random() < 0.15:
                    items.append(Served(view, rng.choice(list(Access))))
                else:
                    items.append(Bind(rng.choice(paths), rng.choice(list(Access))))
            mounts = flatten(base, items)
            for probe in probes:
                above = [m for m in mounts if probe == m.path or m.path in probe.parents]
                if above:
                    m = max(above, key=lambda m: len(m.path.parts))
                    got = state_of(base, [Bind(m.path, Access.WRITABLE if m.state is State.WRITABLE else Access.READ_ONLY)]
                                   if isinstance(m.source, Own) else [Served(m.source.view, Access.WRITABLE if m.state is State.WRITABLE else Access.READ_ONLY)], probe)
                    if isinstance(m.source, Through):
                        # through a view mounted above its own directory: carried from the mount
                        got = (m.state, Through(m.source.view, m.source.rel / probe.relative_to(m.path)))
                else:
                    got = state_of(base, [], probe)
                self.assertEqual(got, state_of(base, items, probe), (base, items, probe))


class TestHostWorld(unittest.TestCase):
    """The certorail process in host mode, and a tool's host view: the host's ``/``, nothing to place."""

    def test_the_base_alone(self) -> None:
        for writable in (True, False):
            with self.subTest(writable=writable):
                g = HostGrants(writable, Lifetime.EXEC, PROCESS)
                self.assertEqual(plan(place_bubblewrap(g, FakeFS())), BwrapPlan(HostBase(writable), ()))
                self.assertEqual(place_seatbelt(g, FakeFS()), SeatbeltPlan(HostBase(writable), ()))


class TestPolicyWorld(unittest.TestCase):
    FS = FakeFS(dirs=("/r/src", "/r/out", "/usr", "/opt/data/x", "/home/u/elsewhere"), files=("/r/README.md",),
                links={"/r/vendor": "/home/u/elsewhere"})
    TOOLCHAIN = grant("/usr", stable=True)

    def jail(self, *layers: Layer, lifetime: Lifetime = Lifetime.EXEC) -> PolicyGrants:
        return PolicyGrants((self.TOOLCHAIN, *layers), lifetime, PROCESS, P("/r"),
                            workdir=P("/r") if lifetime is Lifetime.RUN else None)

    def test_plain_grants_are_binds_for_one_exec(self) -> None:
        g = self.jail(grant("/r/src"), grant("/r/out", Access.WRITABLE))
        self.assertEqual(plan(place_bubblewrap(g, self.FS)).items,
                         (Bind(P("/usr"), Access.READ_ONLY), Bind(P("/r/src"), Access.READ_ONLY), Bind(P("/r/out"), Access.WRITABLE)))

    def test_what_a_bind_cannot_say_is_held_in_the_root_view(self) -> None:
        for layer in (grant("/r/README.md", exact=True),               # a path named exactly
                      grant("/r/vendor"),                              # a linked top directory
                      grant("/r/new", Access.WRITABLE),                # a write grant not there yet
                      restrict("/r/out/keep")):                        # a protection
            with self.subTest(layer=layer.origin.describe()):
                items = plan(place_bubblewrap(self.jail(grant("/r/src"), grant("/r/out", Access.WRITABLE), layer), self.FS)).items
                views = [i for i in items if isinstance(i, Served)]
                self.assertEqual([v.view.directory for v in views], [P("/r")])
                self.assertIn(layer, views[0].view.layers)

    def test_a_plain_grant_is_bound_back_over_the_view_unless_something_in_it_needs_the_view(self) -> None:
        items = plan(place_bubblewrap(self.jail(grant("/r/src"), grant("/r/out", Access.WRITABLE), restrict("/r/out/keep")), self.FS)).items
        self.assertIn(Bind(P("/r/src"), Access.READ_ONLY), items)          # nothing in it needs the view
        self.assertNotIn(Bind(P("/r/out"), Access.WRITABLE), items)        # the protection does
        served = next(i for i in items if isinstance(i, Served))
        self.assertIs(served.access, Access.WRITABLE)
        self.assertLess(items.index(served), items.index(Bind(P("/r/src"), Access.READ_ONLY)))

    def test_an_absolute_pattern_gets_a_view_of_its_literal_prefix(self) -> None:
        pattern = Layer(Pattern(parse_location("/opt/data/<[a-z]+>/**"), P("/")), Grant(Access.READ_ONLY), Say("pattern"))
        views = plan(place_bubblewrap(self.jail(pattern), self.FS)).views
        self.assertEqual([v.directory for v in views], [P("/opt/data")])

    def test_no_view_on_this_machine_refuses(self) -> None:
        reasons = refused(place_bubblewrap(self.jail(grant("/r/README.md", exact=True)), self.FS, view_unavailable="no view daemon"))
        self.assertIn("no view daemon", reasons[0])

    def test_for_the_whole_run_grants_are_views_but_the_toolchain_is_bound(self) -> None:
        items = plan(place_bubblewrap(self.jail(grant("/r/src"), grant("/r/out", Access.WRITABLE), lifetime=Lifetime.RUN), self.FS)).items
        self.assertEqual(items[0], Bind(P("/usr"), Access.READ_ONLY))
        self.assertEqual([type(i) for i in items], [Bind, Served])

    def test_a_wholly_granted_root_is_bound_for_the_whole_run(self) -> None:
        items = plan(place_bubblewrap(self.jail(grant("/r"), grant("/r", Access.WRITABLE), lifetime=Lifetime.RUN), self.FS)).items
        self.assertEqual(items[1:], (Bind(P("/r"), Access.READ_ONLY), Bind(P("/r"), Access.WRITABLE)))
        self.assertEqual(flatten(EmptyBase(), items)[-1], Mount(P("/r"), State.WRITABLE, Own()))

    # the findings of PLACE_PROOF.md

    def test_a_grant_under_a_link_is_held_in_a_view(self) -> None:
        # lstat follows /r/vendor, so /r/vendor/lib reads as a directory; a bind would show where it leads
        fs = FakeFS(dirs=("/r/src", "/usr", "/home/u/elsewhere/lib"), links={"/r/vendor": "/home/u/elsewhere"})
        self.assertIs(fs.kind(P("/r/vendor/lib")), Kind.DIRECTORY)
        result = plan(place_bubblewrap(self.jail(grant("/r/vendor/lib")), fs))
        self.assertNotIn(Bind(P("/r/vendor/lib"), Access.READ_ONLY), result.items)
        self.assertEqual([v.directory for v in result.views], [P("/r")])

    def test_a_view_never_sits_under_a_link(self) -> None:
        fs = FakeFS(dirs=("/usr", "/opt/real/sub"), links={"/opt/alias": "/opt/real"})
        views = plan(place_bubblewrap(self.jail(grant("/opt/alias/sub/f", exact=True)), fs)).views
        self.assertEqual([v.directory for v in views], [P("/opt")])

    def test_a_restrictions_view_is_checked_like_any_other(self) -> None:
        # the grant around the restriction is stable (no view of its own) and spelled through a link
        fs = FakeFS(dirs=("/usr", "/opt/real/keep"), links={"/opt/alias": "/opt/real"})
        views = plan(place_bubblewrap(self.jail(grant("/opt/alias", stable=True), restrict("/opt/alias/keep")), fs)).views
        self.assertEqual([v.directory for v in views], [P("/opt")])

    def test_a_listing_is_a_need_not_a_grant(self) -> None:
        fs = FakeFS(dirs=("/usr", "/opt/site/certorail", "/r"))
        package = grant("/opt/site/certorail", stable=True)
        g = PolicyGrants((self.TOOLCHAIN, package), Lifetime.RUN, PROCESS, P("/r"), listings=(P("/opt/site"),), workdir=P("/r"))
        self.assertEqual(plan(place_bubblewrap(g, fs)).items,
                         (Bind(P("/usr"), Access.READ_ONLY), Bind(P("/opt/site/certorail"), Access.READ_ONLY)))
        seatbelt = place_seatbelt(g, fs)
        assert isinstance(seatbelt, SeatbeltPlan)
        self.assertEqual(seatbelt.rules[0], Rule(LiteralRule(P("/opt/site")), Grant(Access.READ_ONLY, stable=True)))
        hidden = PolicyGrants((self.TOOLCHAIN, package, restrict("/opt/site", Narrowing.HIDDEN)), Lifetime.RUN, PROCESS, P("/r"),
                              listings=(P("/opt/site"),), workdir=P("/r"))
        self.assertIn("cannot run without", refused(place_bubblewrap(hidden, fs))[0])

    # nothing nests inside a plain bind (measured: a nested mount detaches or moves when the host
    # replaces the name under it, and the bind around it shows through)

    def test_a_grant_inside_another_of_a_different_access_makes_the_outer_a_view(self) -> None:
        fs = FakeFS(dirs=("/usr", "/r/a/b", "/r/a/c", "/r/other"), files=("/r/README",))
        g = PolicyGrants((self.TOOLCHAIN, grant("/r", Access.WRITABLE), grant("/r/a/b")), Lifetime.EXEC, PROCESS, P("/r"))
        result = plan(place_bubblewrap(g, fs))
        self.assertEqual([v.directory for v in result.views], [P("/r")])
        binds = {i.path for i in result.items if isinstance(i, Bind)}
        # the inner grant and the rest of /r bound back over the view; /r/a itself is not uniform
        self.assertEqual(binds, {P("/usr"), P("/r/a/b"), P("/r/other"), P("/r/README")})
        self.assertEqual(built_state(result, P("/r/a/b/x")), State.READ_ONLY)
        self.assertEqual(built_state(result, P("/r/a/c/x")), State.WRITABLE)

    def test_a_missing_read_only_grant_under_a_writable_one_makes_it_a_view(self) -> None:
        # /r/a/.git is read-only and not there: skipped, its bind would leave the name to /r's
        fs = FakeFS(dirs=("/usr", "/r/a/src", "/r/other"), files=("/r/a/README",))
        g = PolicyGrants((self.TOOLCHAIN, grant("/r", Access.WRITABLE), grant("/r/a/.git")), Lifetime.EXEC, PROCESS, P("/r"))
        result = plan(place_bubblewrap(g, fs))
        self.assertEqual([v.directory for v in result.views], [P("/r")])
        self.assertEqual(built_state(result, P("/r/a/.git")), State.READ_ONLY)
        self.assertEqual(built_state(result, P("/r/a/src/x")), State.WRITABLE)

    def test_the_working_directory_inside_a_stable_grant(self) -> None:
        # a view above both binds the stable grant back over it; the working directory's own
        # grant is bound back after it, or the stable grant would shadow it
        fs = FakeFS(dirs=("/opt/py/proj",), files=("/opt/f",))
        layers = (grant("/opt/py", stable=True), grant("/opt/py/proj", Access.WRITABLE), grant("/opt/f", exact=True))
        g = PolicyGrants(layers, Lifetime.RUN, PROCESS, P("/opt/py/proj"), workdir=P("/opt/py/proj"))
        result = plan(place_bubblewrap(g, fs))
        self.assertEqual([v.directory for v in result.views], [P("/opt")])
        self.assertEqual(built_state(result, P("/opt/py/proj")), State.WRITABLE)


class TestSeatbelt(unittest.TestCase):
    FS = FakeFS(dirs=("/private/tmp/w", "/Users/u/elsewhere"), links={"/tmp": "/private/tmp", "/private/tmp/w/link": "/Users/u/elsewhere"})

    def test_every_layer_is_a_rule_and_a_grants_own_link_is_not_followed(self) -> None:
        g = PolicyGrants((grant("/tmp/w/link"), grant("/tmp/w/a.txt", exact=True),
                          Layer(Pattern(parse_location("/tmp/w/<[a-z]+>"), P("/")), Grant(Access.READ_ONLY), Say("pattern"))),
                         Lifetime.EXEC, PROCESS, P("/tmp/w"))
        result = place_seatbelt(g, self.FS)
        assert isinstance(result, SeatbeltPlan)
        self.assertEqual([r.filter for r in result.rules][:2],
                         [SubpathRule(P("/private/tmp/w/link")), LiteralRule(P("/private/tmp/w/a.txt"))])
        self.assertIsInstance(result.rules[2].filter, RegexRule)

    def test_a_pattern_outside_the_shared_dialect_refuses(self) -> None:
        g = PolicyGrants((Layer(Pattern(parse_location("/tmp/<\\d+>"), P("/")), Grant(Access.READ_ONLY), Say("digits")),),
                         Lifetime.EXEC, PROCESS, P("/tmp"))
        self.assertIn("POSIX ERE", refused(place_seatbelt(g, self.FS))[0])


class TestFrontEnd(unittest.TestCase):
    ROOT = P("/home/u/proj")

    def test_host_mode(self) -> None:
        self.assertEqual(program_host(), HostGrants(True, Lifetime.RUN, PROCESS))  # the user's authority

    def test_the_policy_view(self) -> None:
        # out/** is a [system.exec] mount-read and a write grant: every read comes before every
        # write, so it is writable, as the union of the grants says
        policy = Policy.allow(read=["src/**", "README.md"], write=["out/**"], no_write=["out/keep"],
                              system=SystemJail(view=View.POLICY, additions=Additions((parse_location("out/**"),))))
        interpreter = InterpreterWorld(P("/opt/py/bin/python3"), (Need(P("/opt/py"), Stdlib()),), (P("/opt/site"),))
        g = program_policy(policy, Floor(), self.ROOT, interpreter, [P("/usr")])
        kinds = [(type(layer.region).__name__, layer.effect) for layer in g.layers]
        self.assertEqual(kinds[:2], [("Subtree", Grant(Access.READ_ONLY, True))] * 2)
        self.assertEqual(g.listings, (P("/opt/site"),))
        self.assertIn(("Exactly", Grant(Access.READ_ONLY)), kinds)      # README.md
        self.assertEqual(kinds[-1], ("Subtree", Restriction(Narrowing.NO_WRITE, sole=False)))
        self.assertEqual(state_at(g, self.ROOT / "out" / "x"), State.WRITABLE)
        self.assertEqual((g.lifetime, g.workdir, g.needs), (Lifetime.RUN, self.ROOT, (P("/opt/py"),)))

    def test_tools(self) -> None:
        policy = Policy.allow(read=["src/**"], write=["out/**"], no_write=["out/keep"], programs=[
            program("cat", cwd=".", view=View.POLICY, write_fs=False),
            program("tee", cwd=".", view=View.POLICY, mount_read=["out/**"]),
            program("git", cwd="."),
        ])
        cat, tee, git = policy.programs
        self.assertEqual(tool(policy, git, self.ROOT, [P("/usr")]), HostGrants(True, Lifetime.EXEC, Process(True, True, True), (), self.ROOT))
        g = tool(policy, cat, self.ROOT, [P("/usr")])
        assert isinstance(g, PolicyGrants)
        self.assertEqual(g.layers[2].effect, Grant(Access.READ_ONLY))    # a write grant, read-only under write-fs = false
        self.assertEqual(g.layers[-1].effect, Restriction(Narrowing.NO_WRITE, sole=True))  # the jail alone stops a tool
        self.assertEqual(state_at(tool(policy, tee, self.ROOT, [P("/usr")]), self.ROOT / "out" / "x"), State.WRITABLE)


# ---------------------------------------------------------------------------------------------
# fuzzing the policy placer: random filesystems and grants, the plan evaluated as bubblewrap
# would build it, against the meaning (``state_at``) at every path reached without a link


# /a/w/v and /b/v/g name what lies below the links' targets (/b, /a/w): through a link they read
# as what they lead to, as lstat reads them
UNIVERSE = ("/a", "/a/x", "/a/x/y", "/a/x/y/f", "/a/x/z", "/a/w", "/a/w/g", "/a/w/v", "/b", "/b/v", "/b/v/k", "/b/v/g")
# (toolchain, working directory): beside each other, and the one inside the other
LAYOUTS = ((P("/b"), P("/a/x")), (P("/a/x"), P("/a/x/y")))
KNOWN_REFUSALS = ("cannot run without", "a view of / itself", "no stable directory lies above it")


def random_fs(rng: random.Random, toolchain: P, workdir: P) -> FakeFS:
    kinds: dict[P, Kind] = {P("/"): Kind.DIRECTORY}
    for fixed in (toolchain, workdir):
        kinds.update({p: Kind.DIRECTORY for p in (fixed, *fixed.parents)})
    files, dirs, links = [], [], {}
    for text in UNIVERSE:
        path = P(text)
        if kinds.get(path) is Kind.DIRECTORY:
            dirs.append(text)
            continue
        if kinds.get(path.parent) is not Kind.DIRECTORY:
            kinds[path] = Kind.MISSING
            continue
        kind = rng.choices([Kind.DIRECTORY, Kind.FILE, Kind.SYMLINK, Kind.MISSING], [6, 2, 1, 2])[0]
        kinds[path] = kind
        if kind is Kind.DIRECTORY:
            dirs.append(text)
        elif kind is Kind.FILE:
            files.append(text)
        elif kind is Kind.SYMLINK:
            links[text] = "/b" if not text.startswith("/b") else "/a/w"
    return FakeFS(tuple(files), tuple(dirs), links)


# patterns over the universe, some with one literal prefix, some with several ({a,b}): a pattern
# with several is held in a view at each
PATTERNS = (
    "/a/x/<[yz]>", "/a/<[xw]>/**", "/b/v/<.*>",
    "/{a,b}/<[vw]>/**", "/{a,b}/**/<[gk]>", "/a/{x,w}/<[yg]>",
)


def random_layer(rng: random.Random) -> Layer:
    if rng.random() < 0.2:
        text = rng.choice(PATTERNS)
        region = Pattern(parse_location(text), P("/"))
        if rng.random() < 0.5:
            return Layer(region, Grant(rng.choice(list(Access))), Say(f"grant {text}"))
        return Layer(region, Restriction(rng.choice(list(Narrowing)), sole=True), Say(f"restriction {text}"))
    path = rng.choice(UNIVERSE)
    if rng.random() < 0.5:
        return grant(path, rng.choice(list(Access)), exact=rng.random() < 0.3)
    return restrict(path, rng.choice(list(Narrowing)))


def served_state(view: Serve, path: P) -> State:
    """What the view's daemon decides at *path*: the layers it holds, by name, over nothing."""
    return state_at(PolicyGrants(view.layers, Lifetime.RUN, PROCESS, P("/")), path)


def built_state(result: BwrapPlan, path: P) -> State:
    """*path* in the jail bubblewrap builds from *result*: the nearest mount at or above it."""
    mounts = flatten(result.base, result.items)
    above = [m for m in mounts if path == m.path or m.path in path.parents]
    if not above:
        match result.base:
            case HostBase(writable=w):
                return State.WRITABLE if w else State.READ_ONLY
            case EmptyBase():
                return State.ABSENT
    m = max(above, key=lambda m: len(m.path.parts))
    if isinstance(m.source, Own):
        return m.state
    decided = served_state(m.source.view, path)
    if m.state is State.READ_ONLY and decided is State.WRITABLE:
        return State.READ_ONLY  # the view's mountpoint is bound read-only
    return decided


def probes(fs: FakeFS) -> list[P]:
    """The paths that are there and reached without a link: what can be compared."""
    return [P(t) for t in UNIVERSE if fs.kind(P(t)) in (Kind.DIRECTORY, Kind.FILE) and fs.resolve(P(t)) == P(t)]


def _covered(layer: Layer, path: P) -> bool:
    region = layer.region
    if isinstance(region, Subtree):
        return path == region.path or region.path in path.parents
    return isinstance(region, Exactly) and path == region.path


class TestPlacerFuzz(unittest.TestCase):
    CASES = 3000  # clean at 20000, patterns included, 2026-09-29

    def check(self, g: PolicyGrants, fs: FakeFS, toolchain: P, case: str) -> None:
        result = place_bubblewrap(g, fs)
        if isinstance(result, CompileError):
            for r in result.refusals:
                self.assertTrue(any(k in r.reason for k in KNOWN_REFUSALS), f"{case}\nunexpected refusal: {r.describe()}")
            return
        mounts = flatten(result.base, result.items)
        for path in probes(fs):
            self.assertEqual(built_state(result, path), state_at(g, path), f"{case}\nat {path}\nitems: {result.items}\nmounts: {mounts}")
        # held by name: wherever a restriction decides the state, nothing is a bind (where a
        # later grant overrides it, it decides nothing)
        for index, layer in enumerate(g.layers):
            if not isinstance(layer.effect, Restriction):
                continue
            without = PolicyGrants(g.layers[:index] + g.layers[index + 1:], g.lifetime, g.process, g.root, workdir=g.workdir)
            for path in probes(fs):
                if not _covered(layer, path) or state_at(g, path) in (State.ABSENT, state_at(without, path)):
                    continue
                nearest = max((m for m in mounts if path == m.path or m.path in path.parents),
                              key=lambda m: len(m.path.parts), default=None)
                self.assertTrue(nearest is not None and isinstance(nearest.source, Through),
                                f"{case}\n{layer.origin.describe()} at {path} is held by {nearest}")
        # a bind laid over a view is mounted at a name the view shows: bubblewrap cannot make one
        for i, item in enumerate(result.items):
            if not isinstance(item, Bind):
                continue
            for under in result.items[:i]:
                if isinstance(under, Served) and item.path != under.path and within(item.path, under.path):
                    self.assertTrue(any(isinstance(layer.effect, Grant) and covers(layer.region, item.path) for layer in under.view.layers),
                                    f"{case}\n{item} lies over a view that does not show it: {under.view}")
        # links: a bind would show where one leads, and a view's daemon would follow one
        for item in result.items:
            if isinstance(item, Bind) and item.path != toolchain:
                self.assertEqual(fs.resolve(item.path), item.path, f"{case}\na bind through a link: {item}")
        for view in result.views:
            self.assertTrue(fs.kind(view.directory) is Kind.DIRECTORY and fs.resolve(view.directory) == view.directory,
                            f"{case}\na view under a link: {view.directory}")
        # nothing nests inside a plain bind (measured: a mount nested in a bind detaches or moves
        # when the host replaces the name under it, and the bind shows through)
        for m in mounts:
            above = [o for o in mounts if o.path != m.path and within(m.path, o.path)]
            if above:
                parent = max(above, key=lambda o: len(o.path.parts))
                if fs.kind(parent.path) is Kind.FILE:
                    continue  # below a file nothing is: a skipped bind, which bubblewrap never makes
                self.assertIsInstance(parent.source, Through, f"{case}\n{m} is nested in the bind {parent}")
        if g.lifetime is Lifetime.RUN:
            # a whole-run bind on the root: the toolchain, the working directory, or a name the
            # stability model says nothing outside the jail replaces
            kept = expand(g.stable, g.root, fs)
            for m in mounts:
                if isinstance(m.source, Own) and not any(o.path != m.path and within(m.path, o.path) for o in mounts):
                    self.assertTrue(m.path in (toolchain, g.workdir) or kept.fixed(m.path), f"{case}\na whole-run bind on the root: {m}")

    def test_policy_world(self) -> None:
        rng = random.Random(2)
        for i in range(self.CASES):
            toolchain, workdir = rng.choice(LAYOUTS)
            fs = random_fs(rng, toolchain, workdir)
            lifetime = rng.choice(list(Lifetime))
            layers = (grant(str(toolchain), stable=True), *(random_layer(rng) for _ in range(rng.randint(1, 6))))
            g = PolicyGrants(layers, lifetime, PROCESS, workdir, workdir=workdir if lifetime is Lifetime.RUN else None)
            self.check(g, fs, toolchain, f"case {i} ({lifetime}, toolchain {toolchain}): "
                                         f"{[(l.origin.describe(), l.effect) for l in layers]}\nfs: {fs.kinds} {fs.links}")


class TestStability(unittest.TestCase):
    """The stability model against a filesystem (``sandbox.stable``): what each selector names."""

    HOME = P("/home/u")
    FS = FakeFS(files=("/home/u/.netrc", "/home/u/proj/a.rs", "/home/u/.ssh/id"), dirs=("/home/u/.cargo", "/opt"),
                links={"/home/u/.link": "/home/u/.cargo"})

    def expanded(self, *selectors: Selector, paths: tuple[P, ...] = (), root: P | None = P("/home/u/proj")) -> StableNames:
        return expand(Stable.of(*selectors, paths=paths, home_at=self.HOME), root, self.FS)

    def test_the_selectors(self) -> None:
        self.assertEqual(self.expanded(), StableNames(frozenset(), frozenset()))
        self.assertEqual(self.expanded(Selector.TOPS), StableNames(frozenset(), frozenset({P("/")})))
        self.assertEqual(self.expanded(Selector.HOME).names, {self.HOME})
        # the dot directories of home: not its dot files, not a link, not its other directories
        self.assertEqual(self.expanded(Selector.HOME_DOTS).names, {P("/home/u/.ssh"), P("/home/u/.cargo")})
        self.assertEqual(self.expanded(Selector.ROOT).names, {P("/home/u/proj")})
        self.assertEqual(self.expanded(Selector.ROOT, root=None).names, set())  # a jail with no root: nothing
        self.assertEqual(self.expanded(Selector.XDG).names,
                         {P("/home/u/.config"), P("/home/u/.cache"), P("/home/u/.local/share"), P("/home/u/.local/state")})
        self.assertEqual(self.expanded(paths=(P("/srv/data"),)).names, {P("/srv/data")})

    def test_fixed_and_above(self) -> None:
        names = self.expanded(Selector.TOPS, Selector.HOME_DOTS)
        self.assertTrue(names.fixed(P("/opt")))
        self.assertTrue(names.fixed(P("/home/u/.ssh")))
        self.assertFalse(names.fixed(P("/home/u")))
        self.assertFalse(names.fixed(P("/")))
        # strictly above: the innermost is the placer's pick
        self.assertEqual(sorted(names.above(P("/home/u/.ssh/id"))), [P("/home"), P("/home/u/.ssh")])
        self.assertEqual(names.above(P("/home/u/.ssh")), [P("/home")])
        self.assertEqual(names.above(P("/opt")), [])


class TestHostWorldRedlines(unittest.TestCase):
    """A host-view tool under the machine's redlines (REDLINES.md): views at the innermost stable
    directory above each, the rest of its children bound back, whether the base is writable or
    read-only -- a mount on a redline's own name would detach when something outside renamed a
    file over it."""

    HOME = P("/home/u")
    ROOT = P("/home/u/proj")
    FS = FakeFS(files=("/home/u/.netrc", "/home/u/proj/a.rs", "/home/u/.ssh/id"), dirs=("/home/u/.cargo", "/home/u/proj"))
    DEFAULT = Stable.of(Selector.TOPS, Selector.HOME, home_at=HOME)

    def jail(self, writable: bool, floor: Floor, lift_read: tuple[str, ...] = (), stable: Stable = DEFAULT) -> HostGrants:
        rule = program("cargo", cwd=".", write_fs=writable, lift_read=list(lift_read))
        grants = tool(Policy.allow(programs=[rule]), rule, self.ROOT, (), floor, stable)
        assert isinstance(grants, HostGrants)
        return grants

    def test_no_redline_nothing_placed(self) -> None:
        self.assertEqual(plan(place_bubblewrap(self.jail(True, Floor()), self.FS)), BwrapPlan(HostBase(True), ()))

    def test_a_writable_host_holds_its_redlines_in_a_view_at_the_anchor(self) -> None:
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh"),), never_write=(P("/home/u/.missing"),)))
        p = plan(place_bubblewrap(g, self.FS))
        self.assertEqual([i.path for i in p.items if isinstance(i, Served)], [self.HOME])
        # the anchor's other children, bound back over the view: speed, and sockets
        self.assertEqual([i.path for i in p.items if isinstance(i, Bind)], [P("/home/u/.cargo"), P("/home/u/.netrc"), P("/home/u/proj")])
        for path, state in ((P("/home/u/.ssh/id"), State.HIDDEN), (P("/home/u/.missing/x"), State.READ_ONLY),
                            (P("/home/u/proj/a.rs"), State.WRITABLE), (P("/etc/x"), State.WRITABLE)):
            with self.subTest(path=path):
                self.assertEqual(state_at(g, path), state)
                self.assertEqual(built_state(p, path), state)

    def test_a_lift_is_a_grant_after_the_redline(self) -> None:
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh"),)), lift_read=("/home/u/.ssh/known_hosts",))
        p = plan(place_bubblewrap(g, self.FS))
        self.assertEqual(built_state(p, P("/home/u/.ssh/known_hosts")), State.READ_ONLY)
        self.assertEqual(built_state(p, P("/home/u/.ssh/id")), State.HIDDEN)

    def test_a_read_only_host_holds_its_redlines_in_the_same_view(self) -> None:
        g = self.jail(False, Floor.of(never_visible=(P("/home/u/.ssh"), P("/home/u/.netrc"), P("/home/u/.later")),
                                      never_write=(P("/home/u/proj"),)))
        p = plan(place_bubblewrap(g, self.FS))
        self.assertEqual([i.path for i in p.items if isinstance(i, Served)], [self.HOME])
        # never-write says nothing the read-only base does not: proj is bound back
        self.assertEqual([i.path for i in p.items if isinstance(i, Bind)], [P("/home/u/.cargo"), P("/home/u/proj")])
        for path in (P("/home/u/.ssh/id"), P("/home/u/.netrc"), P("/home/u/.later/x")):
            self.assertEqual(built_state(p, path), State.HIDDEN)
        self.assertEqual(built_state(p, P("/home/u/proj/a.rs")), State.READ_ONLY)

    def test_a_top_level_redline_has_no_stable_directory_above_it(self) -> None:
        g = self.jail(True, Floor.of(never_write=(P("/opt"),)))
        self.assertEqual(refused(place_bubblewrap(g, FakeFS(dirs=("/opt",)))), [
            "this machine's never-write /opt: no stable directory lies above it to hold its view (world.toml: stable = home, tops)",
        ])

    def test_home_dots_anchor_a_redline_in_its_own_dot_directory(self) -> None:
        stable = Stable.of(Selector.TOPS, Selector.HOME, Selector.HOME_DOTS, home_at=self.HOME)
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh/id"),)), stable=stable)
        p = plan(place_bubblewrap(g, self.FS))
        # the view is of .ssh alone: home and the project are the host's own
        self.assertEqual([i.path for i in p.items if isinstance(i, Served)], [P("/home/u/.ssh")])
        self.assertEqual([i.path for i in p.items if isinstance(i, Bind)], [])
        self.assertEqual(built_state(p, P("/home/u/.ssh/id")), State.HIDDEN)
        # a redline directly in home still needs home's view, and .ssh's merges into it
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh/id"), P("/home/u/.netrc"))), stable=stable)
        p = plan(place_bubblewrap(g, self.FS))
        self.assertEqual([i.path for i in p.items if isinstance(i, Served)], [self.HOME])
        self.assertEqual([i.path for i in p.items if isinstance(i, Bind)], [P("/home/u/.cargo"), P("/home/u/proj")])

    def test_the_root_selector_anchors_at_the_sandbox_root(self) -> None:
        g = self.jail(True, Floor.of(never_write=(P("/home/u/proj/secrets"),)), stable=Stable.of(Selector.ROOT, home_at=self.HOME))
        p = plan(place_bubblewrap(g, self.FS))
        self.assertEqual([i.path for i in p.items if isinstance(i, Served)], [self.ROOT])
        self.assertEqual([i.path for i in p.items if isinstance(i, Bind)], [P("/home/u/proj/a.rs")])
        self.assertEqual(built_state(p, P("/home/u/proj/secrets/k")), State.READ_ONLY)

    def test_nothing_stable_holds_no_redline(self) -> None:
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh"),)), stable=Stable.nothing())
        self.assertEqual(refused(place_bubblewrap(g, self.FS)), [
            "this machine's never-visible /home/u/.ssh: no stable directory lies above it to hold its view (world.toml: stable = nothing)",
        ])

    def test_a_stable_directory_reached_through_a_link_holds_no_view(self) -> None:
        fs = FakeFS(files=("/home/u/.ssh/id",), links={"/home/u/.ssh": "/home/u/real"})
        stable = Stable.of(Selector.TOPS, Selector.HOME, paths=(P("/home/u/.ssh"),), home_at=self.HOME)
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh/id"),)), stable=stable)
        # the view's daemon would follow the link: the next stable directory up holds it
        self.assertEqual([i.path for i in plan(place_bubblewrap(g, fs)).items if isinstance(i, Served)], [self.HOME])

    def test_seatbelt_holds_them_by_name(self) -> None:
        g = self.jail(True, Floor.of(never_visible=(P("/home/u/.ssh"),)), lift_read=("/home/u/.ssh/known_hosts",))
        result = place_seatbelt(g, self.FS)
        assert isinstance(result, SeatbeltPlan)
        self.assertEqual(result.base, HostBase(True))
        self.assertEqual([r.filter for r in result.rules], [SubpathRule(P("/home/u/.ssh")), LiteralRule(P("/home/u/.ssh/known_hosts"))])

    def test_host_world_fuzz(self) -> None:
        rng = random.Random(3)
        anchor = P("/a/x")
        stable = Stable.of(Selector.TOPS, paths=(anchor,), home_at=P("/nohome"))
        for i in range(1000):
            fs = random_fs(rng, P("/b"), anchor)
            writable = rng.random() < 0.5
            redlines = [restrict(rng.choice(UNIVERSE), rng.choice(list(Narrowing))) for _ in range(rng.randint(1, 3))]
            lifts = []
            for _ in range(rng.randint(0, 2)):
                r = rng.choice(redlines)
                inside = [t for t in UNIVERSE if within(P(t), r.region.path)]
                access = Access.WRITABLE if writable and rng.random() < 0.5 else Access.READ_ONLY
                lifts.append(grant(rng.choice(inside), access, exact=rng.random() < 0.5))
            g = HostGrants(writable, Lifetime.EXEC, PROCESS, (*redlines, *lifts), P("/a"), stable)
            case = f"case {i} (writable {writable}): {[(l.origin.describe(), l.effect) for l in g.layers]}\nfs: {fs.kinds} {fs.links}"
            result = place_bubblewrap(g, fs)
            if isinstance(result, CompileError):
                for r in result.refusals:
                    self.assertIn("no stable directory lies above it", r.reason, case)
                continue
            for path in probes(fs):
                self.assertEqual(built_state(result, path), state_at(g, path), f"{case}\nat {path}\nitems: {result.items}")
            if writable:
                # held by name: wherever a redline decides, a view does, which the tool cannot move
                for layer in redlines:
                    for path in probes(fs):
                        if _covered(layer, path) and state_at(g, path) is not State.WRITABLE:
                            mounts = flatten(result.base, result.items)
                            nearest = max((m for m in mounts if path == m.path or m.path in path.parents), key=lambda m: len(m.path.parts))
                            self.assertIsInstance(nearest.source, Through, f"{case}\n{layer.origin.describe()} at {path}")


class TestFacts(unittest.TestCase):
    def test_a_recipe_knows_what_it_was_compiled_against(self) -> None:
        before = Recorded(FakeFS(dirs=("/r/out",)))
        place_bubblewrap(PolicyGrants((grant("/r/out"),), Lifetime.EXEC, PROCESS, P("/r")), before)
        now = FakeFS(links={"/r/out": "/etc"})
        self.assertEqual([c.describe() for c in before.changed(now)],
                         ["/r/out was a directory when the jail was compiled and is a symbolic link now",
                          "/r/out resolved to /r/out when the jail was compiled and resolves to /etc now"])


if __name__ == "__main__":
    unittest.main()
