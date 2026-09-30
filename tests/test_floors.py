"""The certorail process at run time: ``[system]`` in the root policy, this machine's
``world.toml``, the load-time checks between them, and the jail they lower to -- end to end where
bubblewrap is at hand."""
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from certorail.childjail import View
from certorail.confinement import Additions, Lifts, SystemJail
from certorail.lint import lint
from certorail.locations import parse_location
from certorail.policy import Policy, program
from certorail.policyfile import PolicyFileError, from_data
from certorail.sandbox import Backend, Compiled, compile_jail
from certorail.sandbox.emit import Link, bwrap_command, seatbelt_profile
from certorail.sandbox.facts import Disk
from certorail.sandbox.front import program_policy
from certorail.sandbox.interpreter import InterpreterWorld, Need, Package, Stdlib
from certorail.sandbox.place import BwrapPlan, SeatbeltPlan
from certorail.schema import SchemaError, parse_policy, parse_ruleset
from certorail.world import Floor, FloorConflict, Redline, Selector, Stable, World, WorldFileError, floor_findings, home, load_world

HEAD = "policy-version = 1\nbase = false\n"


class TestSystemTable(unittest.TestCase):
    def test_the_defaults(self) -> None:
        policy = from_data(parse_toml(HEAD))
        self.assertEqual(policy.system, SystemJail(View.HOST))

    def test_the_view(self) -> None:
        policy = from_data(parse_toml(HEAD + '[system.exec]\nview = "policy"\nmount-read = "/srv/fixtures/**"\n'))
        self.assertEqual(policy.system.view, View.POLICY)
        self.assertEqual(policy.system.additions, Additions((parse_location("/srv/fixtures/**"),)))

    def test_the_programs_lifts_need_no_view(self) -> None:
        policy = from_data(parse_toml(HEAD + '[system.exec]\nlift-read = "/srv/keys/known"\n'))
        self.assertEqual(policy.system.lifts, Lifts((parse_location("/srv/keys/known"),)))

    def test_what_the_table_refuses(self) -> None:
        for text, message in (
            ('[system]\nwrite-floor = "none"\n', "unknown key 'write-floor'"),
            ('[system.exec]\nmount-read = "/srv/**"\n', 'need view = "policy"'),
            ('[system.exec]\nview = "policy"\nenv = ["PATH"]\n', "unknown key 'env'"),
            ('[system.exec]\nview = "policy"\nspawn = false\n', "unknown key 'spawn'"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(SchemaError) as caught:
                    parse_policy(parse_toml(HEAD + text))
                self.assertIn(message, str(caught.exception))

    def test_a_ruleset_has_no_system_table(self) -> None:
        with self.assertRaises(SchemaError) as caught:
            parse_ruleset(parse_toml('ruleset-version = 1\n[system.exec]\nview = "policy"\n'), "r.toml")
        self.assertIn("unknown key 'system'", str(caught.exception))

    def test_an_absolute_mount_needs_a_literal_head(self) -> None:
        with self.assertRaises(PolicyFileError):
            from_data(parse_toml(HEAD + '[system.exec]\nview = "policy"\nmount-read = "/<x.*>/y"\n'))


def parse_toml(text: str) -> dict:
    import tomllib

    return tomllib.loads(text)


class TestWorldFile(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def load(self, text: str) -> World:
        (self.dir / "world.toml").write_text(text)
        return load_world(self.dir / "world.toml")

    def test_no_file_is_an_empty_world(self) -> None:
        self.assertEqual(load_world(self.dir / "world.toml"), World())

    def test_paths_are_expanded_and_resolved(self) -> None:
        (self.dir / "real").mkdir()
        (self.dir / "link").symlink_to(self.dir / "real")
        world = self.load(f'[system.floor]\nnever-write = ["{self.dir}/link", "~/.ssh"]\n[system.interpreter]\nread = "/nix/store"\n')
        self.assertEqual(world.floor.write_paths, (
            pathlib.Path(os.path.realpath(self.dir / "real")), pathlib.Path(os.path.realpath(os.path.expanduser("~/.ssh"))),
        ))
        self.assertEqual(world.interpreter_read, (pathlib.Path(os.path.realpath("/nix/store")),))
        self.assertEqual(world.source, self.dir / "world.toml")

    def test_the_view_daemon_caches_unless_told_not_to(self) -> None:
        self.assertFalse(self.load("").view_strict)
        self.assertFalse(self.load('view-daemon = "cached"\n').view_strict)
        self.assertTrue(self.load('view-daemon = "strict"\n').view_strict)
        with self.assertRaises(WorldFileError):
            self.load('view-daemon = "fast"\n')

    def test_the_stability_model(self) -> None:
        self.assertEqual(self.load("").stable, Stable.of(Selector.TOPS, Selector.HOME))  # today's judgment
        self.assertEqual(self.load('stable = ["home-dots", "root", "~/work", "/srv"]\n').stable,
                         Stable.of(Selector.HOME_DOTS, Selector.ROOT, paths=(home() / "work", pathlib.Path(os.path.realpath("/srv")))))
        self.assertEqual(self.load('stable = "nothing"\n').stable, Stable.nothing())
        self.assertEqual(self.load('stable = "xdg"\n').stable.describe(), "xdg")
        self.assertEqual(Stable.nothing().describe(), "nothing")
        for text, message in (
            ('stable = ["nothing", "home"]\n', "stands alone"),
            ('stable = ["relative/path"]\n', "absolute path"),
            ('stable = ["everywhere"]\n', "expected one of nothing, tops, home, home-dots, root, xdg"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(WorldFileError) as caught:
                    self.load(text)
                self.assertIn(message, str(caught.exception))

    def test_a_redline_is_a_path_or_a_table(self) -> None:
        world = self.load('[system.floor]\nnever-visible = ["/srv/a", { path = "/srv/b", can-override = false }]\n')
        self.assertEqual(world.floor.never_visible, (
            Redline(pathlib.Path(os.path.realpath("/srv/a"))), Redline(pathlib.Path(os.path.realpath("/srv/b")), can_override=False),
        ))

    def test_what_the_file_refuses(self) -> None:
        for text, message in (
            ('[system.floor]\nnever-write = ["relative/path"]\n', "absolute path"),
            ("[floor]\nnever-write = []\n", "unknown key"),
            ('[system.floor]\nread-only = ["~"]\n', "unknown key 'read-only'"),
            ('[system.floor]\nnever-write = [{ path = "/srv", lift = true }]\n', "unknown key 'lift'"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(WorldFileError) as caught:
                    self.load(text)
                self.assertIn(message, str(caught.exception))


class TestFloorFindings(unittest.TestCase):
    """The policy against this machine's floor: a grant the floor subsumes does not load, a grant
    it overlaps is a lint."""

    ROOT = pathlib.Path("/home/u/proj")

    def test_subsumed_and_overlapping(self) -> None:
        policy = Policy.allow(read=["**", "notes/**", "/home/u/.ssh/known_hosts"], write=["out/**"])
        world = World(Floor.of(
            never_write=(pathlib.Path("/home/u/proj/out"),),
            never_visible=(pathlib.Path("/home/u/.ssh"), pathlib.Path("/home/u/proj/notes")),
        ))
        conflicts, overlaps = floor_findings(policy, world, self.ROOT)
        subsumed = [c for c in conflicts if isinstance(c, FloorConflict)]
        self.assertEqual(len(subsumed), len(conflicts))  # nothing lifts here, so no lift is wrong
        self.assertEqual(
            sorted((c.kind, str(c.path)) for c in subsumed),
            [("read", "/home/u/.ssh"), ("read", "/home/u/proj/notes"), ("write", "/home/u/proj/out")],
        )
        self.assertEqual(sorted((o.kind, str(o.path)) for o in overlaps), [("read", "/home/u/proj/notes")])  # ** reaches in

    def test_the_overlap_is_a_lint(self) -> None:
        world = World(Floor.of(never_write=(self.ROOT / "out",)))
        kinds = [f.kind for f in lint(Policy.allow(write=["**"]), self.ROOT, world=world)]
        self.assertEqual(kinds, ["floor-overlap"])

    def test_a_lift_makes_a_subsumed_grant_usable(self) -> None:
        world = World(Floor.of(never_visible=(pathlib.Path("/home/u/.ssh"),)))
        lifted = SystemJail(lifts=Lifts(read=(parse_location("/home/u/.ssh/known_hosts"),)))
        policy = Policy.allow(read=["/home/u/.ssh/known_hosts"], system=lifted)
        self.assertEqual(floor_findings(policy, world, self.ROOT)[0], [])

    def test_a_lift_lifts_a_redline_or_nothing_loads(self) -> None:
        world = World(Floor(never_visible=(Redline(pathlib.Path("/home/u/.ssh")), Redline(pathlib.Path("/home/u/.gnupg"), can_override=False))))

        def problems(*lifts: str) -> list[str]:
            rule = program("git", cwd=".", lift_read=list(lifts))
            return [c.line() for c in floor_findings(Policy.allow(programs=[rule]), world, self.ROOT)[0]]

        self.assertEqual(problems("/home/u/.ssh/known_hosts"), [])
        (nothing,) = problems("/home/u/.cache/x")
        self.assertIn("lies in no never-visible redline", nothing)
        (absolute,) = problems("/home/u/.gnupg/pubring.kbx")
        self.assertIn("can-override = false", absolute)
        (wide,) = problems("/home/u/**")  # reaches the absolute one, though it lies in no redline either
        self.assertIn("lifts nothing", wide)

    def test_a_tools_mount_the_floor_subsumes_is_refused_unless_lifted(self) -> None:
        world = World(Floor.of(never_visible=(pathlib.Path("/home/u/.ssh"),)))
        mounted = program("git", cwd=".", view=View.POLICY, mount_read=["/home/u/.ssh/**"])
        (refused,) = floor_findings(Policy.allow(programs=[mounted]), world, self.ROOT)[0]
        self.assertIn("'git': the mount-read grant", refused.line())
        lifted = program("git", cwd=".", view=View.POLICY, mount_read=["/home/u/.ssh/**"], lift_read=["/home/u/.ssh/**"])
        self.assertEqual(floor_findings(Policy.allow(programs=[lifted]), world, self.ROOT)[0], [])


class TestLoading(unittest.TestCase):
    def test_a_policy_the_floor_makes_useless_does_not_load(self) -> None:
        from certorail.host import load_policy

        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(os.path.realpath(tmp))
            config, root = base / "config", base / "root"
            (root / "notes").mkdir(parents=True)
            config.mkdir()
            (config / "world.toml").write_text(f'[system.floor]\nnever-visible = ["{root}/notes"]\n')
            policy = base / "policy.toml"
            policy.write_text(HEAD + '[filesystem]\nread = ["notes/**"]\n')
            with mock.patch.dict(os.environ, {"CERTORAIL_CONFIG_DIR": str(config)}):
                with self.assertRaises(SystemExit) as caught:
                    load_policy(policy, root)
                self.assertIn("never-visible", str(caught.exception.code))
                policy.write_text(HEAD + '[filesystem]\nread = ["**"]\n')
                loaded = load_policy(policy, root)  # an overlap loads; the floor carves at run time
                self.assertEqual(loaded.world.floor.visible_paths, (root / "notes",))


def fake_interpreter(prefix: pathlib.Path, package: pathlib.Path) -> InterpreterWorld:
    return InterpreterWorld(prefix / "bin" / "python3", (Need(prefix, Stdlib()), Need(package, Package("certorail"))), (package.parent,))


class TestPolicyViewJail(unittest.TestCase):
    """``[system.exec] view = "policy"``: the program's jail, compiled and written as a tool's is,
    for the whole run."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = pathlib.Path(os.path.realpath(tmp.name))
        self.root = base / "root"
        for d in ("src", "out"):
            (self.root / d).mkdir(parents=True)
        self.interpreter = fake_interpreter(base / "python", base / "site" / "certorail")
        self.policy = Policy.allow(read=["src/**", "out/**"], write=["out/**"], system=SystemJail(view=View.POLICY))

    def compiled(self, backend: Backend, floor: Floor = Floor()) -> Compiled:
        grants = program_policy(self.policy, floor, self.root, self.interpreter, ())
        compiled = compile_jail(grants, backend, Disk(), view_unavailable=None)
        assert isinstance(compiled, Compiled), compiled
        return compiled

    def test_bubblewrap(self) -> None:
        compiled = self.compiled(Backend.BUBBLEWRAP)
        assert isinstance(compiled.plan, BwrapPlan)
        # for the whole run the grants are held in a view of the root, the interpreter's world bound
        mountpoints = {view: pathlib.Path("/views/v") for view in compiled.views}
        self.assertEqual([v.directory for v in compiled.views], [self.root])
        argv = bwrap_command(compiled.plan, compiled.grants.process, Link(self.root, self.interpreter.executable), mountpoints,
                             bwrap="/usr/bin/bwrap")
        text = " ".join(argv)
        self.assertNotIn("--ro-bind / /", text)                       # an empty world, not the host's
        self.assertIn(f"--bind /views/v {self.root}", text)
        self.assertIn(f"--ro-bind-try {self.interpreter.needs[0].path}", text)  # the interpreter's world
        self.assertLess(text.index("--remount-ro /"), text.index("--unshare-net"))

    def test_a_floor_path_that_does_not_exist_is_held_by_name(self) -> None:
        # under a write grant, the view holds it: nothing may create it
        floor = Floor.of(never_write=(self.root / "out" / "later",), never_visible=(self.root / "nope",))
        compiled = self.compiled(Backend.BUBBLEWRAP, floor)
        (view,) = compiled.views
        self.assertIn("this machine's never-write " + str(self.root / "out" / "later"), [layer.origin.describe() for layer in view.layers])
        self.assertIsInstance(self.compiled(Backend.SEATBELT, floor).plan, SeatbeltPlan)

    def test_seatbelt(self) -> None:
        compiled = self.compiled(Backend.SEATBELT)
        assert isinstance(compiled.plan, SeatbeltPlan)
        profile = seatbelt_profile(compiled.plan, compiled.grants.process, Link(self.root, self.interpreter.executable))
        self.assertIn("(deny file-read-data file-write*)", profile)
        self.assertIn(f'(allow file-read-data (literal "{self.interpreter.listed[0]}"))', profile)
        self.assertTrue(profile.rstrip().endswith("(deny process-exec*)"))


BWRAP = sys.platform == "linux" and shutil.which("bwrap") is not None


@unittest.skipUnless(BWRAP, "the end-to-end jail here is bubblewrap's")
class TestEndToEnd(unittest.TestCase):
    """Accepted programs, and the runtime layers that make them fail mid-run by name resolution."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = pathlib.Path(os.path.realpath(tmp.name))
        self.root = base / "root"
        for d in ("src", "out/keep"):
            (self.root / d).mkdir(parents=True)
        (self.root / "src" / "main.txt").write_text("original\n")
        (self.root / "out" / "link").symlink_to(self.root / "src" / "main.txt")
        self.outside = base / "outside.txt"
        self.outside.write_text("outside every grant\n")
        (self.root / "src" / "link-out").symlink_to(self.outside)

    def run_program(self, source: str, system: SystemJail, world: World = World()) -> int:
        from certorail.host import run

        policy = Policy.allow(read=["src/**", "out/**"], write=["out/**"], system=system)
        done = run(source, "p.py", policy, self.root, world=world)
        assert not isinstance(done, (type(None),)) and hasattr(done, "returncode"), done
        return done.returncode  # type: ignore[union-attr]

    def test_a_write_through_a_link_out_of_the_write_grants(self) -> None:
        # the analysis sees out/link, under out/**; it leads to src/main.txt
        main, source = self.root / "src" / "main.txt", 'open("out/link", "w").write("changed\\n")\n'
        # the policy view: only what the policy grants, so not src/main.txt
        self.assertNotEqual(self.run_program(source, SystemJail(view=View.POLICY)), 0)
        self.assertEqual(main.read_text(), "original\n")
        # a redline where it leads
        self.assertNotEqual(self.run_program(source, SystemJail(), World(Floor.of(never_write=(self.root / "src",)))), 0)
        self.assertEqual(main.read_text(), "original\n")
        # host mode, nothing else said: the granted name is followed wherever it leads
        self.assertEqual(self.run_program(source, SystemJail()), 0)
        self.assertEqual(main.read_text(), "changed\n")

    def test_a_read_through_a_link_out_of_the_read_grants(self) -> None:
        source = 'print(open("src/link-out").read())\n'
        self.assertEqual(self.run_program(source, SystemJail()), 0)                     # host view: the name is granted
        self.assertNotEqual(self.run_program(source, SystemJail(view=View.POLICY)), 0)  # policy view: not in its world
        # unless the machine hides where the link leads
        self.assertNotEqual(self.run_program(source, SystemJail(), World(Floor.of(never_visible=(self.outside,)))), 0)

    def test_the_floor_stops_a_direct_write(self) -> None:
        source = 'open("out/keep/x.txt", "w").write("x\\n")\n'
        world = World(Floor.of(never_write=(self.root / "out" / "keep",)))
        self.assertNotEqual(self.run_program(source, SystemJail(), world), 0)
        self.assertFalse((self.root / "out" / "keep" / "x.txt").exists())

    def test_a_floor_path_that_does_not_exist_yet_is_held_by_name(self) -> None:
        world = World(Floor.of(never_write=(self.root / "out" / "later.txt",)))
        self.assertEqual(self.run_program('print("hello")\n', SystemJail(), world), 0)
        self.assertNotEqual(self.run_program('open("out/later.txt", "w").write("x\\n")\n', SystemJail(), world), 0)
        self.assertFalse((self.root / "out" / "later.txt").exists())


if __name__ == "__main__":
    unittest.main()
