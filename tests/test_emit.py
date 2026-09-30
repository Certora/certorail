"""The emitters (LOWERING2.md, "The passes"): a placed jail, linked with one spawn's working
directory, executable and scratch directory, as bubblewrap's command line and as a Seatbelt
profile. Pure: nothing here runs bubblewrap or Seatbelt."""
import pathlib
import unittest

from certorail.sandbox.emit import Link, bwrap_command, seatbelt_profile
from certorail.sandbox.grants import Access, Grant, Narrowing, Process, Restriction
from certorail.sandbox.place import (
    Bind, BwrapPlan, EmptyBase, HostBase, LiteralRule, Placed, RegexRule, Rule, SeatbeltPlan, Serve, Served, SubpathRule,
)

P = pathlib.Path
BWRAP = "/usr/bin/bwrap"
PROGRAM = Process(network=False, spawn=False, exec_=False)   # the certorail process
TOOL = Process(network=False, spawn=False, exec_=True)
OPEN = Process(network=True, spawn=True, exec_=True)


class TestBubblewrapHost(unittest.TestCase):
    """The host's ``/``: nothing linked into it but a scratch directory over a read-only one."""

    def test_a_writable_tool_gets_the_host_as_it_is(self) -> None:
        argv = bwrap_command(BwrapPlan(HostBase(True), ()), OPEN, Link(P("/r"), P("/usr/bin/git")), {}, bwrap=BWRAP)
        self.assertEqual(argv, [BWRAP, "--die-with-parent", "--dev-bind", "/", "/", "--"])

    def test_the_certorail_process_gets_a_fresh_dev(self) -> None:
        argv = bwrap_command(BwrapPlan(HostBase(True), ()), PROGRAM, Link(P("/r")), {}, bwrap=BWRAP)
        self.assertEqual(argv, [BWRAP, "--die-with-parent", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                                "--unshare-net", "--"])

    def test_a_read_only_tool_writes_its_scratch_directory_alone(self) -> None:
        # the executable is the host's already: no bind of it
        link = Link(P("/r"), P("/opt/tool/bin/t"), P("/tmp/s"))
        argv = bwrap_command(BwrapPlan(HostBase(False), ()), TOOL, link, {}, bwrap=BWRAP, seccomp=5)
        self.assertEqual(argv, [
            BWRAP, "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--bind-try", "/tmp/s", "/tmp/s", "--unshare-net", "--seccomp", "5", "--",
        ])

    def test_a_process_that_may_create_processes_gets_no_fork_denial(self) -> None:
        with self.assertRaises(AssertionError):
            bwrap_command(BwrapPlan(HostBase(True), ()), OPEN, Link(P("/r")), {}, bwrap=BWRAP, seccomp=5)


class TestBubblewrapPolicy(unittest.TestCase):
    """The policy world: an empty root, the mounts ancestors first, the root read-only last."""

    PREFIX = [BWRAP, "--die-with-parent", "--dev", "/dev", "--proc", "/proc", "--dir", "/r", "--chdir", "/r"]
    SUFFIX = ["--remount-ro", "/", "--unshare-net", "--"]

    def mounts(self, *items: Placed, link: Link | None = None, mountpoints: dict[Serve, P] | None = None) -> list[str]:
        argv = bwrap_command(BwrapPlan(EmptyBase(), items), TOOL, link or Link(P("/r")), mountpoints or {}, bwrap=BWRAP)
        self.assertEqual(argv[:len(self.PREFIX)], self.PREFIX)
        self.assertEqual(argv[-len(self.SUFFIX):], self.SUFFIX)
        return argv[len(self.PREFIX):-len(self.SUFFIX)]

    def test_the_plan_and_the_spawns_own_ancestors_first(self) -> None:
        got = self.mounts(Bind(P("/usr"), Access.READ_ONLY), Bind(P("/r/src"), Access.READ_ONLY), Bind(P("/r/out"), Access.WRITABLE),
                          link=Link(P("/r"), P("/opt/tool/bin/t"), P("/tmp/s")))
        self.assertEqual(got, [
            "--ro-bind-try", "/usr", "/usr", "--ro-bind-try", "/r/src", "/r/src", "--bind-try", "/r/out", "/r/out",
            "--bind-try", "/tmp/s", "/tmp/s", "--ro-bind-try", "/opt/tool/bin/t", "/opt/tool/bin/t",
        ])

    def test_the_layers_decide_an_executable_they_cover(self) -> None:
        # the toolchain holds it already; a write grant around it keeps it writable
        toolchain = Bind(P("/usr"), Access.READ_ONLY)
        self.assertEqual(self.mounts(toolchain, link=Link(P("/r"), P("/usr/bin/cat"))), ["--ro-bind-try", "/usr", "/usr"])
        self.assertEqual(self.mounts(Bind(P("/r"), Access.WRITABLE), link=Link(P("/r"), P("/r/bin/run"))),
                         ["--bind-try", "/r", "/r"])

    def test_a_view_shows_an_executable_or_not(self) -> None:
        view = Serve(P("/r"), ())
        got = self.mounts(Served(view, Access.READ_ONLY), link=Link(P("/r"), P("/r/gradlew")), mountpoints={view: P("/run/v0")})
        self.assertEqual(got, ["--ro-bind", "/run/v0", "/r"])

    def test_the_scratch_directory_stays_writable_under_a_read_only_grant(self) -> None:
        got = self.mounts(Bind(P("/tmp"), Access.READ_ONLY), link=Link(P("/r"), scratch=P("/tmp/s")))
        self.assertEqual(got, ["--ro-bind-try", "/tmp", "/tmp", "--bind-try", "/tmp/s", "/tmp/s"])

    def test_a_view_is_bound_from_its_mountpoint_and_a_bind_laid_back_over_it(self) -> None:
        view = Serve(P("/r"), ())
        got = self.mounts(Bind(P("/usr"), Access.READ_ONLY), Served(view, Access.WRITABLE), Bind(P("/r/src"), Access.READ_ONLY),
                          mountpoints={view: P("/run/v0")})
        self.assertEqual(got, ["--ro-bind-try", "/usr", "/usr", "--bind", "/run/v0", "/r", "--ro-bind-try", "/r/src", "/r/src"])


class TestSeatbelt(unittest.TestCase):
    def test_the_certorail_process_in_host_mode(self) -> None:
        profile = seatbelt_profile(SeatbeltPlan(HostBase(True), ()), PROGRAM, Link(P("/r")))
        self.assertEqual(profile.splitlines(),
                         ["(version 1)", "(allow default)", "(deny network*)", "(deny process-fork)", "(deny process-exec*)"])

    def test_a_read_only_tool_writes_its_scratch_directory_alone(self) -> None:
        profile = seatbelt_profile(SeatbeltPlan(HostBase(False), ()), TOOL, Link(P("/r"), P("/usr/bin/git"), P("/private/tmp/s")))
        self.assertEqual(profile.splitlines(), [
            "(version 1)", "(allow default)", "(deny file-write*)",
            '(allow file-write* (subpath "/private/tmp/s") (literal "/dev/null"))',
            "(deny network*)", "(deny process-fork)",
        ])

    def test_the_policy_world(self) -> None:
        # the executable under the rules (a later restriction would narrow it), the scratch
        # directory and the entries of / over them
        rules = (
            Rule(SubpathRule(P("/usr")), Grant(Access.READ_ONLY, stable=True)),
            Rule(SubpathRule(P("/r")), Grant(Access.WRITABLE)),
            Rule(LiteralRule(P("/r/README.md")), Grant(Access.READ_ONLY)),
            Rule(RegexRule("^/r/keep(/.*)?$"), Restriction(Narrowing.NO_WRITE, sole=True)),
            Rule(SubpathRule(P("/r/secret")), Restriction(Narrowing.HIDDEN, sole=True)),
        )
        link = Link(P("/r"), P("/opt/t/bin/t"), P("/private/tmp/s"))
        self.assertEqual(seatbelt_profile(SeatbeltPlan(EmptyBase(), rules), TOOL, link).splitlines(), [
            "(version 1)", "(allow default)",
            "(deny file-read-data file-write*)",
            '(allow file-read-data (subpath "/opt/t/bin/t"))',
            '(allow file-read-data (subpath "/usr"))', '(deny file-write* (subpath "/usr"))',
            '(allow file-read-data file-write* (subpath "/r"))',
            '(allow file-read-data (literal "/r/README.md"))', '(deny file-write* (literal "/r/README.md"))',
            '(deny file-write* (regex #"^/r/keep(/.*)?$"))',
            '(deny file-read-data file-write* (subpath "/r/secret"))',
            '(allow file-read-data (literal "/") (subpath "/private/tmp/s"))',
            '(allow file-write* (subpath "/private/tmp/s") (literal "/dev/null"))',
            "(deny network*)", "(deny process-fork)",
        ])


if __name__ == "__main__":
    unittest.main()
