"""The placement checker (``sandbox.certify``, ``proofs/place``) on what the placer makes: the
document it is handed, and its verdicts on the plans of the placer's own fuzzes -- every one it
makes must be certified. Skips where no checker is built (``lake -d proofs/place build``)."""
import pathlib
import random
import unittest

from certorail.locations import parse_location
from certorail.sandbox.certify import Certified, Native, Refused, document, locate, stability
from certorail.sandbox.facts import Recorded
from certorail.sandbox.grants import (
    Access, Grant, HostGrants, Layer, Lifetime, Narrowing, Pattern, PolicyGrants, Restriction, within,
)
from certorail.sandbox.place import Bind, BwrapPlan, EmptyBase, place_bubblewrap
from certorail.world import Selector, Stable
from tests.test_jail_compiler import LAYOUTS, PROCESS, UNIVERSE, FakeFS, Say, grant, random_fs, random_layer, restrict

P = pathlib.Path


def checker() -> Native:
    found = locate()
    if isinstance(found, str):
        raise unittest.SkipTest(found)
    return found


def placed(grants: PolicyGrants | HostGrants, fs: FakeFS) -> tuple[BwrapPlan, Recorded] | None:
    recorded = Recorded(fs)
    plan = place_bubblewrap(grants, recorded)
    return (plan, recorded) if isinstance(plan, BwrapPlan) else None


class TestDocument(unittest.TestCase):
    FS = FakeFS(dirs=("/usr/lib", "/r/src", "/opt/data"), links={"/lib": "/usr/lib"})

    def test_a_bind_through_a_link_is_an_alias(self) -> None:
        g = PolicyGrants((grant("/lib", stable=True), grant("/r/src")), Lifetime.EXEC, PROCESS, P("/r"))
        result = placed(g, self.FS)
        assert result is not None
        doc = document(g, *result)
        sources = {m["path"]: m["source"] for m in doc["mounts"]}
        self.assertEqual(sources, {"/lib": {"alias": "/usr/lib"}, "/r/src": "own"})
        # the facts the checker needs of every mount were asked, so each spawn asks them again
        self.assertIn(["/usr/lib", "directory"], doc["facts"]["kinds"])
        self.assertIn(["/lib", "/usr/lib"], doc["facts"]["resolutions"])

    def test_a_view_is_named_by_its_index(self) -> None:
        pattern = Layer(Pattern(parse_location("/opt/data/<[a-z]+>/**"), P("/")), Grant(Access.READ_ONLY), Say("pattern"))
        g = PolicyGrants((pattern,), Lifetime.EXEC, PROCESS, P("/r"))
        result = placed(g, self.FS)
        assert result is not None
        doc = document(g, *result)
        self.assertEqual(doc["mounts"], [{"path": "/opt/data", "state": "read-only", "source": {"view": 0, "rel": "."}}])
        self.assertEqual(doc["views"][0]["directory"], "/opt/data")
        self.assertEqual(doc["layers"][0]["region"]["tops"], ["/opt/data"])

    def test_the_stability_model(self) -> None:
        facts = Recorded(self.FS)
        home = Stable.of(Selector.HOME, home_at=P("/home/u"))
        g = PolicyGrants((grant("/usr", stable=True), grant("/r/src")), Lifetime.RUN, PROCESS, P("/r"), workdir=P("/r"), stable=home)
        # a policy world: nothing outside the jail replaces these; what the jail may do, its mounts say
        self.assertEqual(stability(g, facts), {"names": [], "children-of": [], "kept": ["/r", "/home/u"], "subtrees": ["/usr"]})
        # the top-level names nothing replaces at all: the policy world's root is a read-only tmpfs
        tops = PolicyGrants(g.layers, Lifetime.RUN, PROCESS, P("/r"), workdir=P("/r"), stable=Stable.of(Selector.TOPS, home_at=P("/home/u")))
        self.assertEqual(stability(tops, facts), {"names": [], "children-of": ["/"], "kept": ["/r"], "subtrees": ["/usr"]})
        # a host world: nothing replaces these at all, the views of the redlines sit on them
        h = HostGrants(True, Lifetime.EXEC, PROCESS, (restrict("/home/u/.ssh", Narrowing.HIDDEN),), P("/r"),
                       Stable.of(Selector.TOPS, Selector.HOME, home_at=P("/home/u")))
        self.assertEqual(stability(h, facts), {"names": ["/home/u"], "children-of": ["/"], "kept": [], "subtrees": []})


class TestVerdicts(unittest.TestCase):
    FS = FakeFS(dirs=("/usr", "/r/src", "/r/out"))

    def test_a_plan_the_placer_makes_is_certified(self) -> None:
        g = PolicyGrants((grant("/usr", stable=True), grant("/r/src"), grant("/r/out", Access.WRITABLE)), Lifetime.EXEC, PROCESS, P("/r"))
        result = placed(g, self.FS)
        assert result is not None
        self.assertEqual(checker().certify([document(g, *result)]), [Certified()])

    def test_pins_and_a_parent_view_are_certified(self) -> None:
        fs = FakeFS(dirs=("/usr", "/r/a/b", "/r/a/src"), files=("/r/a/README",))
        pinned = PolicyGrants((grant("/usr", stable=True), grant("/r", Access.WRITABLE), grant("/r/a/b")),
                              Lifetime.EXEC, PROCESS, P("/r"))
        parent = PolicyGrants((grant("/usr", stable=True), grant("/r", Access.WRITABLE), grant("/r/a/.git")),
                              Lifetime.EXEC, PROCESS, P("/r"))
        documents = []
        for g in (pinned, parent):
            result = placed(g, fs)
            assert result is not None
            documents.append(document(g, *result))
        self.assertEqual(checker().certify(documents), [Certified(), Certified()])

    def test_a_wrong_plan_is_refused_and_says_why(self) -> None:
        g = PolicyGrants((grant("/r/src"),), Lifetime.EXEC, PROCESS, P("/r"))
        recorded = Recorded(self.FS)
        wrong = BwrapPlan(EmptyBase(), (Bind(P("/r/src"), Access.WRITABLE),))
        [verdict] = checker().certify([document(g, wrong, recorded)])
        assert isinstance(verdict, Refused), verdict
        self.assertIn("at /r/src the jail is writable, and the grants make it read-only", verdict.reasons)


class TestFuzzedPlansAreCertified(unittest.TestCase):
    """The placer's fuzzes (``test_jail_compiler``), their plans handed to the checker."""

    CASES = 3000  # clean at 20000, patterns included, footings, 2026-09-29

    def assert_certified(self, cases: list[tuple[str, dict]]) -> None:
        verdicts = checker().certify([doc for _, doc in cases])
        refused = [(case, doc, v) for (case, doc), v in zip(cases, verdicts) if isinstance(v, Refused)]
        report = "\n\n".join(
            f"{case}\n  mounts: " + ", ".join(f"{m['path']} {m['state']} {m['source']}" for m in doc["mounts"])
            + "\n  " + "\n  ".join(dict.fromkeys(v.reasons))
            for case, doc, v in refused)
        self.assertEqual(len(refused), 0, f"{len(refused)} of {len(cases)} plans refused:\n\n{report}")

    def test_policy_world(self) -> None:
        rng = random.Random(2)
        cases: list[tuple[str, dict]] = []
        for i in range(self.CASES):
            toolchain, workdir = rng.choice(LAYOUTS)
            fs = random_fs(rng, toolchain, workdir)
            lifetime = rng.choice(list(Lifetime))
            layers = (grant(str(toolchain), stable=True), *(random_layer(rng) for _ in range(rng.randint(1, 6))))
            g = PolicyGrants(layers, lifetime, PROCESS, workdir, workdir=workdir if lifetime is Lifetime.RUN else None)
            result = placed(g, fs)
            if result is not None:
                cases.append((f"case {i} ({lifetime}, toolchain {toolchain}): "
                               f"{[(l.origin.describe(), l.effect) for l in layers]}\nfs: {fs.kinds} {fs.links}",
                               document(g, *result)))
        self.assert_certified(cases)

    def test_host_world(self) -> None:
        rng = random.Random(3)
        anchor = P("/a/x")
        stable = Stable.of(Selector.TOPS, paths=(anchor,), home_at=P("/nohome"))
        cases: list[tuple[str, dict]] = []
        for i in range(self.CASES // 3):
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
            result = placed(g, fs)
            if result is not None:
                cases.append((f"case {i} (writable {writable}): {[(l.origin.describe(), l.effect) for l in g.layers]}"
                               f"\nfs: {fs.kinds} {fs.links}", document(g, *result)))
        self.assert_certified(cases)


if __name__ == "__main__":
    unittest.main()
