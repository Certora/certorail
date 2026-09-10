"""The policy format as a schema (``certorail.schema``): the shape layer -- closed key sets,
strict values, local invariants, every problem reported with its path. Meaning is not checked
here; the semantic passes are."""
import pathlib
import tomllib
import unittest

from certorail.schema import (
    EachHole,
    FlagsHole,
    FlagsetRef,
    PolicyDoc,
    SchemaError,
    TokenHole,
    json_schema,
    parse_policy,
    parse_ruleset,
)

REPO = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def load(text: str) -> PolicyDoc:
    return parse_policy(tomllib.loads(text), "<t>")


def problems(text: str) -> list[str]:
    with unittest.TestCase().assertRaises(SchemaError) as cm:
        load(text)
    return cm.exception.problems


class TestOneStandsForTheListOfOne(unittest.TestCase):
    """Every set-valued key takes one string (``ports``: one integer) as the list of one; the
    model always holds the list."""

    def test_every_set_valued_key(self) -> None:
        doc = load(
            'policy-version = 1\n'
            '[filesystem]\nread = "**"\nwrite = "out/**"\nlist = "**"\nno-write = ".git/**"\n'
            '[regions]\nblah = { footprint = "thing" }\n'
            '[atoms]\nmy-thing = { reads = "blah" }\n'
            '[[program]]\nname = "git"\nargv = ["git", "push", "${B}", "${F...}"]\ncwd = "repos/*"\n'
            'requires = "my-thing"\nwrites = "blah"\n'
            'holes.B = { one-of = "main" }\nholes.F = { kind = "flags", bare = "-v" }\n'
            'exec.view = "policy"\nexec.env = "PATH"\nexec.mount-read = "/srv/keys/**"\n'
            '[[validation]]\nname = "v"\nparams = "X"\nargv = ["test", "${X}"]\ncwd = "**"\n'
            'establishes = { X = "my-thing" }\nwrites = "blah"\n'
            '[[network]]\nhost = "api.github.com"\nschemes = "https"\nports = 443\nmethods = "GET"\n'
            'requires = "my-thing"\nwrites = "blah"\n'
        )
        fs = doc.filesystem
        self.assertEqual((fs.read, fs.write, fs.list_, fs.no_write), (["**"], ["out/**"], ["**"], [".git/**"]))
        self.assertEqual(doc.regions["blah"].footprint, ["thing"])  # type: ignore[union-attr]
        self.assertEqual(doc.atoms["my-thing"].reads, ["blah"])
        (rule,) = doc.program
        self.assertEqual((rule.requires, rule.writes), (["my-thing"], ["blah"]))
        assert rule.holes is not None and rule.exec_ is not None
        b, f = rule.holes["B"], rule.holes["F"]
        assert isinstance(b, TokenHole) and isinstance(f, FlagsHole)
        self.assertEqual((b.one_of, f.bare), (["main"], ["-v"]))
        self.assertEqual((rule.exec_.env, rule.exec_.mount_read), (["PATH"], ["/srv/keys/**"]))
        (v,) = doc.validation
        self.assertEqual((v.params, v.establishes, v.writes), (["X"], {"X": ["my-thing"]}, ["blah"]))
        (n,) = doc.network
        self.assertEqual(
            (n.schemes, n.ports, n.methods, n.requires, n.writes),
            (["https"], [443], ["GET"], ["my-thing"], ["blah"]),
        )

    def test_only_a_scalar_of_the_element_kind_is_lifted(self) -> None:
        self.assertEqual(problems('policy-version = 1\n[filesystem]\nread = { x = 1 }\n'), ["filesystem.read: expected a list"])
        self.assertEqual(problems('policy-version = 1\n[[network]]\nhost = "h"\nports = "443"\n'), ["network[0].ports: expected a list"])
        self.assertEqual(problems('policy-version = 1\n[[network]]\nhost = "h"\nmethods = 7\n'), ["network[0].methods: expected a list"])


class TestDocuments(unittest.TestCase):
    def test_the_fixture_policies_have_the_shape(self) -> None:
        # a full root policy applying the git pack (deny, override, no-write, every key kind) and
        # a read-only find with a large flagset: the two documents the loader tests lean on
        for name in ("git-policy.toml", "find.toml"):
            with self.subTest(name=name):
                data = tomllib.loads((FIXTURES / name).read_text(encoding="utf-8"))
                parse_policy(data, name)

    @unittest.skipUnless((REPO / "rulesets" / "git").is_dir(), "the shipped git pack is not in this tree")
    def test_the_git_pack_rulesets_have_the_shape(self) -> None:
        paths = sorted((REPO / "rulesets" / "git").glob("*.toml"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(name=path.name):
                parse_ruleset(tomllib.loads(path.read_text(encoding="utf-8")), path.name)

    def test_the_dev_policy_has_the_shape(self) -> None:
        doc = load(
            'policy-version = 1\nroot = "/srv/x"\n'
            '[[program]]\nname = "uv"\nargv = ["uv", "run", "pytest", "${FLAGS...}", "${TESTS...}"]\ncwd = "."\n'
            'network = false\nholes.FLAGS.kind = "flags"\nholes.FLAGS.bare = ["-q"]\n'
            'holes.FLAGS."-k" = { any = true }\nholes.TESTS = { kind = "each", location = "tests/**" }\n'
        )
        (rule,) = doc.program
        assert rule.holes is not None
        flags, tests = rule.holes["FLAGS"], rule.holes["TESTS"]
        assert isinstance(flags, FlagsHole) and isinstance(tests, EachHole)
        self.assertEqual(flags.flags["-k"].any, True)
        self.assertEqual(tests.location, ["tests/**"])  # a slot is held as its list

    def test_a_token_hole_needs_no_kind_and_a_parameter_is_a_string(self) -> None:
        doc = load(
            'policy-version = 1\n[[program]]\nname = "git"\ncwd = "."\n'
            'argv = ["git", "push", "${A}", "${B}", "${F...}"]\nholes.A = { atoms = ["x"] }\nholes.B = "${branch}"\n'
            'holes.F = { kind = "flags", flagset = "f" }\n'
        )
        assert doc.program[0].holes is not None
        self.assertIsInstance(doc.program[0].holes["A"], TokenHole)
        self.assertEqual(doc.program[0].holes["B"], "${branch}")
        ref = doc.program[0].holes["F"]
        assert isinstance(ref, FlagsetRef)
        self.assertEqual(ref.flagset, "f")


class TestShapeErrors(unittest.TestCase):
    def test_every_problem_with_its_path(self) -> None:
        found = problems(
            'policy-version = 1\n[filesystem]\nread = ["a/**/b/**"]\n'
            '[[program]]\nname = "git"\ncwd = "."\nsubcommand = "log"\nargv = ["git", "log"]\nholes = {}\n'
            '[[program]]\nname = "x"\ncwd = "."\nunknown-arguments = true\n'
            '[atoms]\nbad = { pure = true, reads = ["r"] }\n'
        )
        self.assertEqual(len(found), 4, found)
        self.assertTrue(any(p.startswith("filesystem.read[0]") for p in found))
        self.assertTrue(any("program[0]" in p and "no subcommand" in p for p in found))
        self.assertTrue(any("program[1]" in p and "no longer a rule key" in p for p in found))
        self.assertTrue(any(p.startswith("atoms.bad") and "reads applies" in p for p in found))

    def test_strict_values(self) -> None:
        # no coercion: 1 is not true, "1" is not 1
        self.assertTrue(any("network" in p for p in problems('policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\nnetwork = 1\n')))
        self.assertTrue(any("ports" in p for p in problems('policy-version = 1\n[[network]]\nhost = "h"\nports = ["443"]\n')))
        self.assertTrue(problems('policy-version = "1"\n'))

    def test_closed_keys(self) -> None:
        self.assertEqual(problems('policy-version = 1\nroot = "/x"\ncolour = "blue"\n'), ["unknown key 'colour'"])
        self.assertTrue(any("holes.A" in p for p in problems(
            'policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\nargv = ["x", "${A}"]\nholes.A = { any = true, min = 1 }\n'
        )))

    def test_the_catalogue(self) -> None:
        def rule(body: str) -> str:
            return 'policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\n' + body

        cases = [
            (rule('argv = ["x", "${A}"]\nholes.A = {}\n'), "says nothing"),
            (rule('argv = ["x", "${A}"]\nholes.A = { location = "**", matches = "x" }\n'), "textless"),
            (rule('argv = ["x", "${A}"]\nholes.A = { any = true, atoms = ["a"] }\n'), "combines with nothing"),
            (rule('argv = ["x", "a${A}"]\nholes.A = { any = true }\n'), "whole words"),
            (rule('holes.A = { any = true }\n'), "need an argv template"),
            (rule('argv = ["x", "${A}"]\nholes.A = { kind = "nope" }\n'), "kind must be one of"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", "-q" = {} }\n'), "not a bare flag"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", bare = ["q"] }\n'), "begin with '-'"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", any = true, bare = ["-q"] }\n'), "lists no flags"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", flagset = "f", bare = ["-q"] }\n'), "holes.A: unknown key 'bare'"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags" }\n'), "at least one flag"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", "-q" = { value = true } }\n'), "-q"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { kind = "flags", "-q" = { value = false, any = true } }\n'), "takes no constraint"),
            (rule('subcommand = "y"\nrequires = { A = ["a"] }\n'), "no template"),
            (rule('argv = ["y", "${A}"]\nholes.A = { any = true }\n'), "not 'x'"),
            ('policy-version = 1\n[regions]\nr = { footprint = "x", network = true }\n', "one medium"),
            ('policy-version = 1\n[regions]\nr = { about = "?" }\n', "one medium"),
            ('policy-version = 1\n[regions]\nr = { network = false }\n', "one medium"),
            ('policy-version = 1\n[atoms]\na = { matches = "x", pure = false }\n', "pure by construction"),
            ('policy-version = 1\n[atoms]\na = { matches = "(" }\n', "bad regex"),
            ('policy-version = 1\n[atoms]\na = { reads = [] }\n', "depends on nothing"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\nparams = ["cwd"]\n', "may not be named 'cwd'"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\nestablishes = { cwd = ["a"] }\n', "cannot establish atoms on cwd"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t", "${checkers}/x"]\ncwd = "."\n', "head argv[0]"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t", "a${p}"]\nparams = ["p"]\n', "whole arguments"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\neffect-free = true\n', "'effect-free' is no longer a key: spell writes = []"),
            ('policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\nwrite = false\n', "'write' is no longer a key: spell write-fs"),
            ('policy-version = 1\nroot = "x"\n', "absolute path"),
            ('policy-version = 1\n[[apply]]\nruleset = "../x.toml"\n', ".toml file"),
            ('policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\nwhen = "maybe"\n', "bool parameter"),
            # names that could never be referenced or would be read as something else
            (rule('argv = ["x", "${cwd}"]\nholes.cwd = { any = true }\n'), "'cwd' is reserved"),
            (rule('argv = ["x", "${A}"]\nholes.A = { any = true }\nrequires = { "my-hole" = ["a"] }\n'), "letters, digits and '_'"),
            (rule('argv = ["x", "${A}", "${A}"]\nholes.A = { any = true }\n'), "more than once"),
            (rule('argv = ["x", "${A}"]\nholes = {}\n'), "used but not declared"),
            (rule('argv = ["x"]\nholes.A = { any = true }\n'), "declared but not used"),
            (rule('argv = ["x", "${A...}"]\nholes.A = { any = true }\n'), "disagrees with its kind (token)"),
            (rule('argv = ["x", "${A}"]\nholes.A = { kind = "each", any = true }\n'), "disagrees with its kind (each)"),
            (rule('argv = ["x", "${A...}"]\nholes.A = "${p}"\n'), "disagrees with its kind (a parameter)"),
            (rule('subcommand = " "\n'), "one or more words"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\nparams = ["checkers"]\n', "cannot be a parameter"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\nparams = ["a b"]\n', "letters, digits, '_' and '-'"),
            ('policy-version = 1\n[atoms]\nnot-option = {}\n', "built in and cannot be declared"),
            ('policy-version = 1\n[regions]\nfs = { footprint = "x" }\n', "regions.fs: 'fs' names a medium"),
            ('policy-version = 1\n[[network]]\nhost = "https://api.example.com"\n', "no scheme, port or path"),
            ('policy-version = 1\n[[flagset]]\nname = "f"\nbare = ["-q"]\n[[flagset]]\nname = "f"\nbare = ["-v"]\n', "declared twice"),
            ('policy-version = 1\n[[validation]]\nname = "v"\nargv = ["t"]\n[[validation]]\nname = "v"\nargv = ["u"]\n', "declared twice"),
            ('policy-version = 1\n[[flagset]]\nname = "f"\nbare = ["-q"]\nholes = ["cwd"]\n', "'cwd' is reserved"),
        ]
        for text, expected in cases:
            with self.subTest(expected=expected):
                found = problems(text)
                self.assertTrue(any(expected in p for p in found), found)

    def test_a_parameter_must_be_bindable_and_referenceable(self) -> None:
        for name, expected in (("when", "key of [[apply]]"), ("ruleset", "key of [[apply]]"), ("a.b", "letters, digits")):
            with self.subTest(name=name), self.assertRaises(SchemaError) as cm:
                parse_ruleset(tomllib.loads(f'ruleset-version = 1\n[params]\n"{name}" = {{ kind = "bool" }}\n'), "r")
            self.assertTrue(any(expected in p for p in cm.exception.problems), cm.exception.problems)

    def test_a_ruleset_has_no_grants(self) -> None:
        with self.assertRaises(SchemaError) as cm:
            parse_ruleset(tomllib.loads('ruleset-version = 1\n[filesystem]\nread = ["**"]\n'), "r")
        self.assertTrue(any("filesystem" in p for p in cm.exception.problems))
        doc = parse_ruleset(tomllib.loads(
            'ruleset-version = 1\n[params]\nwhere = { kind = "directory" }\nforce = { kind = "bool" }\n'
            '[[apply]]\nruleset = "x.toml"\nwhere = "${where}"\nforce = "${force}"\nwhen = "${force}"\n'
        ), "r")
        self.assertEqual(doc.params["force"].kind, "bool")
        self.assertEqual(doc.apply[0].bindings, {"where": "${where}", "force": "${force}"})

    def test_every_table_knows_its_document(self) -> None:
        doc = parse_policy(tomllib.loads(
            'policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\nargv = ["x", "${A...}"]\n'
            'holes.A = { kind = "flags", "-n" = { matches = "[0-9]+" } }\n'
        ), "p.toml")
        rule = doc.program[0]
        assert rule.holes is not None
        hole = rule.holes["A"]
        assert isinstance(hole, FlagsHole)
        self.assertEqual((doc.where, rule.where, hole.where, hole.flags["-n"].where), ("p.toml",) * 4)
        self.assertEqual(rule.model_copy(update={"name": "y"}).where, "p.toml")
        self.assertNotIn("where", json_schema()["properties"])

    def test_the_json_schema_exists(self) -> None:
        schema = json_schema()
        self.assertIn("policy-version", schema["properties"])
        self.assertEqual(schema["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
