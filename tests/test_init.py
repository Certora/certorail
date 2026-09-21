"""``certorail init``: the interview, driven by scripted answers against a scratch config
directory. It writes one policy file, through the installer, and nothing else."""
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from certorail import init
from certorail.host import main as certorail_main
from certorail.ids import ProgramName
from certorail.init import base_applies, interview, manifest
from certorail.policydir import find_policy
from certorail.policyfile import BASE_RULESET, load_policy_file, rulesets_dir
from certorail.schema import SchemaError, parse_ruleset

REPO = pathlib.Path(__file__).resolve().parent.parent
SHIPPED = REPO / "rulesets"

TOOLS = """\
ruleset-version = 1
description = "a read-only tool: true, from anywhere under where"

[params]
where = { kind = "directory", description = "the tree" }

[[program]]
name = "true"
cwd  = "${where}/**"
writes = []
"""

PUSHER = """\
ruleset-version = 1
description = "pushes somewhere"

[params]
where  = { kind = "directory", description = "the repositories" }
remote = { kind = "constraint", description = "where pushes go" }

[[program]]
name = "git"
argv = ["git", "push", "${REMOTE}"]
cwd  = "${where}/**"
holes.REMOTE = "${remote}"
"""

UMBRELLA = """\
ruleset-version = 1
description = "the umbrella: tools plus pusher"

[params]
where  = { kind = "directory", description = "the tree" }
remote = { kind = "constraint", description = "where pushes go" }

[[apply]]
ruleset = "tools.toml"
where   = "${where}"

[[apply]]
ruleset = "pusher.toml"
where   = "${where}"
remote  = "${remote}"
"""

BASE = """\
ruleset-version = 1

[[apply]]
ruleset = "tools.toml"
where   = "."
"""


class Script:
    """Scripted answers: a yes/no question is matched by a substring, a free-text prompt is
    answered from a queue. Records everything asked and said."""

    def __init__(self, answers: dict[str, bool] | None = None, typed: list[str] | None = None) -> None:
        self.answers = answers or {}
        self.typed = list(typed or [])
        self.asked: list[tuple[str, bool]] = []
        self.prompted: list[str] = []
        self.said: list[str] = []

    def ask(self, question: str, default: bool) -> bool:
        self.asked.append((question, default))
        for key, answer in self.answers.items():
            if key in question:
                return answer
        return default

    def prompt(self, question: str) -> str:
        self.prompted.append(question)
        return self.typed.pop(0) if self.typed else ""

    def say(self, line: str) -> None:
        self.said.append(line)

    def transcript(self) -> str:
        return "\n".join(self.said)


class TestInit(unittest.TestCase):
    def setUp(self) -> None:
        self.config = pathlib.Path(tempfile.mkdtemp(prefix="certorail-init-config-"))
        self.enterContext(mock.patch.dict("os.environ", {"CERTORAIL_CONFIG_DIR": str(self.config)}))
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="certorail-init-root-"))
        self.addCleanup(shutil.rmtree, self.config, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        rulesets_dir().mkdir(parents=True)
        (rulesets_dir() / "tools.toml").write_text(TOOLS)
        (rulesets_dir() / "pusher.toml").write_text(PUSHER)
        (rulesets_dir() / "umbrella.toml").write_text(UMBRELLA)

    def with_base(self) -> None:
        (rulesets_dir() / BASE_RULESET).write_text(BASE)

    def run_init(self, script: Script, root: pathlib.Path | None = None) -> Script:
        status = interview(root=root or self.root, ask=script.ask, prompt=script.prompt, say=script.say)
        self.assertEqual(status, 0, script.transcript())
        return script

    def installed(self):
        found = find_policy(self.root)
        assert found is not None
        return found[0], load_policy_file(found[0])

    def test_the_defaults_give_full_access_and_inherit_the_base(self) -> None:
        self.with_base()
        s = self.run_init(Script())
        self.assertEqual(
            [q[:25] for q, _ in s.asked],
            ["Apply the base ruleset to", "Give programs full read, ", "Allow all programs the po"],
        )
        self.assertEqual([d for _, d in s.asked], [True, True, False])  # allow-all defaults to no
        self.assertEqual(s.prompted, [])
        file, policy = self.installed()
        self.assertNotIn("base = false", file.read_text())
        self.assertNotIn("default-allow", file.read_text())
        self.assertFalse(policy.default_allow)
        for kind in ("read", "write", "listing"):
            self.assertEqual([str(loc) for loc in getattr(policy, kind)], [str(loc) for loc in load_policy_file(file).read])
        self.assertIn(BASE_RULESET, policy.applied)
        self.assertIn("true", {p.name for p in policy.programs})  # the base's tool reaches the root
        # the base's summary came from the ruleset's own description
        self.assertIn("tools.toml: a read-only tool: true, from anywhere under where", s.transcript())

    def test_declining_the_base_opts_the_root_out(self) -> None:
        self.with_base()
        s = self.run_init(Script({"Apply the base": False}))
        file, policy = self.installed()
        self.assertIn("base = false", file.read_text())
        self.assertNotIn(BASE_RULESET, policy.applied)
        self.assertEqual(policy.programs, ())
        self.assertIn("(nothing)" if not base_applies() else "tools.toml", s.transcript())

    def test_without_a_base_nothing_is_asked_about_it(self) -> None:
        s = self.run_init(Script())
        self.assertFalse(any("base" in q.lower() for q, _ in s.asked))
        file, _ = self.installed()
        self.assertNotIn("base", file.read_text().split("[filesystem]")[0].replace("base ruleset", ""))

    def test_the_quiz_takes_locations_per_kind_and_checks_them(self) -> None:
        s = self.run_init(Script(
            {"full read": False},
            typed=["src/**, docs/**/<.*\\.md>", "out/**, bad//path", "out/**", "."],
        ))
        self.assertEqual(len(s.prompted), 4)  # read, write (rejected once), write again, list
        self.assertIn("'bad//path'", s.transcript())
        _, policy = self.installed()
        self.assertEqual(len(policy.read), 2)
        self.assertEqual(len(policy.write), 1)
        self.assertEqual(len(policy.listing), 1)
        self.assertTrue(policy.read[1].static_prefix)  # the regex-leaf grant parsed

    def test_allow_all_is_opt_in(self) -> None:
        self.run_init(Script({"Allow all": True}))
        file, policy = self.installed()
        self.assertIn("default-allow = true", file.read_text())
        self.assertTrue(policy.default_allow)
        self.assertFalse(policy.governed(ProgramName("git")))  # no rule names it: it runs ungoverned

    def test_empty_answers_grant_nothing(self) -> None:
        self.run_init(Script({"full read": False}, typed=["", "", ""]))
        _, policy = self.installed()
        self.assertEqual((policy.read, policy.write, policy.listing), ((), (), ()))

    def test_already_set_up_does_nothing(self) -> None:
        self.run_init(Script())
        file, _ = self.installed()
        before = file.read_bytes()
        again = self.run_init(Script({"full read": False}))
        self.assertEqual(again.asked, [])
        self.assertIn("already set up", again.transcript())
        self.assertEqual(file.read_bytes(), before)
        # a subdirectory is governed by the parent's policy: also nothing to do
        sub = self.root / "sub"
        sub.mkdir()
        deeper = self.run_init(Script(), root=sub)
        self.assertIn("above this directory", deeper.transcript())
        self.assertEqual(deeper.asked, [])

    def test_the_manifest_lists_what_the_base_does_not_apply(self) -> None:
        self.with_base()
        s = self.run_init(Script())
        text = s.transcript()
        self.assertNotIn("  tools.toml: a read-only", text.split("installed rulesets the base does not apply")[1])
        self.assertIn("  pusher.toml: pushes somewhere", text)
        self.assertIn("applied by umbrella.toml", text)
        self.assertIn("parameters: where (the repositories); remote (where pushes go)", text)
        self.assertIn("certorail policy apply umbrella.toml where=.", text)
        lines = manifest(("tools.toml",))
        self.assertTrue(lines[0].startswith("  pusher.toml"))

    def test_the_verb_and_the_non_interactive_guard(self) -> None:
        with mock.patch.object(init, "_interactive", return_value=False):
            with self.assertRaises(SystemExit) as cm:
                certorail_main(["init", "--root", str(self.root)])
        self.assertIn("--yes", str(cm.exception))
        with mock.patch("builtins.print"):
            self.assertEqual(certorail_main(["init", "--yes", "--root", str(self.root)]), 0)
        self.assertIsNotNone(find_policy(self.root))

    def test_descriptions_are_schema_keys(self) -> None:
        doc = parse_ruleset(
            {"ruleset-version": 1, "description": "a pack", "params": {"where": {"kind": "directory", "description": "the tree"}}},
            "<t>",
        )
        self.assertEqual((doc.description, doc.params["where"].description), ("a pack", "the tree"))
        with self.assertRaises(SchemaError):
            parse_ruleset({"ruleset-version": 1, "description": 3}, "<t>")


@unittest.skipUnless((SHIPPED / "git").is_dir() and (SHIPPED / "coreutils").is_dir(), "the shipped packs are not in this tree")
class TestShippedDescriptions(unittest.TestCase):
    def test_every_shipped_ruleset_and_parameter_is_described(self) -> None:
        import tomllib

        for pack in ("coreutils", "git"):
            for path in sorted((SHIPPED / pack).glob("*.toml")):
                with self.subTest(ruleset=path.name):
                    doc = parse_ruleset(tomllib.loads(path.read_text(encoding="utf-8")), path.name)
                    self.assertTrue(doc.description, f"{path.name} has no description")
                    for name, param in doc.params.items():
                        self.assertTrue(param.description, f"{path.name}: parameter {name} has no description")


if __name__ == "__main__":
    unittest.main()
