"""``certorail policy apply`` and the described ``certorail policy list``: bringing an installed
ruleset into a root policy with bindings, against a scratch config directory."""
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from certorail.apply import (
    apply_ruleset,
    base_applies,
    parse_binding,
    render_apply,
    ruleset_lines,
    toml_value,
    unbound,
)
from certorail.install import InstallError, install_policy, list_installed, main as policy_main
from certorail.policydir import find_policy
from certorail.policyfile import BASE_RULESET, load_policy_file, rulesets_dir

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
gate   = { kind = "atom", description = "atoms the cwd must carry; [] for none" }
force  = { kind = "bool", description = "permit --force" }

[[program]]
name = "git"
argv = ["git", "push", "${REMOTE}", "${FLAGS...}"]
cwd  = "${where}/**"
holes.REMOTE = "${remote}"
holes.FLAGS  = { kind = "flags", bare = ["-u"], "--force" = { value = false, when = "${force}" } }
requires = ["${gate}"]
"""

BASE = """\
ruleset-version = 1

[[apply]]
ruleset = "tools.toml"
where   = "."
"""

POLICY = """\
policy-version = 1
root = "{root}"

[filesystem]
read  = ["**"]
write = ["**"]
list  = ["**"]
"""


class Said:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    def text(self) -> str:
        return "\n".join(self.lines)


class TestBindings(unittest.TestCase):
    def test_key_value_parsing(self) -> None:
        self.assertEqual(parse_binding("where=."), ("where", "."))
        self.assertEqual(parse_binding("where=repos"), ("where", "repos"))
        self.assertEqual(parse_binding('where=["repos", "/srv/data"]'), ("where", ["repos", "/srv/data"]))
        self.assertEqual(parse_binding("force=true"), ("force", True))
        self.assertEqual(parse_binding("gate=[]"), ("gate", []))
        self.assertEqual(parse_binding('remote={ one-of = ["origin"] }'), ("remote", {"one-of": ["origin"]}))
        self.assertEqual(parse_binding('branch = { atoms = ["x"], literal = true }'), ("branch", {"atoms": ["x"], "literal": True}))
        with self.assertRaises(InstallError):
            parse_binding("nonsense")

    def test_toml_rendering_round_trips(self) -> None:
        import tomllib

        bindings = {
            "where": ".", "list": ["a", "b"], "force": True, "n": 3,
            "remote": {"one-of": ["origin"], "literal": False}, "regex": "src/**/<.*\\.py>", "quoted": "it's",
        }
        text = render_apply("x.toml", bindings)
        back = tomllib.loads(text)["apply"][0]
        self.assertEqual(back["ruleset"], "x.toml")
        for k, v in bindings.items():
            self.assertEqual(back[k], v)
        self.assertEqual(toml_value("src/**/<.*\\.py>"), "'src/**/<.*\\.py>'")

    def test_unbound_names_are_read_from_the_loaders_problems(self) -> None:
        problems = [
            "x.toml (where=.): apply[0]: parameter 'remote' is not bound",
            "x.toml (where=.): apply[0]: parameter 'gate' is not bound",
            "x.toml (where=.): apply[0]: parameter 'remote' is not bound",
            "something else entirely",
        ]
        self.assertEqual(unbound(problems), ["remote", "gate"])


class TestApply(unittest.TestCase):
    def setUp(self) -> None:
        self.config = pathlib.Path(tempfile.mkdtemp(prefix="certorail-apply-config-"))
        self.enterContext(mock.patch.dict("os.environ", {"CERTORAIL_CONFIG_DIR": str(self.config)}))
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="certorail-apply-root-"))
        self.addCleanup(shutil.rmtree, self.config, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        rulesets_dir().mkdir(parents=True)
        (rulesets_dir() / "tools.toml").write_text(TOOLS)
        (rulesets_dir() / "pusher.toml").write_text(PUSHER)
        src = self.root / "policy.toml"
        src.write_text(POLICY.format(root=self.root.resolve()))
        install_policy(src)
        found = find_policy(self.root)
        assert found is not None
        self.target, self.prefix = found

    def apply(self, ruleset: str, bindings: dict, typed: list[str] | None = None) -> tuple[int, Said]:
        said = Said()
        queue = list(typed) if typed is not None else None

        def prompt(question: str) -> str:
            assert queue is not None, "the test did not expect a prompt"
            said(f"? {question}")
            return queue.pop(0)

        status = apply_ruleset(self.target, self.prefix, ruleset, bindings, prompt=prompt if queue is not None else None, say=said)
        return status, said

    def test_a_fully_bound_application_lands_and_loads(self) -> None:
        status, said = self.apply("pusher.toml", {"where": ".", "remote": {"one-of": ["origin"]}, "gate": []})
        self.assertEqual(status, 0, said.text())
        text = self.target.read_text()
        self.assertIn('[[apply]]\nruleset = "pusher.toml"', text)
        self.assertIn("remote = { one-of = ['origin'] }", text)
        policy = load_policy_file(self.target)
        self.assertIn(("git", "push"), [p.leading_words for p in policy.programs])
        self.assertIn("applied pusher.toml", said.text())
        self.assertIn("review it:", said.text())

    def test_missing_bindings_without_a_terminal_stop_and_name_them(self) -> None:
        before = self.target.read_bytes()
        status, said = self.apply("pusher.toml", {"where": "."})
        self.assertEqual(status, 1)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertIn("remote (constraint: where pushes go)", said.text())
        self.assertIn("gate (atom: atoms the cwd must carry; [] for none)", said.text())

    def test_missing_bindings_are_asked_for_with_their_descriptions(self) -> None:
        status, said = self.apply("pusher.toml", {}, typed=["", "not a table", '{ one-of = ["origin", "fork"] }', ""])
        self.assertEqual(status, 0, said.text())
        asked = [line for line in said.lines if line.startswith("? ")]
        self.assertEqual(len(asked), 4)  # where, remote (twice: the first answer was not a table), gate
        self.assertIn("where (the repositories)", asked[0])
        self.assertIn("remote (where pushes go)", asked[1])
        self.assertIn("'not a table' is not a table", said.text())
        text = self.target.read_text()
        self.assertIn("where  = '.'", text)  # the directory default
        self.assertIn("gate   = []", text)
        policy = load_policy_file(self.target)
        push = next(p for p in policy.programs if p.leading_words == ("git", "push"))
        self.assertIsNotNone(push.template)

    def test_refusals(self) -> None:
        status, said = self.apply("missing.toml", {})
        self.assertEqual((status, "is not installed" in said.text()), (1, True))
        status, said = self.apply("pusher.toml", {"where": ".", "nope": 1})
        self.assertEqual((status, "'nope' is not a parameter" in said.text()), (1, True))
        status, _ = self.apply("pusher.toml", {"where": ".", "remote": {"one-of": ["origin"]}, "gate": []})
        self.assertEqual(status, 0)
        status, said = self.apply("pusher.toml", {"where": ".", "remote": {"one-of": ["origin"]}, "gate": []})
        self.assertEqual((status, "already applies pusher.toml" in said.text()), (1, True))

    def test_the_base_already_applying_it_is_a_refusal_unless_opted_out(self) -> None:
        (rulesets_dir() / BASE_RULESET).write_text(BASE)
        self.assertEqual(base_applies(), ("tools.toml",))
        status, said = self.apply("tools.toml", {"where": "sub"})
        self.assertEqual((status, "base ruleset already applies tools.toml" in said.text()), (1, True))
        self.target.write_text(self.target.read_text().replace('root = ', 'base = false\nroot = ', 1))
        status, said = self.apply("tools.toml", {"where": "sub"})
        self.assertEqual(status, 0, said.text())

    def test_the_inventory_describes_and_attributes(self) -> None:
        (rulesets_dir() / BASE_RULESET).write_text(BASE)
        self.apply("pusher.toml", {"where": ".", "remote": {"one-of": ["origin"]}, "gate": []})
        lines = "\n".join(ruleset_lines(self.root))
        self.assertIn("base.toml: the base ruleset", lines)
        self.assertIn("tools.toml: a read-only tool", lines)
        self.assertIn("applied by the base", lines)
        self.assertIn("pusher.toml: pushes somewhere", lines)
        self.assertIn(f"applied by {self.target}", lines)
        self.assertIn("parameters: where (directory: the repositories); remote (constraint: where pushes go)", lines)
        self.assertNotIn("certorail policy apply pusher.toml", lines)  # applied here: no hint
        without_root = "\n".join(ruleset_lines(None))
        self.assertIn("certorail policy apply pusher.toml where=.", without_root)
        full = list_installed(self.root)
        self.assertIn("rulesets:", full)
        self.assertIn("pusher.toml: pushes somewhere", full)

    def test_the_verbs(self) -> None:
        with mock.patch("certorail.install._interactive", return_value=False):
            self.assertEqual(policy_main(["apply", "pusher.toml", "--root", str(self.root), "where=.", 'remote={ one-of = ["origin"] }', "gate=[]"]), 0)
            self.assertIn(("git", "push"), [p.leading_words for p in load_policy_file(self.target).programs])
            self.assertEqual(policy_main(["apply", "tools.toml", "--root", str(self.root)]), 1)  # where unbound, no terminal
        with mock.patch("builtins.print") as printed:
            self.assertEqual(policy_main(["list", "--root", str(self.root)]), 0)
        self.assertIn("pusher.toml: pushes somewhere", "\n".join(str(c.args[0]) for c in printed.call_args_list))


if __name__ == "__main__":
    unittest.main()
