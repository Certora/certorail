"""The Claude Code pack, installed into a throwaway HOME.

Every wiring step is asserted to have landed, a second install is asserted to change nothing, an
uninstall is asserted to put the settings file back exactly as it was, and the hook is asserted to
stay quiet on anything that is not a certorail rejection. Offline: no network, and no installed
``certorail`` -- the one test that needs a binary puts a four-line shim on PATH.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

PACK = pathlib.Path(__file__).resolve().parent.parent / "examples" / "claude-code-pack"
REPO = PACK.parent.parent
HOOK = PACK / "hooks" / "explain_hook.py"

EXISTING_SETTINGS = {
    "model": "opus",
    "hooks": {
        "PostToolUse": [
            {"matcher": "Write", "hooks": [{"type": "command", "command": "echo mine"}]}
        ],
        "Stop": [{"hooks": [{"type": "command", "command": "echo stopping"}]}],
    },
}


def load_installer():
    """examples/ is not a package, so the installer is loaded by path rather than imported."""
    spec = importlib.util.spec_from_file_location("certorail_pack_install", PACK / "install.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(root: pathlib.Path) -> dict[str, object]:
    """Every path under *root*, with its bytes -- or, for a link, where it points."""
    out: dict[str, object] = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        out[key] = os.readlink(path) if path.is_symlink() else (
            path.read_bytes() if path.is_file() else "<dir>"
        )
    return out


class PackTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # /var is a symlink to /private/var on macOS; both sides of every path comparison here
        # have to be resolved or nothing matches
        self.home = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.claude = self.home / ".claude"
        self.install = load_installer()
        probe = self.home / "probe"
        try:
            os.symlink(self.home, probe)
        except OSError:
            self.skipTest("this filesystem does not allow symlinks")
        probe.unlink()

    def run_installer(self, *args: str) -> int:
        return self.install.main(["--home", str(self.home), "--quiet", *args])

    def settings(self) -> dict:
        return json.loads((self.claude / "settings.json").read_text(encoding="utf-8"))


class TestInstall(PackTestCase):
    def test_install_lands_every_wiring_step(self) -> None:
        self.assertEqual(self.run_installer(), 0)

        installed = self.claude / "certorail" / "explain_hook.py"
        self.assertEqual(installed.read_bytes(), HOOK.read_bytes())
        self.assertTrue(os.access(installed, os.X_OK))

        link = self.claude / "skills" / "certorail-policy"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), (REPO / ".claude" / "skills" / "certorail-policy").resolve())

        hooks = self.settings()["hooks"]
        for event in ("PostToolUse", "PostToolUseFailure"):
            entry = next(e for e in hooks[event] if e.get("matcher") == "Bash")
            self.assertTrue(
                entry["hooks"][0]["command"].endswith("certorail/explain_hook.py")
            )

    def test_install_merges_rather_than_overwriting(self) -> None:
        self.claude.mkdir(parents=True)
        (self.claude / "settings.json").write_text(json.dumps(EXISTING_SETTINGS), encoding="utf-8")
        self.assertEqual(self.run_installer(), 0)

        settings = self.settings()
        self.assertEqual(settings["model"], "opus")
        self.assertEqual(settings["hooks"]["Stop"], EXISTING_SETTINGS["hooks"]["Stop"])
        commands = [e["hooks"][0]["command"] for e in settings["hooks"]["PostToolUse"]]
        self.assertIn("echo mine", commands)
        self.assertEqual(len(commands), 2)

    def test_installing_twice_changes_nothing(self) -> None:
        self.run_installer()
        first = snapshot(self.claude)
        self.assertEqual(self.run_installer(), 0)
        self.assertEqual(snapshot(self.claude), first)
        self.assertEqual(len(self.settings()["hooks"]["PostToolUse"]), 1)

    def test_dry_run_writes_nothing(self) -> None:
        self.assertEqual(self.run_installer("--dry-run"), 0)
        self.assertFalse(self.claude.exists())

    def test_uninstall_reverses_every_step(self) -> None:
        self.claude.mkdir(parents=True)
        (self.claude / "settings.json").write_text(json.dumps(EXISTING_SETTINGS), encoding="utf-8")
        self.run_installer()
        self.assertEqual(self.run_installer("--uninstall"), 0)

        self.assertFalse((self.claude / "certorail" / "explain_hook.py").exists())
        self.assertFalse((self.claude / "skills" / "certorail-policy").is_symlink())
        self.assertFalse((self.claude / "certorail-pack.json").exists())
        self.assertEqual(self.settings(), EXISTING_SETTINGS)

    def test_it_refuses_to_clobber_a_foreign_file(self) -> None:
        destination = self.claude / "certorail" / "explain_hook.py"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"someone else wrote this\n")
        self.assertEqual(self.run_installer(), 1)
        self.assertEqual(destination.read_bytes(), b"someone else wrote this\n")

    def test_an_unknown_variable_is_an_error(self) -> None:
        with self.assertRaises(self.install.InstallError):
            self.install.expand("$NOPE/x", {"HOME": "/h"})


class TestManifest(PackTestCase):
    def test_the_manifest_lists_every_file_it_installs(self) -> None:
        manifest = self.install.load_manifest(PACK)
        for entry in [*manifest["artifact"], *manifest["wiring"]]:
            if "source" in entry:
                self.assertTrue((PACK / entry["source"]).is_file(), entry["source"])
            if "patch" in entry:
                self.assertTrue((PACK / entry["patch"]).is_file(), entry["patch"])

    def test_only_documented_variables_appear(self) -> None:
        manifest = self.install.load_manifest(PACK)
        env = dict.fromkeys(self.install.VARIABLES, "/x")
        for step in manifest["wiring"]:
            for key in ("dest", "link", "target", "file"):
                if key in step:
                    self.install.expand(step[key], env)  # an unknown variable raises
        for step in manifest["wiring"]:
            if "patch" in step:
                self.install.expand((PACK / step["patch"]).read_text(encoding="utf-8"), env)


class TestHook(PackTestCase):
    """The hook is driven directly, with a synthesised payload on stdin."""

    def fire(self, payload: dict, path: str | None = None, pythonpath: str | None = None):
        env = dict(os.environ)
        env["PATH"] = path if path is not None else tempfile.mkdtemp()
        if pythonpath is not None:
            env["PYTHONPATH"] = pythonpath
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def shim(self, body: str) -> str:
        """A directory holding one executable named ``certorail``."""
        directory = pathlib.Path(tempfile.mkdtemp())
        script = directory / "certorail"
        script.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        script.chmod(0o755)
        return str(directory)

    def test_the_hook_is_quiet_on_an_unrelated_failure(self) -> None:
        result = self.fire(
            {
                "tool_input": {"command": "git status"},
                "tool_response": "fatal: not a git repository",
                "hook_event_name": "PostToolUseFailure",
            }
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.returncode, 0)

    def test_the_hook_is_quiet_without_certorail(self) -> None:
        result = self.fire(
            {
                "tool_input": {"command": "certorail prog.py --check"},
                "tool_response": "prog.py: rejected",
                "hook_event_name": "PostToolUseFailure",
            }
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.returncode, 0)

    def test_the_hook_is_quiet_when_the_output_is_not_a_rejection(self) -> None:
        result = self.fire(
            {
                "tool_input": {"command": "certorail prog.py --check"},
                "tool_response": "prog.py: accepted",
                "hook_event_name": "PostToolUse",
            },
            path=self.shim("print('never reached')\n"),
        )
        self.assertEqual(result.stdout, "")

    def test_the_hook_injects_the_explanation(self) -> None:
        result = self.fire(
            {
                "tool_input": {"command": "certorail prog.py --check"},
                "tool_response": {"stdout": "", "stderr": "prog.py: rejected"},
                "hook_event_name": "PostToolUse",
            },
            path=self.shim("print('CANNED EXPLANATION')\n"),
        )
        document = json.loads(result.stdout)
        output = document["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PostToolUse")
        self.assertIn("the only two legitimate ones", output["additionalContext"])
        self.assertIn("CANNED EXPLANATION", output["additionalContext"])

    def test_the_hook_drops_run_only_arguments(self) -> None:
        recorded = pathlib.Path(tempfile.mkdtemp()) / "argv.json"
        path = self.shim(
            "import json, sys, pathlib\n"
            f"pathlib.Path({str(recorded)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            "print('explanation')\n"
        )
        self.fire(
            {
                "tool_input": {
                    "command": "certorail prog.py --root /r --policy p.toml --check "
                    "--no-jail -- a b"
                },
                "tool_response": "prog.py: rejected",
                "hook_event_name": "PostToolUseFailure",
            },
            path=path,
        )
        self.assertEqual(
            json.loads(recorded.read_text()),
            ["explain", "prog.py", "--root", "/r", "--policy", "p.toml"],
        )

    def test_the_hook_reaches_the_real_explain(self) -> None:
        # the shim IS certorail: the injected context is a genuine explanation of a genuine
        # rejection, produced by this checkout
        path = self.shim(
            "import runpy, sys\n"
            f"sys.path.insert(0, {str(REPO)!r})\n"
            'sys.argv = ["certorail", *sys.argv[1:]]\n'
            'runpy.run_module("certorail.host", run_name="__main__")\n'
        )
        result = self.fire(
            {
                "tool_input": {
                    "command": 'certorail -c "from os import path" --check'
                },
                "tool_response": "<command>: rejected",
                "hook_event_name": "PostToolUseFailure",
            },
            path=path + os.pathsep + os.environ.get("PATH", ""),
            pythonpath=str(REPO),
        )
        context = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("violation", context)
        self.assertIn("import from", context)


if __name__ == "__main__":
    unittest.main()
