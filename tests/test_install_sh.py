"""``install.sh``, exercised without installing anything.

Every case here runs the script with ``--dry-run`` or on a path that makes it refuse, so the
suite never builds a virtualenv, never reaches the network, and never touches the developer's
own installation. What is asserted is the part that can be wrong quietly: which installer gets
chosen, what the plan would do, and that the uninstall guard refuses a path the script did not
create.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
INSTALL = REPO / "install.sh"


def run(*args, env=None, cwd=None):
    environment = dict(os.environ)
    # a developer's own overrides would otherwise decide what the script does under test
    for name in (
        "CERTORAIL_SOURCE",
        "CERTORAIL_INSTALLER",
        "CERTORAIL_INSTALL_DIR",
        "CERTORAIL_VENV",
        "CLAUDE_HOME",  # the pack installer reads it, and it would aim the plan at a real config
    ):
        environment.pop(name, None)
    environment.update(env or {})
    return subprocess.run(
        ["sh", str(INSTALL), *args],
        capture_output=True,
        text=True,
        env=environment,
        cwd=cwd or REPO,
    )


class InstallScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.venv_env = {
            "CERTORAIL_INSTALLER": "venv",
            "CERTORAIL_VENV": str(self.home / "share" / "certorail" / "venv"),
            "CERTORAIL_INSTALL_DIR": str(self.home / "bin"),
        }

    def test_the_script_parses(self):
        self.assertEqual(0, subprocess.run(["sh", "-n", str(INSTALL)]).returncode)

    def test_help_documents_the_overrides(self):
        result = run("--help")
        self.assertEqual(0, result.returncode)
        for name in ("CERTORAIL_SOURCE", "CERTORAIL_INSTALLER", "CERTORAIL_INSTALL_DIR", "CERTORAIL_VENV"):
            self.assertIn(name, result.stdout)

    def test_an_unknown_argument_is_refused(self):
        result = run("--install-everything")
        self.assertEqual(1, result.returncode)
        self.assertIn("unknown argument", result.stderr)

    def test_a_source_that_is_not_certorail_is_refused(self):
        elsewhere = self.home / "not-certorail"
        elsewhere.mkdir()
        (elsewhere / "pyproject.toml").write_text('[project]\nname = "something-else"\n')
        result = run("--dry-run", env={"CERTORAIL_SOURCE": str(elsewhere)})
        self.assertEqual(1, result.returncode)
        self.assertIn("not a certorail checkout", result.stderr)

    def test_a_missing_source_is_refused(self):
        result = run("--dry-run", env={"CERTORAIL_SOURCE": str(self.home / "nowhere")})
        self.assertEqual(1, result.returncode)
        self.assertIn("no such directory", result.stderr)

    def test_an_unknown_installer_is_refused(self):
        result = run("--dry-run", env={"CERTORAIL_INSTALLER": "brew"})
        self.assertEqual(1, result.returncode)
        self.assertIn("must be uv, pipx or venv", result.stderr)

    def test_the_dry_run_plan_installs_nothing(self):
        result = run("--dry-run", env=self.venv_env)
        self.assertEqual(0, result.returncode, result.stderr)
        plan = result.stderr
        self.assertIn("python3 -m venv", plan)
        self.assertIn("pip install", plan)
        self.assertIn("Dry run: nothing was installed.", plan)
        self.assertFalse((self.home / "bin").exists())
        self.assertFalse((self.home / "share").exists())

    def test_the_dry_run_covers_the_pack_too(self):
        result = run("--dry-run", "--with-claude-pack", env={**self.venv_env, "HOME": str(self.home)})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("would write", result.stdout)
        self.assertIn("explain_hook.py", result.stdout)
        self.assertFalse((self.home / ".claude").exists())

    def test_uninstall_leaves_an_environment_it_did_not_create(self):
        stranger = self.home / "someones-venv"
        result = run(
            "--uninstall",
            "--dry-run",
            env={**self.venv_env, "CERTORAIL_VENV": str(stranger)},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("was left alone", result.stderr)
        self.assertNotIn(f"rm -rf {stranger}", result.stderr)

    def test_uninstall_removes_the_environment_it_did_create(self):
        result = run("--uninstall", "--dry-run", env=self.venv_env)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(f"would: rm -rf {self.venv_env['CERTORAIL_VENV']}", result.stderr)
        self.assertIn("certorail removed.", result.stderr)


if __name__ == "__main__":
    unittest.main()
