"""Policy lints: legal, probably unintended, and said to the policy's author."""
import os
import pathlib
import tempfile
import unittest

from certorail.lint import lint
from certorail.policy import Policy


class TestLint(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(tmp.name))
        (self.root / "src").mkdir()
        (self.root / "notes.txt").write_text("x\n")

    def kinds(self, policy: Policy, platform: str = "linux") -> list[str]:
        return [f.kind for f in lint(policy, self.root, platform=platform)]

    def test_an_absolute_grant_into_the_root_shadows_a_relative_protection(self) -> None:
        parent = self.root.parent
        policy = Policy.allow(write=["**", f"{parent}/**"], no_write=["src/keep"])
        self.assertEqual(self.kinds(policy), ["shadowed-protection"])
        # an absolute grant elsewhere does not reach the root
        self.assertEqual(self.kinds(Policy.allow(write=["**", "/srv/elsewhere/**"], no_write=["src/keep"])), [])

    def test_a_literal_directory_grant_is_probably_a_subtree(self) -> None:
        self.assertEqual(self.kinds(Policy.allow(read=["src", "notes.txt"])), ["literal-directory"])
        self.assertEqual(self.kinds(Policy.allow(read=["src/**"])), [])

    def test_a_spelling_the_directory_stores_differently(self) -> None:
        (self.root / "Docs").mkdir()
        policy = Policy.allow(read=["docs/**"])
        self.assertEqual(self.kinds(policy, platform="darwin"), ["spelling"])
        self.assertEqual(self.kinds(policy, platform="linux"), [])  # a case-sensitive filesystem: another name


if __name__ == "__main__":
    unittest.main()
