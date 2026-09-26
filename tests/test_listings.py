"""Listing a directory is reading it, and a traversal that descends lists every directory at or
below where it starts: ``os.walk``, ``rglob``, and a ``glob`` whose pattern reaches past the first
level are held to a read grant over that whole subtree. ``iterdir`` and a one-level ``glob`` list
the directory alone."""
import unittest

from certorail.host import Accepted, Rejected, check
from certorail.policy import Policy

WALK = 'import os\nfor dirpath, dirnames, filenames in os.walk("notes"):\n    print(dirpath)\n'


def traversal(call: str) -> str:
    return f'import pathlib\nfor p in pathlib.Path("notes").{call}:\n    print(p)\n'


class TestListings(unittest.TestCase):
    LISTING = Policy.allow(read=["notes"])       # the directory's listing, and nothing below it
    SUBTREE = Policy.allow(read=["notes/**"])

    def verdict(self, source: str, policy: Policy) -> Accepted | Rejected:
        return check(source, "p.py", policy)

    def test_a_traversal_that_descends_reads_the_subtree(self) -> None:
        for source in (WALK, traversal('rglob("*.md")'), traversal('glob("sub/*.md")'), traversal('glob("**/*.md")')):
            with self.subTest(source=source):
                refused = self.verdict(source, self.LISTING)
                assert isinstance(refused, Rejected), refused
                self.assertIn("notes/**", refused.describe("p.py")[-1])
                self.assertIsInstance(self.verdict(source, self.SUBTREE), Accepted)

    def test_one_level_lists_the_directory_alone(self) -> None:
        for source in (traversal("iterdir()"), traversal('glob("*.md")')):
            with self.subTest(source=source):
                self.assertIsInstance(self.verdict(source, self.LISTING), Accepted)


if __name__ == "__main__":
    unittest.main()
