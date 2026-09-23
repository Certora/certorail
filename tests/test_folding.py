"""Whether a directory's lookups are exact, as its filesystem declares (``certorail.folding``)."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from certorail import folding


@unittest.skipUnless(sys.platform == "linux", "fstatfs and the inode attribute ioctl are Linux's")
class TestFolding(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.fd = os.open(self.dir, os.O_PATH | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def test_the_type_is_the_one_stat_reports(self) -> None:
        stat = shutil.which("stat")
        if stat is None:
            self.skipTest("no stat(1) to compare with")
        reported = subprocess.run([stat, "-f", "-c", "%t", self.dir], capture_output=True, text=True, check=True)
        self.assertEqual(folding.fs_type(self.fd), int(reported.stdout.strip(), 16))

    def test_known_filesystems_are_exact_and_the_rest_cannot_say(self) -> None:
        kind = folding.fs_type(self.fd)
        known = kind in folding._NEVER_FOLDS or kind in folding._FOLDS_PER_DIRECTORY
        # a fresh temporary directory carries no casefold attribute
        self.assertEqual(folding.exact_lookups(self.fd), known)

    def test_a_failed_call_cannot_say(self) -> None:
        closed = os.open(self.dir, os.O_PATH | os.O_DIRECTORY)
        os.close(closed)
        self.assertIsNone(folding.fs_type(closed))
        self.assertFalse(folding.exact_lookups(closed))


if __name__ == "__main__":
    unittest.main()
