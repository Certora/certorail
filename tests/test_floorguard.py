"""The floor guard (``floorguard``): this machine's redlines in host mode, held in the process where
each path leads, for every operation. An audit hook cannot be removed, so the hook itself runs in a
child interpreter; the rules are also asked directly."""
import contextlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import certorail
from certorail.confinement import Lifts
from certorail.floorguard import Guard
from certorail.locations import parse_location
from certorail.world import Floor, Redline


class Fixture(unittest.TestCase):
    """A root with links into this machine's floor: ``attic`` never visible, ``archive/inner``
    never written."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(os.path.realpath(tmp.name))
        self.root = self.base / "root"
        for d in ("src/sub", "out", "attic", "archive/inner"):
            (self.root / d).mkdir(parents=True)
        (self.root / "src" / "main.txt").write_text("original\n")
        (self.root / "attic" / "box.txt").write_text("boxed\n")
        (self.root / "out" / "lnk").symlink_to(self.root / "src")                     # anywhere: followed
        (self.root / "src" / "to-attic").symlink_to(self.root / "attic" / "box.txt")   # into the floor
        (self.root / "out" / "to-inner").symlink_to(self.root / "archive" / "inner")   # into the floor
        self.floor = Floor(never_write=(Redline(self.root / "archive" / "inner"),), never_visible=(Redline(self.root / "attic"),))
        self.guard = Guard.of(self.floor)
        self.enterContext(contextlib.chdir(self.root))


class TestRules(Fixture):
    def refusal(self, event: str, *args: object) -> str | None:
        return self.guard.refusal(event, args)

    def test_names_are_followed_wherever_they_lead(self) -> None:
        self.assertIsNone(self.refusal("open", "out/lnk/a.txt", "w", os.O_WRONLY | os.O_CREAT))
        self.assertIsNone(self.refusal("open", "src/main.txt", "r", 0))
        self.assertIsNone(self.refusal("os.listdir", "."))  # a hidden name below is only a name

    def test_never_visible_wherever_a_name_leads(self) -> None:
        why = self.refusal("open", "src/to-attic", "r", 0) or ""
        self.assertIn(f"which leads to {self.root / 'attic' / 'box.txt'}", why)
        self.assertIn("never-visible", why)
        for event, args in (("open", ("attic/box.txt", "a", 0)), ("os.listdir", ("attic",)),
                            ("os.scandir", ("ATTIC",))):  # names compared folded
            with self.subTest(event=event, args=args):
                self.assertIn("never-visible", self.guard.refusal(event, args) or "")

    def test_never_write_and_what_carries_it(self) -> None:
        self.assertIn("never-write", self.refusal("open", "out/to-inner/x", "w", 0) or "")
        self.assertIsNone(self.refusal("open", "archive/other", "w", 0))
        # a rename, a removal or a link above it would carry it off; an empty directory would not
        self.assertIn("cannot be moved", self.refusal("os.rename", "archive", "moved", -1, -1) or "")
        self.assertIn("cannot be moved", self.refusal("os.symlink", "x", "archive", -1) or "")
        self.assertIsNone(self.refusal("os.mkdir", "archive/fresh", 0o777, -1))

    def test_an_entry_is_the_link_itself(self) -> None:
        self.assertIsNone(self.refusal("os.remove", "src/to-attic", -1))     # removes the link, not the box
        self.assertIn("never-visible", self.refusal("open", "src/to-attic", "a", 0) or "")

    def test_what_names_no_path(self) -> None:
        self.assertIsNone(self.refusal("open", 3, "w", os.O_WRONLY))           # a descriptor
        self.assertIn("directory descriptor", self.refusal("os.mkdir", "x", 0o777, 5) or "")
        self.assertIsNone(self.refusal("os.system", "ls"))                     # not a path event

    def test_the_document_round_trips(self) -> None:
        self.assertEqual(Guard.parse(self.guard.document()), self.guard)
        self.assertTrue(Guard.of(Floor()).empty)
        lifted = Guard.of(self.floor, Lifts((parse_location("attic/box.txt"),), (parse_location("archive/inner/**"),)), self.root)
        self.assertEqual(Guard.parse(lifted.document()), lifted)

    def test_a_lift_is_the_programs_way_past_a_redline(self) -> None:
        # [system.exec] lift-read / lift-write, relative to the root: readable and read-only, or writable
        guard = Guard.of(self.floor, Lifts((parse_location("attic/box.txt"),), (parse_location("archive/inner/**"),)), self.root)
        self.assertIsNone(guard.refusal("open", ("attic/box.txt", "r", 0)))
        self.assertIsNone(guard.refusal("open", ("src/to-attic", "r", 0)))  # where the name leads, lifted
        self.assertIn("never-visible", guard.refusal("open", ("attic/box.txt", "a", 0)) or "")  # read-only
        self.assertIn("never-visible", guard.refusal("os.listdir", ("attic",)) or "")  # the lift names the file alone
        self.assertIsNone(guard.refusal("open", ("archive/inner/x", "w", 0)))
        # a lifted redline still cannot be carried off
        self.assertIn("cannot be moved", guard.refusal("os.rename", ("archive", "moved", -1, -1)) or "")


# the hook itself, in a child interpreter: each operation the subset can reach, then the rest of
# the events the guard reads, so every argument layout is the running interpreter's
CHILD = r'''
import os, pathlib, sys
sys.path.insert(0, sys.argv[1])
import certorail.floorguard
guard = certorail.floorguard.Guard.parse(pathlib.Path(sys.argv[2]).read_text())
sys.dont_write_bytecode = True
certorail.floorguard.install(guard)
P = pathlib.Path

def attempt(name, fn):
    try:
        fn()
    except PermissionError as e:
        print(name, "refused", str(e).replace("\n", " "))
    except OSError as e:
        print(name, type(e).__name__)
    else:
        print(name, "ok")

attempt("read", lambda: open("src/main.txt").read())
attempt("read-hidden", lambda: open("attic/box.txt").read())
attempt("read-hidden-through-link", lambda: open("src/to-attic").read())
attempt("write", lambda: open("out/a.txt", "w").close())
attempt("write-through-link", lambda: open("out/lnk/b.txt", "w").close())
attempt("write-text", lambda: P("out/c.txt").write_text("c"))
attempt("write-never-write", lambda: open("archive/inner/x", "w"))
attempt("write-never-write-through-link", lambda: os.open("out/to-inner/y", os.O_WRONLY | os.O_CREAT))
attempt("mkdir-parents", lambda: P("out/deep/er").mkdir(parents=True))
attempt("mkdir-never-write", lambda: P("archive/inner/new").mkdir())
attempt("touch", lambda: P("out/a.txt").touch())
attempt("touch-never-write", lambda: P("out/to-inner/z").touch())
attempt("chmod", lambda: P("out/a.txt").chmod(0o644))
attempt("replace", lambda: P("out/a.txt").replace("out/d.txt"))
attempt("replace-into-never-write", lambda: P("out/d.txt").replace("archive/inner/d.txt"))
attempt("listdir", lambda: os.listdir("src"))
attempt("listdir-hidden", lambda: os.listdir("attic"))
attempt("iterdir-hidden", lambda: list(P("attic").iterdir()))
print("walk-hidden", "empty" if not list(os.walk("attic")) else "listed")  # walk swallows the error
attempt("import", lambda: __import__("difflib"))
attempt("remove-hidden", lambda: os.remove("attic/box.txt"))
attempt("rmdir-never-write", lambda: os.rmdir("archive/inner"))
attempt("rename-above", lambda: os.rename("archive", "out/moved"))
attempt("link-hidden", lambda: os.link("attic/box.txt", "out/hard"))
attempt("truncate-never-write", lambda: os.truncate("out/to-inner", 0))
fd = os.open("out", os.O_RDONLY)
attempt("dir-fd", lambda: os.mkdir("y", dir_fd=fd))
'''


class TestHook(Fixture):
    def test_every_operation(self) -> None:
        (self.base / "guard.json").write_text(self.guard.document())
        parent = str(pathlib.Path(certorail.__file__).resolve().parent.parent)
        done = subprocess.run([sys.executable, "-I", "-c", CHILD, parent, str(self.base / "guard.json")],
                              cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        got: dict[str, str] = {}
        for line in done.stdout.splitlines():
            name, _, rest = line.partition(" ")
            got[name] = rest
        self.assertEqual({name for name, rest in got.items() if rest == "ok"}, {
            "read", "write", "write-through-link", "write-text", "mkdir-parents", "touch", "chmod", "replace",
            "listdir", "import",
        }, got)
        self.assertEqual({name for name, rest in got.items() if rest.startswith("refused")}, {
            "read-hidden", "read-hidden-through-link", "write-never-write", "write-never-write-through-link",
            "mkdir-never-write", "touch-never-write", "replace-into-never-write", "listdir-hidden",
            "iterdir-hidden", "remove-hidden", "rmdir-never-write", "rename-above", "link-hidden",
            "truncate-never-write", "dir-fd",
        }, got)
        self.assertEqual(got["walk-hidden"], "empty")
        # refused before the operation, so nothing of it happened; the link out was followed
        self.assertFalse((self.root / "archive" / "inner" / "x").exists())
        self.assertFalse((self.root / "archive" / "inner" / "y").exists())
        self.assertTrue((self.root / "src" / "b.txt").exists())
        self.assertEqual((self.root / "attic" / "box.txt").read_text(), "boxed\n")
        self.assertIn("certorail:", got["read-hidden"])


if __name__ == "__main__":
    unittest.main()
