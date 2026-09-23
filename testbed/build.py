#!/usr/bin/env python3
"""Build (or rebuild) the testbed tree under ROOT, and the directory outside it the policy's
absolute grants name. Standard library only; run it as the user who will run the scenario.

    python3 build.py [ROOT]          # default /mnt/certorail-testbed

Idempotent: every directory the testbed owns is emptied and refilled, so a scenario run always
starts from the same state; anything else under ROOT (``lost+found``) is left alone.

The case-folding directory ``cf/`` is the exception, because the casefold attribute can only be
set on an EMPTY directory. The first run creates ``cf/`` empty and leaves it so; set the attribute
(``chattr +F ROOT/cf``, on an ext4 or f2fs made with the casefold feature, or a tmpfs mounted with
``casefold``) and run again. From then on ``cf/`` itself is never removed, only its contents, so
the attribute survives rebuilds. ``--no-casefold`` fills ``cf/`` without it: the folding probes
then report their control failing, which is the point of the control.
"""
import argparse
import fcntl
import os
import pathlib
import shutil
import struct
import sys

DEFAULT_ROOT = pathlib.Path("/mnt/certorail-testbed")
OUTSIDE = pathlib.Path("/tmp/certorail-testbed-outside")

# ioctl_iflags(2): FS_IOC_GETFLAGS, _IOR('f', 1, long), argument an int; FS_CASEFOLD_FL
_GETFLAGS = (2 << 30) | (struct.calcsize("l") << 16) | (ord("f") << 8) | 1
_CASEFOLD = 0x40000000

# the tree, relative to ROOT: a file's text, or a symlink target (a Link)


class Link:
    def __init__(self, target: pathlib.Path) -> None:
        self.target = target


TREE: dict[str, "str | Link"] = {
    # src/**: a tree grant
    "src/main.py": 'print("hello from src")\n',
    "src/util.py": "# needle: a reader finds this one\n",
    "src/link-out": Link(OUTSIDE / "unlisted.txt"),       # names, not objects: a name inside, a file outside
    # notes/**/<[a-z]+\.txt>: a pattern grant
    "notes/top.txt": "top\n",
    "notes/deep/ok.txt": "needle, and the pattern admits me\n",
    "notes/deep/NO.txt": "needle, but the pattern does not admit me\n",
    "notes/deep/ok.md": "the pattern does not admit me either\n",
    # catalog: a literal directory grant (its listing only)
    "catalog/item-a.txt": "needle in the catalog, listed but never opened\n",
    "catalog/item-b.txt": "item b\n",
    # drop/*: one level
    "drop/one.txt": "one\n",
    "drop/two.txt": "two\n",
    "drop/sub/three.txt": "three: a level too deep\n",
    # out/**: writable; out/keep protected
    "out/keep/final.txt": "keep\n",
    "out/hard-a.txt": "one file, two names\n",             # hard-linked to out/hard-b.txt below
    # repos/**: writable; **/.git protected
    "repos/alpha/README.md": "alpha\n",
    "repos/alpha/.git/config": "[core]\n\tbare = false\n",
    "repos/alpha/.git/HEAD": "ref: refs/heads/main\n",
    # data/*/x.txt: the one-component write grant
    "data/alpha/.keep": "",
    "data/beta/.keep": "",
    # under no grant at all
    "private/journal.txt": "needle, under no grant\n",
}
HARD_LINKS = {"out/hard-b.txt": "out/hard-a.txt"}
OWNED = ("src", "notes", "catalog", "drop", "out", "repos", "data", "private")

# cf/: the case-folding directory, filled only once it carries the attribute
CASEFOLD_TREE = {
    "cf/Stored.txt": "stored as Stored.txt\n",
    "cf/Docs/readme.txt": "docs\n",
    "cf/.git/config": "[core]\n",
}

OUTSIDE_TREE = {
    "unlisted.txt": "outside every grant\n",
    "elsewhere.txt": "outside every write grant\n",
    "abs/.keep": "",
    "alt/.keep": "",
}


def casefolded(directory: pathlib.Path) -> bool | None:
    """Does *directory* carry the casefold attribute? None when the filesystem cannot say."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        flags = fcntl.ioctl(fd, _GETFLAGS, bytes(8))
    except OSError:
        return None
    finally:
        os.close(fd)
    return bool(struct.unpack_from("i", flags)[0] & _CASEFOLD)


def fill(base: pathlib.Path, tree: dict[str, "str | Link"] | dict[str, str]) -> None:
    for rel, content in tree.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, Link):
            path.symlink_to(content.target)
        else:
            path.write_text(content)


def empty(directory: pathlib.Path) -> None:
    """Remove everything inside *directory*, keeping the directory itself (and its attributes)."""
    for entry in directory.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", type=pathlib.Path, default=DEFAULT_ROOT)
    parser.add_argument("--no-casefold", action="store_true", help="fill cf/ even without the casefold attribute")
    ns = parser.parse_args()
    root: pathlib.Path = ns.root

    root.mkdir(parents=True, exist_ok=True)
    for name in OWNED:
        target = root / name
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()
    shutil.rmtree(OUTSIDE, ignore_errors=True)
    fill(OUTSIDE, OUTSIDE_TREE)
    fill(root, TREE)
    for link, target in HARD_LINKS.items():
        os.link(root / target, root / link)

    cf = root / "cf"
    cf.mkdir(exist_ok=True)
    folded = True if sys.platform == "darwin" else casefolded(cf)  # APFS folds by default
    if folded or ns.no_casefold:
        empty(cf)
        fill(root, CASEFOLD_TREE)
        state = "casefolded" if folded else "NOT casefolded (--no-casefold): the folding probes' control will fail"
    elif folded is None:
        state = (
            "this filesystem has no casefold attribute to read (ext4, f2fs and tmpfs do): build on "
            "one made with the casefold feature, or pass --no-casefold"
        )
    elif any(cf.iterdir()):
        state = (
            "NOT casefolded and not empty, so the attribute cannot be set: empty it "
            f"(rm -r {cf}/* {cf}/.[!.]*), chattr +F {cf}, and run build.py again"
        )
    else:
        state = f"empty, waiting for the attribute: chattr +F {cf}, then run build.py again"
    print(f"testbed built under {root}")
    print(f"outside the root: {OUTSIDE}")
    print(f"cf/: {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
