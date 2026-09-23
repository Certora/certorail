"""The Seatbelt lowering agrees with the analysis. The emitted regex core means the same thing to
Python's ``re`` as to POSIX ERE, so the agreement can be checked here, on generated locations and
paths: a path lies within a location exactly when the location's regex fullmatches it (a grant),
and at or below one exactly when the protection's regex does."""
import pathlib
import random
import re
import unittest

from certorail.analysis import (
    ANY_NAME,
    Component,
    DirSplat,
    LocationFact,
    Matching,
    Named,
    OneOf,
    RegexLit,
    StaticPath,
    location_le,
)
from certorail.sandbox.seatbelt import pattern_regex

ROOT = pathlib.Path("/certorail-agreement-root")
NAMES = ["a", "b", "ab", "abab", "src", "x", "x.md", "q.md", ".hidden", "a-b", "a+b", "a.b", "sub"]
REGEXES = [
    ".*\\.md", "[^.].*", "[a-z]+", "a|b", "^x$", "(?:ab)*", "[!-~]+", "a.b", "x?", "[^/]+", "(?:a+)+b?",
]


def component(rng: random.Random) -> Component:
    kind = rng.randrange(4)
    if kind == 0:
        return Named(rng.choice(NAMES))
    if kind == 1:
        return ANY_NAME
    if kind == 2:
        return OneOf(frozenset(rng.sample(NAMES, 2)))
    return Matching(RegexLit(rng.choice(REGEXES)))


def location(rng: random.Random) -> LocationFact:
    if rng.random() < 0.5:
        return StaticPath(tuple(component(rng) for _ in range(rng.randint(1, 3))))
    prefix = tuple(component(rng) for _ in range(rng.randint(0, 2)))
    leaf = None if rng.random() < 0.4 else component(rng)
    return DirSplat(prefix, leaf)


def within(names: list[str], loc: LocationFact) -> bool:
    return location_le(StaticPath(tuple(Named(n) for n in names)), loc)


class TestAgreement(unittest.TestCase):
    def check(self, below: bool) -> int:
        rng = random.Random(20260923 + below)
        real = str(ROOT)
        compared = 0
        for _ in range(400):
            loc = location(rng)
            regex = pattern_regex(loc, ROOT, below=below)
            if regex is None:
                continue  # refused: the location is omitted, never approximated
            compiled = re.compile(regex)
            for _ in range(25):
                names = [rng.choice(NAMES) for _ in range(rng.randint(1, 4))]
                path = real + "/" + "/".join(names)
                if below:
                    expected = any(within(names[:k], loc) for k in range(1, len(names) + 1))
                else:
                    expected = within(names, loc)
                with self.subTest(location=repr(loc), path=path):
                    self.assertEqual(compiled.fullmatch(path) is not None, expected, regex)
                compared += 1
        return compared

    def test_grants(self) -> None:
        self.assertGreater(self.check(below=False), 1000)

    def test_protections(self) -> None:
        self.assertGreater(self.check(below=True), 1000)


if __name__ == "__main__":
    unittest.main()
