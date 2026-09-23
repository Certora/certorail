"""The empty string names nothing. It is not the root, it is not a path component, and a piece of
text that may be empty never decides what the whole text begins with."""
import unittest

from certorail import markers
from certorail.analysis import Concat, Exact, RegexLit, may_start_with
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy
from certorail.policyfile import from_data

HEADER = "import re\nimport sys\nimport pathlib\n"

ROOT_ONLY = Policy.allow(read=[markers.within(".")], write=[markers.within(".")])

ECHO = from_data({
    "policy-version": 1,
    "filesystem": {"read": ["**"]},
    "program": [{"name": "echo", "argv": ["echo", "${X}"], "cwd": ".", "holes": {"X": {"any": True}}}],
})


def outcome(body: str, policy: Policy = ROOT_ONLY) -> Accepted | Rejected:
    return host_check(HEADER + body, "<t>", policy)


class TestPrefixes(unittest.TestCase):
    def test_a_piece_that_may_be_empty_hands_the_question_on(self) -> None:
        self.assertTrue(may_start_with(Concat([Exact(""), RegexLit(".*")]), "/"))
        self.assertTrue(may_start_with(Concat([RegexLit("a*"), Exact("-v")]), "-"))
        self.assertFalse(may_start_with(Concat([RegexLit("a+"), Exact("-v")]), "-"))
        self.assertFalse(may_start_with(Concat([Exact("docs"), RegexLit(".*")]), "/"))

    def test_a_prefix_may_span_pieces(self) -> None:
        self.assertTrue(may_start_with(Concat([Exact("-"), RegexLit(".*")]), "--"))
        self.assertFalse(may_start_with(Concat([Exact("-"), Exact("v")]), "--"))


class TestPrograms(unittest.TestCase):
    def test_an_empty_prefix_guard_proves_nothing(self) -> None:
        got = outcome(
            'x = sys.argv[1]\n'
            'assert x.startswith("")\n'
            'assert ".." not in x\n'
            'print(open(x).read())\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_empty_text_keeps_a_leading_slash(self) -> None:
        got = outcome('e = ""\nprint(open(e + "/srv/notes.txt").read())\n')
        assert isinstance(got, Rejected)
        self.assertTrue(any("/srv/notes.txt" in d.reason for d in got.denials), got.describe("<t>"))

    def test_a_possibly_empty_name_is_no_component(self) -> None:
        # x may be "" or ".", so out/x/f.txt may be out/f.txt: within out/**, not out/*/f.txt
        policy = Policy.allow(read=[markers.within(".")], write=["out/*/f.txt"])
        got = outcome(
            'x = sys.argv[1]\n'
            'if "/" not in x and x != "..":\n'
            '    (pathlib.Path("out") / x / "f.txt").write_text("hi")\n',
            policy,
        )
        self.assertIsInstance(got, Rejected)

    def test_a_listed_name_still_is_one(self) -> None:
        policy = Policy.allow(read=[markers.within(".")], write=["out/*/f.txt"])
        got = outcome(
            'for name in sorted(pathlib.Path("out").iterdir()):\n'
            '    (name / "f.txt").write_text("hi")\n',
            policy,
        )
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")

    def test_a_nullable_head_does_not_pass_the_dash_guard(self) -> None:
        got = outcome(
            'p = sys.argv[1]\n'
            'if re.fullmatch(r"a*", p):\n'
            '    certora.exec("echo", p + "-v", cwd=".")\n',
            ECHO,
        )
        assert isinstance(got, Rejected)
        self.assertTrue(any("may begin with '-'" in d.reason for d in got.denials))

    def test_a_non_empty_head_does(self) -> None:
        got = outcome(
            'p = sys.argv[1]\n'
            'if re.fullmatch(r"a+", p):\n'
            '    certora.exec("echo", p + "-v", cwd=".")\n',
            ECHO,
        )
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


if __name__ == "__main__":
    unittest.main()
