"""``certorail --describe``: the loaded policy rendered as the program author's interface."""
import contextlib
import io
import pathlib
import tempfile
import unittest

from certorail import markers
from certorail.describe import describe
from certorail.host import main
from certorail.policy import (
    Policy,
    atom,
    constraint,
    flagset,
    hole,
    network,
    param,
    program,
    pure,
    splice,
    validation,
)
from certorail.templates import Each, Flags, Token

POLICY = Policy.allow(
    read=[markers.within("repos"), markers.within("reports")],
    write=[markers.within("repos", leaf=markers.matches(r"\w+\.md"))],
    atoms=[atom("no-flag", markers.matches(r"[^-].*"))],
    validations=[
        validation(
            "org-repo", argv=("/x/org-checkout",), cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]}, effect_free=True,
        ),
        validation(
            "vetted", argv=("test", param("value"), "!=", "x"), params=("value",),
            establishes={"value": [pure("vetted")]}, effect_free=True,
        ),
    ],
    programs=[
        program(
            "git", cwd=markers.within("repos"), requires=["org-checkout"],
            argv=["git", "push", "origin", hole("BRANCH")],
            holes={"BRANCH": Token(constraint(atoms=["no-flag"]))},
        ),
        program("git", cwd=markers.within("repos"), subcommand="log"),
        program(
            "tar", cwd=".", argv=["tar", splice("FLAGS"), "-f", hole("ARCHIVE"), splice("FILES")],
            holes={
                "FLAGS": Flags(flagset(bare=["-c", "-z"], valued={"-C": constraint(location=markers.within("repos"))})),
                "ARCHIVE": Token(constraint(location=markers.within("archives"))),
                "FILES": Each(constraint(location=markers.within("repos")), min=1),
            },
        ),
    ],
    network=[network("api.github.com", methods=["GET"], requires=["vetted"])],
)


class TestDescribe(unittest.TestCase):
    def setUp(self) -> None:
        self.text = describe(POLICY, "policy.toml", "/srv/work")

    def test_the_interface_is_all_there(self) -> None:
        for expected in (
            "governs /srv/work",
            "- read: repos/**, reports/**",
            r"- write: repos/**/</\w+\.md/>",
            "- list: nothing",
            "Notation: <...> marks a value",
            "- git push origin BRANCH",
            "cwd validated by org-checkout",
            "BRANCH: <validated no-flag>",
            "- git log\n",
            "exactly these words: no further arguments",
            "- built in (every policy",
            "not-option: the text does not begin with '-'",
            "- tar FLAGS... -f ARCHIVE FILES...",
            "FLAGS... ends at the first positional that is not a flag; ARCHIVE begins there",
            "inserted by the host, do not spell: -f",
            "bare: -c -z",
            "-C <path within repos/**>",
            "FILES...: each <path within repos/**>, at least 1",
            'certora.check("org-repo", cwd=<path within repos/**>)',
            "establishes on cwd: org-checkout (environmental)",
            'certora.check("vetted", value=<str>)',
            'certora.check_single("vetted", value)',
            "- no-flag: </[^-].*/>",
            "- vetted: a property of the value's text",
            "- org-checkout: a property of the environment",
            "- GET https://api.github.com; the URL must be validated by vetted",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.text)

    def test_the_cli_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = pathlib.Path(tmp) / "p.toml"
            policy.write_text(
                'policy-version = 1\n[filesystem]\nread = ["**"]\n[[program]]\nname = "gh"\ncwd = "."\n',
                encoding="utf-8",
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["--describe", "--policy", str(policy), "--root", tmp])
            self.assertEqual(code, 0)
            self.assertIn("## Programs", out.getvalue())
            self.assertIn("- gh\n", out.getvalue())
            self.assertIn("exactly these words", out.getvalue())
            self.assertIn(f"Policy: {policy}", out.getvalue())

    def test_describe_takes_no_program(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--describe", "-c", "pass"])


if __name__ == "__main__":
    unittest.main()
