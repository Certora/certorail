"""The host CLI: the -c inline-source path (the agentic entry) and its mutex with a file
argument. Runs go through --no-jail so the suite needs no srt."""
import pathlib
import tempfile
import unittest

from certorail.host import main, run_main


class TestRunEntryPoint(unittest.TestCase):
    """``certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]``: a closed interface. Nothing
    but --check is an option, everything after the program is a program argument, and the
    ambient policy is the only policy -- so a shell allow-rule on the command's prefix cannot be
    widened from inside."""

    def test_check_inline_and_from_a_file(self) -> None:
        self.assertEqual(run_main(["--check", "-c", "x = 1 + 1\n"]), 0)
        self.assertEqual(run_main(["--check", "-c", "from os import path\n"]), 1)
        self.assertEqual(run_main(["--check", "-c", "def (\n"]), 2)
        with tempfile.TemporaryDirectory() as tmp:
            prog = pathlib.Path(tmp) / "p.py"
            prog.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(run_main(["--check", str(prog)]), 0)
            self.assertEqual(run_main(["--check", str(pathlib.Path(tmp) / "missing.py")]), 2)

    def test_everything_after_the_program_is_a_program_argument(self) -> None:
        # the words that would widen `certorail` are data here, so the check still passes
        widening = ["--policy", "evil.toml", "--root", "/", "--no-jail", "--check", "--", "-x"]
        self.assertEqual(run_main(["--check", "-c", "x = 1\n", *widening]), 0)
        with tempfile.TemporaryDirectory() as tmp:
            prog = pathlib.Path(tmp) / "p.py"
            prog.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(run_main(["--check", str(prog), *widening]), 0)

    def test_no_option_but_check_exists_and_it_comes_first(self) -> None:
        for argv in (
            ["--policy", "evil.toml", "--check", "-c", "x = 1\n"],
            ["--root", "/", "--check", "-c", "x = 1\n"],
            ["--no-jail", "-c", "x = 1\n"],
            ["--check", "-c"],
            ["--check"],
            [],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(run_main(argv), 2)
        # after -c, --check is the source text: the program `--check` (an expression over an
        # unbound name) is analysed and accepted, and nothing here read it as an option
        self.assertEqual(run_main(["--check", "-c", "--check", "x = 1\n"]), 0)


class TestInlineSource(unittest.TestCase):
    def test_inline_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                main(["-c", "print('hi')", "--root", tmp, "--no-jail"]), 0
            )

    def test_inline_check_accepts(self) -> None:
        code = main(["-c", "x = 1 + 1\n", "--check"])
        self.assertEqual(code, 0)

    def test_inline_check_rejects(self) -> None:
        # a bare from-import: rejected by the subset's lexical rules (and pleasantly
        # innocuous, unlike the more exciting things the checker also rejects)
        code = main(["-c", "from os import path\n", "--check"])
        self.assertEqual(code, 1)

    def test_inline_syntax_error(self) -> None:
        self.assertEqual(main(["-c", "def (\n", "--check"]), 2)

    def test_a_file_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prog = pathlib.Path(tmp) / "p.py"
            prog.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(main([str(prog), "--check"]), 0)

    def test_inline_source_takes_arguments(self) -> None:
        # with -c every positional is an argument for the program, as with `python -c`; `--`
        # passes option-like ones through
        with tempfile.TemporaryDirectory() as tmp:
            source = 'import pathlib\nimport sys\npathlib.Path("argv.txt").write_text(" ".join(sys.argv[1:]))\n'
            self.assertEqual(main(["-c", source, "--root", tmp, "--no-jail", "--", "a", "-b", "--check"]), 0)
            self.assertEqual((pathlib.Path(tmp) / "argv.txt").read_text(), "a -b --check")
            self.assertEqual(main(["-c", source, "first", "--root", tmp, "--no-jail"]), 0)
            self.assertEqual((pathlib.Path(tmp) / "argv.txt").read_text(), "first")

    def test_neither_is_an_error(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            main(["--check"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
