"""The host CLI: the -c inline-source path (the agentic entry) and its mutex with a file
argument. Runs go through --no-jail so the suite needs no srt."""
import pathlib
import tempfile
import unittest

from certorail.host import main


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
