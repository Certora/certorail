# Oversteps: the pin comes from the command line, so there is no text for the checker to
# settle during analysis. The rule admits no argument it cannot vouch for.
import pathlib
import sys

WIDGET = pathlib.Path("deps") / "widget"


def main() -> None:
    result = certora.exec("git", "checkout", "--detach", sys.argv[1], cwd=WIDGET)
    print(f"git exited with {result.returncode}")


main()
