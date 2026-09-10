# Oversteps: a well-formed commit id that is not on the upstream default branch.
import pathlib

WIDGET = pathlib.Path("deps") / "widget"
REVISION = "ffffffffffffffffffffffffffffffffffffffff"


def main() -> None:
    result = certora.exec("git", "checkout", "--detach", REVISION, cwd=WIDGET)
    print(f"git exited with {result.returncode}")


main()
