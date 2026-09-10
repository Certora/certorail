# Oversteps: a branch name is not a pin. It resolves to whatever upstream points it at next.
import pathlib

WIDGET = pathlib.Path("deps") / "widget"
REVISION = "main"


def main() -> None:
    result = certora.exec("git", "checkout", "--detach", REVISION, cwd=WIDGET)
    print(f"git exited with {result.returncode}")


main()
