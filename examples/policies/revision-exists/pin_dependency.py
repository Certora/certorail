# Conforming: the pin is a literal revision the checker confirms upstream, so certorail
# settles it while checking the program -- before anything is checked out.
import pathlib

WIDGET = pathlib.Path("deps") / "widget"
REVISION = "0123456789abcdef0123456789abcdef01234567"


def main() -> None:
    result = certora.exec("git", "checkout", "--detach", REVISION, cwd=WIDGET)
    print(f"git exited with {result.returncode}")


main()
