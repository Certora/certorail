# Oversteps: the image reference is assembled at runtime, so there is no text to check.
import pathlib
import sys


def main() -> None:
    image = f"registry.example.com/example/{sys.argv[1]}"
    result = certora.exec("docker", "run", "--rm", image, cwd=pathlib.Path("."))
    print(f"report-builder exited with {result.returncode}")


main()
