# Conforming: the image is a digest-pinned literal on the approved list, so both atoms are
# discharged while the program is being checked -- before anything runs.
import pathlib

IMAGE = "registry.example.com/example/report-builder@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def main() -> None:
    result = certora.exec("docker", "run", "--rm", IMAGE, cwd=pathlib.Path("."))
    print(f"report-builder exited with {result.returncode}")


main()
