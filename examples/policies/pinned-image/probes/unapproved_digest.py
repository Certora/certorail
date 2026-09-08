# Oversteps: pinned by digest, but not a digest this repository approved.
import pathlib

IMAGE = "registry.example.com/example/report-builder@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"


def main() -> None:
    result = certora.exec("docker", "run", "--rm", IMAGE, cwd=pathlib.Path("."))
    print(f"report-builder exited with {result.returncode}")


main()
