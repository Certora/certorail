# Oversteps: a moving tag. Nothing about `:latest` is stable, so it carries neither atom.
import pathlib

IMAGE = "registry.example.com/example/report-builder:latest"


def main() -> None:
    result = certora.exec("docker", "run", "--rm", IMAGE, cwd=pathlib.Path("."))
    print(f"report-builder exited with {result.returncode}")


main()
