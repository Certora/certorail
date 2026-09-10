# Oversteps: the environment name is taken on trust. Nothing has asked the provider whether
# the credentials in effect belong to that environment.
import pathlib
import sys


def main() -> None:
    environment = sys.argv[1]
    workdir = pathlib.Path(".")
    result = certora.exec(
        "cloudctl", "deploy", "--manifest", "manifests/service.yaml", environment,
        cwd=workdir,
    )
    print(f"cloudctl exited with {result.returncode}")


main()
