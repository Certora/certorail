# Oversteps: the check is real, but a call in between could have changed the world -- a
# different profile exported, a session refreshed, a token swapped. An environmental fact
# does not survive it.
import pathlib
import sys


def announce(environment: str) -> None:
    print(f"deploying to {environment}")


def main() -> None:
    environment = sys.argv[1]
    workdir = pathlib.Path(".")
    certora.check("credentials-for", environment=environment, cwd=workdir)
    announce(environment)
    result = certora.exec(
        "cloudctl", "deploy", "--manifest", "manifests/service.yaml", environment,
        cwd=workdir,
    )
    print(f"cloudctl exited with {result.returncode}")


main()
