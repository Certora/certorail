# Conforming: the account behind the credentials is confirmed for the named environment
# immediately before the deploy, with nothing in between to invalidate it.
import pathlib
import sys


def main() -> None:
    if len(sys.argv[1:]) != 1:
        print("usage: deploy.py <environment>")
        return
    # `sys.argv[1]` is known to be a string, so a check has a value to attach its fact to.
    # `sys.argv[1:][0]` is not: the analysis knows nothing about it, and a check on it
    # establishes nothing.
    environment = sys.argv[1]
    workdir = pathlib.Path(".")

    certora.check("credentials-for", environment=environment, cwd=workdir)
    result = certora.exec(
        "cloudctl", "deploy", "--manifest", "manifests/service.yaml", environment,
        cwd=workdir,
    )
    print(f"cloudctl exited with {result.returncode}")


main()
