# Conforming: the account behind the credentials is confirmed for the named environment
# immediately before the deploy, with nothing in between to invalidate it.
import pathlib
import sys


def main() -> None:
    if len(sys.argv[1:]) != 1:
        print("usage: deploy.py <environment>")
        return
    # Indexing `sys.argv` gives a value the analysis knows is a string, so a check has
    # something to attach its fact to. Binding the slice to a name first --
    # `args = sys.argv[1:]` and then `args[0]` -- does not: the element is unknown, the
    # check establishes nothing, and the exec is denied.
    environment = sys.argv[1]
    workdir = pathlib.Path(".")

    certora.check("credentials-for", environment=environment, cwd=workdir)
    result = certora.exec(
        "cloudctl", "deploy", "--manifest", "manifests/service.yaml", environment,
        cwd=workdir,
    )
    print(f"cloudctl exited with {result.returncode}")


main()
