# Oversteps: the policy declares one `cloudctl` subcommand, so `cloudctl` fails closed. No
# amount of checking makes a second subcommand available.
import pathlib


def main() -> None:
    result = certora.exec("cloudctl", "secrets", "list", cwd=pathlib.Path("."))
    print(f"cloudctl exited with {result.returncode}")


main()
