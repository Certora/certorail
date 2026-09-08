# Conforming: the gate is re-established inside the loop, immediately before each
# submission. The previous submission killed the fact, and so did the loop boundary.
import pathlib

JOBS = pathlib.Path("jobs")


def main() -> None:
    workdir = pathlib.Path(".")
    for spec in sorted(JOBS.glob("*.json")):
        certora.check("budget-gate", cwd=workdir)
        result = certora.exec("submit-job", "submit", spec, cwd=workdir)
        print(f"{spec}: exit {result.returncode}")


main()
