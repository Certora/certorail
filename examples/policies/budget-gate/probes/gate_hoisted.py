# Oversteps: one gate for the whole batch. It says nothing about the account's balance after
# the first submission, and the analysis will not pretend otherwise -- an environmental fact
# does not cross a loop boundary.
import pathlib

JOBS = pathlib.Path("jobs")


def main() -> None:
    workdir = pathlib.Path(".")
    certora.check("budget-gate", cwd=workdir)
    for spec in sorted(JOBS.glob("*.json")):
        result = certora.exec("submit-job", "submit", spec, cwd=workdir)
        print(f"{spec}: exit {result.returncode}")


main()
