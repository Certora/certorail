# Oversteps: the gate is run somewhere the policy does not let it run. A checker's cwd is
# part of what it means, so it is checked too.
import pathlib

JOBS = pathlib.Path("jobs")


def main() -> None:
    workdir = pathlib.Path(".")
    for spec in sorted(JOBS.glob("*.json")):
        certora.check("budget-gate", cwd=JOBS)
        result = certora.exec("submit-job", "submit", spec, cwd=workdir)
        print(f"{spec}: exit {result.returncode}")


main()
