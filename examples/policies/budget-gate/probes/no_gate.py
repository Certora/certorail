# Oversteps: no gate at all.
import pathlib

JOBS = pathlib.Path("jobs")


def main() -> None:
    workdir = pathlib.Path(".")
    for spec in sorted(JOBS.glob("*.json")):
        result = certora.exec("submit-job", "submit", spec, cwd=workdir)
        print(f"{spec}: exit {result.returncode}")


main()
