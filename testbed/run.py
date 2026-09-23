#!/usr/bin/env python3
"""Run the testbed scenario (scenario.toml) against a built root: every probe, every policy that
must not load, every lint. Standard library only.

    python3 run.py [--root ROOT] [--certorail CMD] [--no-build] [-v] [NAME ...]

Rebuilds the tree first (build.py: probes change it) unless --no-build, starts serve.py while
the probes that need the network run, and prints one line per item -- PASS, FAIL with what
differed, or SKIP with why -- exiting 1 if anything failed. NAMEs select probes by name.
"""
import argparse
import pathlib
import shlex
import socket
import subprocess
import sys
import time
import tomllib

import build

TESTBED = pathlib.Path(__file__).resolve().parent
PLATFORM = "darwin" if sys.platform == "darwin" else "linux"


class Runner:
    def __init__(self, root: pathlib.Path, certorail: list[str], verbose: bool) -> None:
        self.root = root
        self.certorail = certorail
        self.verbose = verbose
        self.failed = 0

    def certorail_run(self, *words: str | pathlib.Path) -> subprocess.CompletedProcess[str]:
        argv = [*self.certorail, *(str(w) for w in words)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)

    def report(self, verdict: str, name: str, detail: str = "", result: subprocess.CompletedProcess[str] | None = None) -> None:
        if verdict == "FAIL":
            self.failed += 1
        print(f"{verdict:4}  {name}" + (f": {detail}" if detail else ""))
        if result is not None and (self.verbose or verdict == "FAIL"):
            for stream, text in (("stdout", result.stdout), ("stderr", result.stderr)):
                for line in text.rstrip().splitlines():
                    print(f"        {stream}| {line}")

    # -- probes ---------------------------------------------------------------------------

    def probe(self, probe: dict, casefold: bool) -> None:
        name = probe["name"]
        if PLATFORM not in probe.get("platforms", [PLATFORM]):
            return self.report("SKIP", name, f"not on {PLATFORM}")
        if "casefold" in probe.get("needs", []) and not casefold:
            return self.report("SKIP", name, "cf/ does not fold (README: chattr +F, then build.py again)")
        program = TESTBED / probe["program"]
        result = self.certorail_run(
            "run", "--root", self.root, "--policy", TESTBED / probe.get("policy", "policy.toml"),
            program, "--", *probe.get("args", []),
        )
        rejected = f"{program}: rejected" in result.stderr
        if probe["check"] != "accepted":
            kind = "violation" if probe["check"] == "violation" else "denied"
            if not rejected:
                return self.report("FAIL", name, f"expected {kind}, it ran", result)
            if f": {kind}: " not in result.stderr or probe["because"] not in result.stderr:
                return self.report("FAIL", name, f"rejected, but not {kind} because {probe['because']!r}", result)
            return self.report("PASS", name, f"{kind} ({probe['covers']})", result)
        if rejected:
            return self.report("FAIL", name, "expected to pass the analysis, it was rejected", result)
        expected = probe["darwin"] if PLATFORM == "darwin" and "darwin" in probe else probe.get("run", {})
        problems = []
        if "exit" in expected and result.returncode != expected["exit"]:
            problems.append(f"exit {result.returncode}, expected {expected['exit']}")
        problems += [f"stdout lacks {s!r}" for s in expected.get("stdout-has", []) if s not in result.stdout]
        problems += [f"stdout has {s!r}" for s in expected.get("stdout-lacks", []) if s in result.stdout]
        problems += [f"stderr lacks {s!r}" for s in expected.get("stderr-has", []) if s not in result.stderr]
        if problems:
            return self.report("FAIL", name, "; ".join(problems), result)
        self.report("PASS", name, probe["covers"], result)

    # -- policies -------------------------------------------------------------------------

    def refused(self, item: dict) -> None:
        name = f"refused {item['policy']}"
        result = self.certorail_run("describe", "--root", self.root, "--policy", TESTBED / item["policy"])
        if result.returncode == 0:
            return self.report("FAIL", name, "it loaded", result)
        if item["error"] not in result.stderr + result.stdout:
            return self.report("FAIL", name, f"refused, but not with {item['error']!r}", result)
        self.report("PASS", name, item["error"], result)

    def lint(self, item: dict) -> None:
        name = f"lint {item['policy']}"
        kinds = item["darwin"]["kinds"] if PLATFORM == "darwin" and "darwin" in item else item["kinds"]
        result = self.certorail_run("describe", "--root", self.root, "--policy", TESTBED / item["policy"])
        missing = [k for k in kinds if f"lint ({k})" not in result.stderr]
        if result.returncode != 0 or missing:
            hint = ""
            if "shadowed-protection" in missing and self.root != build.DEFAULT_ROOT:
                hint = f" (lints.toml spells the default root {build.DEFAULT_ROOT}; edit it to match {self.root})"
            return self.report("FAIL", name, f"missing {', '.join(missing) or 'nothing'}{hint}", result)
        self.report("PASS", name, ", ".join(kinds), result)


def wait_for(port: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="run only these probes")
    parser.add_argument("--root", type=pathlib.Path, default=build.DEFAULT_ROOT)
    parser.add_argument("--certorail", default="certorail", help="the command, split like a shell would (e.g. 'uv run certorail')")
    parser.add_argument("--no-build", action="store_true", help="run against the tree as it is")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every run's output, not only a failure's")
    ns = parser.parse_args()
    scenario = tomllib.loads((TESTBED / "scenario.toml").read_text(encoding="utf-8"))
    probes = [p for p in scenario["probe"] if not ns.names or p["name"] in ns.names]

    if not ns.no_build:
        built = subprocess.run([sys.executable, str(TESTBED / "build.py"), str(ns.root)], capture_output=True, text=True)
        print(built.stdout.rstrip())
        if built.returncode != 0:
            print(built.stderr.rstrip())
            return 1
    casefold = PLATFORM == "darwin" or bool(build.casefolded(ns.root / "cf"))  # APFS folds by default
    print(f"platform {PLATFORM}; cf/ folds: {casefold}\n")

    runner = Runner(ns.root, shlex.split(ns.certorail), ns.verbose)
    server = None
    if any("network" in p.get("needs", []) for p in probes):
        server = subprocess.Popen([sys.executable, str(TESTBED / "serve.py")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not all(wait_for(port) for port in (8765, 8766)):
            print("serve.py did not start listening on 8765 and 8766")
            server.terminate()
            return 1
    try:
        for probe in probes:
            runner.probe(probe, casefold)
    finally:
        if server is not None:
            server.terminate()
    if not ns.names:
        for item in scenario.get("refused", []):
            runner.refused(item)
        for item in scenario.get("lint", []):
            runner.lint(item)
    print(f"\n{runner.failed} failed" if runner.failed else "\nall passed")
    return 1 if runner.failed else 0


if __name__ == "__main__":
    sys.exit(main())
