"""``certorail policy``: install policies and ruleset packs into the config directory.

The config directory (``policydir.config_dir()``) is the one auditable place for everything the
analysis trusts, and until now things got there by hand: an agent or a user writing files into
``policy/``, ``checkers/`` and ``rulesets/`` directly, with nothing validated until some later
run failed to load. This module is the mechanical path (INSTALL.md): validate the exact bytes
that will land, refuse conflicts instead of overwriting them, and rotate into place in the
order that keeps the tree loadable at every instant -- checkers and notes first, TOML last,
each file written beside its target and ``os.replace``d, because the loader fails closed on a
missing checker but not on an extra one.

Two installable units, deliberately different:

- a **ruleset pack**: a directory of ruleset ``*.toml`` documents plus the ``checkers/``
  executables they reference (and ``<name>.md`` program-author notes). Rulesets are rootless
  and parameterized, so a pack can only be checked for *shape* (``schema.parse_ruleset``) and
  *closure* -- every ``${checkers}/<name>`` supplied or already installed, everything supplied
  actually referenced (nothing parked in ``checkers/`` for a later "minor update" to activate).
  Full meaning is checked where it exists: at root-policy install, when the pack is composed.
- a **root policy**: one ``*.toml`` carrying an absolute ``root``. It composes everything, so
  it gets the full semantic load (``policyfile.from_data``) against the installed tree before
  placement in ``policy/<munged root>/``, and a second file claiming the same root is refused
  outright -- ambient discovery would refuse to choose between them anyway.

No ledger, no signatures, no hashes yet (INSTALL.md defers them): this is the rotation layer
those would sit on.
"""
import argparse
import os
import pathlib
import tempfile
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field

from .integrity import CheckerIntegrityError, Pin, digest, document_pins, verify_all
from .policydir import AmbientPolicyError, config_dir, find_policy, munge, policy_dir
from .policyfile import PolicyFileError, from_data, rulesets_dir
from .schema import RulesetDoc, SchemaError, parse_ruleset

_CHECKER_HEAD = "${checkers}/"


class InstallError(Exception):
    """Nothing was installed; every problem found, one per line."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("\n".join(self.problems))


@dataclass(frozen=True)
class Placement:
    """One file the install will put in place, already validated as bytes."""

    target: pathlib.Path
    data: bytes
    executable: bool = False

    @property
    def settled(self) -> bool:
        """Is the target already exactly this? (Same bytes; and for a checker, executable --
        a checker present with the right bytes but no exec bit still needs placing.)"""
        try:
            if self.target.read_bytes() != self.data:
                return False
        except OSError:
            return False
        return not self.executable or os.access(self.target, os.X_OK)


@dataclass(frozen=True)
class Report:
    installed: tuple[str, ...]
    unchanged: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def lines(self) -> list[str]:
        out = [f"installed {t}" for t in self.installed]
        out += [f"unchanged {t}" for t in self.unchanged]
        out += list(self.notes)
        return out


def _place(placements: Sequence[Placement], replace: bool) -> Report:
    """Refuse every conflict up front, then rotate the rest into place in order, atomically
    per file (a temp file beside the target, then ``os.replace``)."""
    conflicts = [
        f"{p.target}: exists with different content (pass --replace to install over it)"
        for p in placements
        if not replace and p.target.exists() and not p.settled
    ]
    if conflicts:
        raise InstallError(conflicts)
    installed: list[str] = []
    unchanged: list[str] = []
    for p in placements:
        if p.settled:
            unchanged.append(str(p.target))
            continue
        p.target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.target.parent, prefix="." + p.target.name + ".")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(p.data)
            os.chmod(tmp, 0o755 if p.executable else 0o644)
            os.replace(tmp, p.target)
        except BaseException:
            pathlib.Path(tmp).unlink(missing_ok=True)
            raise
        installed.append(str(p.target))
    return Report(tuple(installed), tuple(unchanged))


# ---------------------------------------------------------------------------
# ruleset packs
# ---------------------------------------------------------------------------


def _checker_ref(argv0: str) -> str | None:
    """The relative checker name a validation's ``argv[0]`` references, or None for a stock
    or plain evaluator."""
    if not argv0.startswith(_CHECKER_HEAD):
        return None
    return argv0[len(_CHECKER_HEAD):]


def _checker_ok(rel: str, where: str, problems: list[str]) -> bool:
    parts = pathlib.PurePosixPath(rel).parts
    if not rel or rel.startswith("/") or ".." in parts or "." in parts:
        problems.append(f"{where}: checker reference {rel!r} must be a plain relative name")
        return False
    return True


@dataclass
class _Pack:
    """The validated plan for one pack directory."""

    rulesets: dict[str, bytes] = field(default_factory=dict)   # name.toml -> bytes
    notes: dict[str, bytes] = field(default_factory=dict)      # name.md -> bytes
    checkers: dict[str, bytes] = field(default_factory=dict)   # relative name -> bytes
    pins: list[Pin] = field(default_factory=list)              # validations pinning a checker
    skipped: list[str] = field(default_factory=list)


def load_pack(pack: pathlib.Path) -> _Pack:
    """Read and validate a pack directory: every ruleset has the shape, the checker closure is
    exact both ways, every applied ruleset is in the pack or already installed. Raises
    ``InstallError`` with every problem; touches nothing."""
    problems: list[str] = []
    if not pack.is_dir():
        raise InstallError([f"{pack}: a pack is a directory of ruleset .toml files (plus checkers/)"])
    plan = _Pack()
    docs: dict[str, RulesetDoc] = {}
    for p in sorted(pack.iterdir()):
        if p.suffix == ".toml" and p.is_file():
            data = p.read_bytes()
            try:
                raw = tomllib.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
                problems.append(f"{p.name}: {e}")
                continue
            # pins are read raw, before the schema pass, so a pin problem is reported even
            # while the schema is what refuses the document
            try:
                plan.pins.extend(document_pins(raw, p.name))
            except CheckerIntegrityError as e:
                problems.append(str(e))
            try:
                docs[p.name] = parse_ruleset(raw, p.name)
            except SchemaError as e:
                problems.extend(str(e).splitlines())
                continue
            plan.rulesets[p.name] = data
        elif p.suffix == ".md" and p.is_file():
            plan.notes[p.name] = p.read_bytes()
    if not plan.rulesets and not problems:
        problems.append(f"{pack}: no ruleset .toml files")
    # a <name>.md is the program-author note for <name>.toml and installs beside it; any other
    # .md (a README) documents the pack itself and never lands in the trusted tree
    for name in sorted(plan.notes):
        if pathlib.PurePath(name).stem + ".toml" not in plan.rulesets:
            del plan.notes[name]
            plan.skipped.append(f"skipped {name}: no ruleset of that name in the pack")
    checkers_dir = pack / "checkers"
    if checkers_dir.is_dir():
        for p in sorted(checkers_dir.rglob("*")):
            if p.is_file():
                plan.checkers[p.relative_to(checkers_dir).as_posix()] = p.read_bytes()
    # the closure, both ways (INSTALL.md): referenced but missing fails here rather than at
    # some later load; supplied but unreferenced is refused as smuggling
    referenced: set[str] = set()
    for name, doc in sorted(docs.items()):
        for v in doc.validation:
            rel = _checker_ref(v.argv[0])
            if rel is not None and _checker_ok(rel, f"{name}: validation {v.name!r}", problems):
                referenced.add(rel)
        for a in doc.apply:
            if a.ruleset not in plan.rulesets and not (rulesets_dir() / a.ruleset).is_file():
                problems.append(
                    f"{name}: applies {a.ruleset!r}, which is neither in the pack nor installed"
                )
    for rel in sorted(referenced - plan.checkers.keys()):
        installed = config_dir() / "checkers" / rel
        if not (installed.is_file() and os.access(installed, os.X_OK)):
            problems.append(
                f"checker {rel!r} is referenced but neither in the pack's checkers/ nor "
                "installed (executable)"
            )
    for rel in sorted(plan.checkers.keys() - referenced):
        problems.append(
            f"checkers/{rel} is supplied but no ruleset in the pack references it; a pack "
            "installs exactly the closure of its rulesets"
        )
    # pin consistency: a pinned validation and the checker bytes travel as one reviewed unit,
    # so a pack whose pins disagree with the checkers it supplies is refused as corrupt
    for pn in plan.pins:
        supplied = plan.checkers.get(pn.checker)
        if supplied is None:
            try:
                supplied = (config_dir() / "checkers" / pn.checker).read_bytes()
            except OSError:
                continue  # missing entirely: the closure check above already says so
        actual = digest(supplied)
        if actual != pn.pin:
            problems.append(
                f"{pn.where}: validation {pn.validation!r} pins {pn.pin} but {pn.checker} is "
                f"{actual}; the pack is internally inconsistent -- recompute deliberately "
                "with `certorail policy pin`"
            )
    if problems:
        raise InstallError(problems)
    return plan


def install_pack(pack: pathlib.Path, *, replace: bool = False) -> Report:
    """Validate *pack* and rotate it into the config directory: checkers first, notes, then
    the ruleset TOMLs -- the tree is loadable at every instant in between."""
    plan = load_pack(pack)
    checkers = config_dir() / "checkers"
    rulesets = rulesets_dir()
    placements = (
        [Placement(checkers / rel, data, executable=True) for rel, data in sorted(plan.checkers.items())]
        + [Placement(rulesets / name, data) for name, data in sorted(plan.notes.items())]
        + [Placement(rulesets / name, data) for name, data in sorted(plan.rulesets.items())]
    )
    report = _place(placements, replace)
    notes = list(plan.skipped)
    if plan.pins:
        notes.append(f"verified {len(plan.pins)} validation pin(s) against the checkers")
    return Report(report.installed, report.unchanged, tuple(notes))


# ---------------------------------------------------------------------------
# root policies
# ---------------------------------------------------------------------------


def _declared_root(data: object, where: str) -> str:
    # the same reading policydir applies during discovery; kept locally so install stays
    # new-files-only -- a candidate for sharing with policydir._declared_root
    if not isinstance(data, dict) or not isinstance(data.get("root"), str):
        raise InstallError([
            f"{where}: an ambient policy carries an absolute root = \"/...\" naming the "
            "sandbox directory it governs; add one (a policy without it is for --policy runs)"
        ])
    root = data["root"]
    if not root.startswith("/"):
        raise InstallError([f"{where}: root must be an absolute path, got {root!r}"])
    return root


def install_policy(src: pathlib.Path, *, name: str | None = None, replace: bool = False) -> Report:
    """Validate the exact bytes of *src* as a root policy -- the full semantic load, against
    the installed rulesets and checkers -- and place them in ``policy/<munged root>/``. A
    second file claiming the same root is refused: discovery would refuse the pair anyway."""
    if src.suffix != ".toml":
        raise InstallError([f"{src}: an installable policy is a .toml document"])
    try:
        data_bytes = src.read_bytes()
    except OSError as e:
        raise InstallError([f"{src}: {e}"])
    try:
        data = tomllib.loads(data_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise InstallError([f"{src}: {e}"])
    try:
        from_data(data, str(src))  # loads against the installed tree: packs install first
    except PolicyFileError as e:
        raise InstallError(str(e).splitlines())
    root = _declared_root(data, str(src))
    basename = name if name is not None else src.name
    if "/" in basename or not basename.endswith(".toml"):
        raise InstallError([f"--name {basename!r}: a bare *.toml file name"])
    bucket = policy_dir() / munge(pathlib.PurePath(root))
    target = bucket / basename
    claimants = []
    for other in sorted(bucket.glob("*.toml")) if bucket.is_dir() else []:
        if other == target:
            continue
        try:
            if tomllib.loads(other.read_text(encoding="utf-8")).get("root") == root:
                claimants.append(other)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            claimants.append(other)  # unreadable in the bucket: discovery would refuse too
    if claimants:
        raise InstallError(
            [f"{c}: already claims root {root} (ambient discovery refuses two); remove it, "
             f"or install over it with --name {c.name}" for c in claimants]
        )
    try:
        pins = document_pins(data, str(src))
    except CheckerIntegrityError as e:
        raise InstallError([str(e)])
    pin_problems: list[str] = []
    for pn in pins:
        pinned_target = config_dir() / "checkers" / pn.checker
        try:
            actual = digest(pinned_target.read_bytes())
        except OSError as e:
            pin_problems.append(
                f"{pn.where}: validation {pn.validation!r} pins {pn.checker}, which cannot "
                f"be read ({e})"
            )
            continue
        if actual != pn.pin:
            pin_problems.append(
                f"{pn.where}: validation {pn.validation!r}: {pn.checker} is {actual}, "
                f"pinned {pn.pin}"
            )
    if pin_problems:
        raise InstallError(pin_problems)
    report = _place([Placement(target, data_bytes)], replace)
    notes = [f"governs {root} and every directory below it without a policy of its own"]
    try:
        found = find_policy(pathlib.Path(root))
    except AmbientPolicyError as e:
        notes.append(f"warning: ambient discovery for {root} now fails: {e}")
    else:
        if found is None or found[0] != target:
            notes.append(
                f"warning: ambient discovery for {root} finds "
                f"{found[0] if found else 'nothing'}, not the installed file"
            )
        else:
            notes.append(f"review it: certorail --describe --root {root}")
    return Report(report.installed, report.unchanged, tuple(notes))


def suggest_pins(pack: pathlib.Path) -> list[str]:
    """For each validation in the pack's rulesets whose evaluator is ``${checkers}/<name>``,
    the ``pin = "sha256:..."`` line for the checker the pack supplies (or the installed one) --
    so authors never hand-compute a hash."""
    lines: list[str] = []
    checkers = pack / "checkers"
    for p in sorted(pack.glob("*.toml")):
        try:
            raw = tomllib.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            lines.append(f"{p.name}: unreadable ({e})")
            continue
        validations = raw.get("validation") if isinstance(raw, dict) else None
        for v in validations if isinstance(validations, list) else []:
            if not isinstance(v, dict):
                continue
            argv = v.get("argv")
            argv0 = argv[0] if isinstance(argv, list) and argv and isinstance(argv[0], str) else None
            rel = _checker_ref(argv0) if argv0 is not None else None
            if rel is None:
                continue
            name = v.get("name") if isinstance(v.get("name"), str) else "?"
            source = checkers / rel
            if not source.is_file():
                source = config_dir() / "checkers" / rel
            if not source.is_file():
                lines.append(f'{p.name}: validation "{name}": checker {rel} not found')
                continue
            lines.append(f'{p.name}: validation "{name}": pin = "{digest(source.read_bytes())}"')
    return lines


# ---------------------------------------------------------------------------
# listing
# ---------------------------------------------------------------------------


def list_installed() -> str:
    """What the config directory holds, by section, with each policy's declared root."""
    cfg = config_dir()
    out = [f"config directory: {cfg}"]
    out.append("policies:")
    buckets = sorted(policy_dir().iterdir()) if policy_dir().is_dir() else []
    seen = False
    for bucket in buckets:
        for f in sorted(bucket.glob("*.toml")):
            seen = True
            try:
                root = tomllib.loads(f.read_text(encoding="utf-8")).get("root", "(no root)")
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
                root = f"(unreadable: {e})"
            out.append(f"  {f}  ->  {root}")
    if not seen:
        out.append("  none")
    out.append("rulesets:")
    rdir = rulesets_dir()
    entries = [p for p in sorted(rdir.iterdir()) if p.is_file()] if rdir.is_dir() else []
    if entries:
        out.extend(f"  {p.name}" for p in entries)
    else:
        out.append("  none")
    out.append("checkers:")
    cdir = cfg / "checkers"
    found = [p for p in sorted(cdir.rglob("*")) if p.is_file()] if cdir.is_dir() else []
    for p in found:
        mode = "" if os.access(p, os.X_OK) else "  (NOT executable: loads will fail)"
        out.append(f"  {p.relative_to(cdir).as_posix()}{mode}")
    if not found:
        out.append("  none")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail policy",
        description="Install certorail policies and ruleset packs: validate, then rotate into "
        "the config directory.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_pack = sub.add_parser(
        "install-pack",
        help="install a pack: a directory of ruleset .toml files plus their checkers/",
    )
    p_pack.add_argument("pack", type=pathlib.Path)
    p_pack.add_argument("--replace", action="store_true",
                        help="install over existing files whose content differs")
    p_pol = sub.add_parser(
        "install", help="install one root policy .toml ambiently for its declared root"
    )
    p_pol.add_argument("policy", type=pathlib.Path)
    p_pol.add_argument("--name", default=None, help="the installed file name (default: the source's)")
    p_pol.add_argument("--replace", action="store_true",
                       help="install over an existing file of the same name whose content differs")
    sub.add_parser("list", help="what the config directory holds")
    sub.add_parser("verify", help="re-hash every pinned validation's checker; report drift")
    p_pin = sub.add_parser("pin", help="print pin = \"sha256:...\" lines for a pack's validations")
    p_pin.add_argument("pack", type=pathlib.Path)
    ns = parser.parse_args(argv)
    try:
        if ns.command == "install-pack":
            report = install_pack(ns.pack, replace=ns.replace)
        elif ns.command == "install":
            report = install_policy(ns.policy, name=ns.name, replace=ns.replace)
        elif ns.command == "verify":
            vr = verify_all()
            for line in (*vr.problems, *vr.notes):
                print(line)
            if not vr.clean:
                return 1
            print("clean")
            return 0
        elif ns.command == "pin":
            for line in suggest_pins(ns.pack):
                print(line)
            return 0
        else:
            print(list_installed())
            return 0
    except InstallError as e:
        raise SystemExit(str(e))
    for line in report.lines():
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
