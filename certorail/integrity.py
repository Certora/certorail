"""Checker pins: a validation names the sha256 of the evaluator it trusts.

A ``[[validation]]`` is a trusted assertion -- "success of this program establishes these
atoms" -- and the assertion is only as meaningful as the exact bytes that compute the verdict.
The pin binds the two in the reviewed document itself::

    [[validation]]
    name = "org-repo"
    argv = ["${checkers}/org-checkout"]
    pin  = "sha256:<64 hex>"

Why the pin lives on the validation rather than in a side manifest: the granularity is the
assertion, not the file. ``checkers/`` is a flat shared namespace, and a later pack
legitimately installing a different ``org-checkout`` must not silently change what *this*
document's validations mean -- with the pin here, they fail loudly instead of following the
new bytes. The document is also self-contained: reviewing the TOML reviews a commitment to an
exact implementation, and it is the natural place a proof attestation would sit later
(INSTALL.md's verified tier).

Semantics:

- **Optional by absence.** A validation without ``pin`` runs whatever is installed, as today.
- **Violent by presence.** ``verify_pinned`` is called with the resolved evaluator path
  immediately before it is executed (the broker; and the analysis-time literal-checker
  runner). A pinned evaluator that is missing, unreadable, or not the pinned bytes raises
  ``CheckerIntegrityError``, and the caller treats that as fatal to the whole run: a drifted
  checker's verdicts taint every fact established after them.
- **TOCTOU, conceded.** Hash, then exec; a racer can swap between. The property bought is
  drift detection -- an edit, a clobbering install, an unreviewed "fix" -- not defense against
  an adversary with the user's write authority.

``schema.ValidationDecl`` accepts the key, the loader carries it onto ``policy.Validation``,
and it is verified at both places an evaluator runs: the broker's ``_run_check`` (which
poisons the whole broker on a violation -- every subsequent request is refused, not just this
check) and the analysis-time literal-checker runner. ``document_pins`` and ``verify_all``
here read documents *raw* (``tomllib``, not the schema) so the installer's consistency check
and the CLI sweep need no loadable composition to do their jobs.
"""
import atexit
import hashlib
import os
import pathlib
import re
import shutil
import tempfile
import tomllib
from dataclasses import dataclass

from .policydir import config_dir, policy_dir

PIN_KEY = "pin"
_CHECKER_HEAD = "${checkers}/"
# the pin format; schema.py carries a mirror for document shape-checking
PIN_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class CheckerIntegrityError(Exception):
    """A pinned evaluator is not the bytes its validation pinned (or a pin is malformed).
    Callers treat this as fatal to the run."""


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def well_formed(pin: str, where: str) -> str:
    if PIN_PATTERN.fullmatch(pin) is None:
        raise CheckerIntegrityError(
            f'{where}: a pin is "sha256:" plus 64 lowercase hex digits, got {pin!r}'
        )
    return pin


def verify_pinned(argv0: str | pathlib.Path, pin: str) -> None:
    """The runtime half: call with the resolved evaluator path and the validation's pin,
    immediately before executing it. Silent when the bytes are the pinned bytes."""
    path = pathlib.Path(argv0)
    pin = well_formed(pin, str(path))
    try:
        actual = digest(path.read_bytes())
    except OSError as e:
        raise CheckerIntegrityError(
            f"pinned evaluator {path} cannot be read ({e}); refusing to run"
        )
    if actual != pin:
        raise CheckerIntegrityError(
            f"evaluator {path} is not the implementation its validation pinned: {actual}, "
            f"pinned {pin}. Its verdicts no longer mean what was reviewed; refusing to run "
            "anything. Re-install the pack that owns it, or re-pin deliberately "
            "(certorail policy pin)."
        )


# the snapshot store: evaluator bytes captured at load are materialized here once, named by
# digest, and executed from here -- the mutable file in checkers/ is never what runs. The dir
# is process-private (0700 mkdtemp), never the run tempdir or a spawn's scratch TMPDIR, and
# readable inside the child jail (write-fs=false ro-binds the whole fs). Cleaned at exit.
_SNAPSHOT: pathlib.Path | None = None


def _snapshot_store() -> pathlib.Path:
    global _SNAPSHOT
    if _SNAPSHOT is None:
        d = pathlib.Path(tempfile.mkdtemp(prefix="certorail-evaluators-"))
        atexit.register(shutil.rmtree, d, ignore_errors=True)
        _SNAPSHOT = d
    return _SNAPSHOT


def materialize(data: bytes) -> str:
    """The executable snapshot path for these evaluator bytes: written once (named by their
    digest, so validations sharing a checker share a file), mode r-x, never rewritten. What
    was pin-verified at load is what runs, whatever happens to the installed file since."""
    path = _snapshot_store() / hashlib.sha256(data).hexdigest()
    if not path.exists():
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o555)
            os.replace(tmp, path)
        except BaseException:
            pathlib.Path(tmp).unlink(missing_ok=True)
            raise
    return str(path)


@dataclass(frozen=True)
class Pin:
    """One pinned validation, as read raw from a document."""

    where: str       # the document, as named to the reader
    validation: str  # the validation's name
    checker: str     # the relative name after ``${checkers}/``
    pin: str         # normalized ``sha256:<hex>``


def document_pins(data: object, where: str) -> list[Pin]:
    """Every ``[[validation]]`` in *data* (a raw TOML document) that carries ``pin``. Shape
    beyond the pin itself is the schema's business: entries without the key are skipped, but a
    pin that is malformed, or on a validation whose evaluator is not ``${checkers}/<name>``,
    is an error -- a pin that cannot be checked must not look like one that is."""
    out: list[Pin] = []
    if not isinstance(data, dict):
        return out
    validations = data.get("validation")
    if not isinstance(validations, list):
        return out
    for i, v in enumerate(validations):
        if not isinstance(v, dict) or PIN_KEY not in v:
            continue
        name = v.get("name") if isinstance(v.get("name"), str) else f"validation[{i}]"
        pin = v[PIN_KEY]
        if not isinstance(pin, str):
            raise CheckerIntegrityError(f"{where}: validation {name!r}: pin must be a string")
        pin = well_formed(pin, f"{where}: validation {name!r}")
        argv = v.get("argv")
        argv0 = argv[0] if isinstance(argv, list) and argv and isinstance(argv[0], str) else None
        if argv0 is None or not argv0.startswith(_CHECKER_HEAD):
            raise CheckerIntegrityError(
                f"{where}: validation {name!r}: a pin needs argv[0] = ${{checkers}}/<name>; "
                "only installed checkers are pinnable"
            )
        out.append(Pin(where, str(name), argv0[len(_CHECKER_HEAD):], pin))
    return out


@dataclass(frozen=True)
class VerifyReport:
    problems: tuple[str, ...]  # pinned but drifted, missing, or malformed
    notes: tuple[str, ...]     # pinnable but unpinned validations: legal, worth knowing

    @property
    def clean(self) -> bool:
        return not self.problems


def _installed_documents() -> list[pathlib.Path]:
    from .policyfile import rulesets_dir  # deferred: policyfile -> policy -> this module

    out: list[pathlib.Path] = []
    rdir = rulesets_dir()
    if rdir.is_dir():
        out.extend(sorted(rdir.glob("*.toml")))
    pdir = policy_dir()
    if pdir.is_dir():
        for bucket in sorted(pdir.iterdir()):
            out.extend(sorted(bucket.glob("*.toml")))
    return out


def verify_all() -> VerifyReport:
    """Sweep every installed ruleset and policy for pinned validations and re-hash each
    pinned checker; note validations that reference a checker without pinning it."""
    problems: list[str] = []
    notes: list[str] = []
    checkers = config_dir() / "checkers"
    for doc_path in _installed_documents():
        try:
            data = tomllib.loads(doc_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            problems.append(f"{doc_path}: unreadable ({e})")
            continue
        try:
            pins = document_pins(data, str(doc_path))
        except CheckerIntegrityError as e:
            problems.append(str(e))
            continue
        pinned_names = {p.validation for p in pins}
        for p in pins:
            target = checkers / p.checker
            try:
                actual = digest(target.read_bytes())
            except OSError as e:
                problems.append(
                    f"{p.where}: validation {p.validation!r} pins {p.checker}, which cannot "
                    f"be read ({e})"
                )
                continue
            if actual != p.pin:
                problems.append(
                    f"{p.where}: validation {p.validation!r}: {p.checker} is {actual}, "
                    f"pinned {p.pin}"
                )
        validations = data.get("validation") if isinstance(data, dict) else None
        for v in validations if isinstance(validations, list) else []:
            if not isinstance(v, dict):
                continue
            argv = v.get("argv")
            argv0 = argv[0] if isinstance(argv, list) and argv and isinstance(argv[0], str) else None
            name = v.get("name")
            if (
                argv0 is not None
                and argv0.startswith(_CHECKER_HEAD)
                and isinstance(name, str)
                and name not in pinned_names
            ):
                notes.append(f"note: {doc_path}: validation {name!r} does not pin {argv0[len(_CHECKER_HEAD):]}")
    return VerifyReport(tuple(problems), tuple(notes))
