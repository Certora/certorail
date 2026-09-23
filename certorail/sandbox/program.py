"""The confined program's own jail, in the same passes as a grant's child: the policy lowered to a
self-contained ``ProgramJail`` (``lower_program``), then rendered for the platform -- bubblewrap
arguments around the interpreter on Linux (``bwrap_argv``), the Seatbelt profile the bootstrap
installs on itself on macOS (``seatbelt_profile``).

The program jail confines writes only: reads stay open, since the interpreter needs its stdlib
from everywhere and read confinement is the analysis' stronger half. Its write surface is coarser
than the policy below the first pattern, on purpose: precision is the analysis' job, the jail is
the backstop."""
import os
import pathlib
from dataclasses import dataclass

from certorail import sbpl
from certorail.locations import bindable_paths, enumerable_prefixes
from certorail.sandbox.lowering import Bind, Omitted, RegexRule
from certorail.sandbox.seatbelt import NOT_ERE, pattern_regex

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from certorail.policy import Policy


@dataclass(frozen=True)
class ProgramJail:
    """What the program's jail says: where the program may write, and which protections the
    mechanism holds on top. A protection it cannot express is kept as ``Omitted``: the analysis
    enforces it alone."""

    writable: tuple[pathlib.Path, ...]
    protected: tuple[Bind | RegexRule, ...]
    omitted: tuple[Omitted, ...] = ()


def lower_program(policy: "Policy", root: pathlib.Path, *, patterns: bool) -> ProgramJail:
    """The program jail of *policy* under *root*. Writable: the root -- which covers every
    root-relative write location -- and the literal prefixes of every absolute write grant,
    ``{a,b}`` sets exploded (the loader guarantees each has one). Protected: every ``no-write``
    location that is one path, and with *patterns* (Seatbelt takes regexes) every pattern that
    has an ERE spelling."""
    writable: list[pathlib.Path] = [root]
    for loc in policy.write:
        if not loc.absolute:
            continue
        for names in enumerable_prefixes(loc):
            assert names, "absolute grants begin with a literal (Policy.allow)"
            path = pathlib.Path("/", *names)
            if path not in writable:
                writable.append(path)
    protected: list[Bind | RegexRule] = []
    omitted: list[Omitted] = []
    for loc in policy.no_write:
        paths = bindable_paths(loc, root)
        if paths is not None:
            protected.extend(Bind(p, "no-write", subtree=True) for p in paths)
            continue
        regex = pattern_regex(loc, root, below=True) if patterns else None
        if regex is not None and sbpl.regex(regex) is not None:
            protected.append(RegexRule(regex, "no-write"))
        else:
            reason = NOT_ERE if patterns else "a pattern has no bind mount"
            omitted.append(Omitted(loc, "no-write", reason))
    return ProgramJail(tuple(writable), tuple(protected), tuple(omitted))


def bwrap_argv(jail: ProgramJail, bwrap: str, command: list[str]) -> list[str]:
    """The Linux jail around the interpreter: the host's filesystem read-only, the write surface
    bound writable, every protection that is one path remounted read-only on top (later mounts
    win), no network. Process creation is the bootstrap's own seccomp filter, which composes
    with these namespaces; the broker's socket is an inherited descriptor, which bubblewrap
    passes through."""
    argv = [bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for path in jail.writable:
        argv += ["--bind-try", str(path), str(path)]
    for guarded in jail.protected:
        if isinstance(guarded, Bind):
            argv += ["--ro-bind-try", str(guarded.path), str(guarded.path)]
    argv += ["--unshare-net", "--die-with-parent", "--", *command]
    return argv


def seatbelt_profile(jail: ProgramJail) -> str:
    """The macOS jail, which the bootstrap installs on itself with one ``sandbox_init`` (a
    sandboxed process cannot sandbox itself again, so nothing may wrap the interpreter first):
    everything allowed except writes outside the write surface, the network, fork and exec. Real
    paths, since Seatbelt matches those (``/var`` is ``/private/var``); later rules win, so the
    allowances follow the broad denial and the protections come last."""
    allowed = " ".join(sbpl.subpath(os.path.realpath(p)) for p in jail.writable)
    lines = ["(version 1)", "(allow default)", "(deny file-write*)", f"(allow file-write* {allowed})"]
    for guarded in jail.protected:
        if isinstance(guarded, Bind):
            rendered = sbpl.subpath(os.path.realpath(guarded.path))
        else:
            maybe = sbpl.regex(guarded.pattern)
            assert maybe is not None, "lower_program keeps only patterns that sit in a literal"
            rendered = maybe
        lines.append(f"(deny file-write* {rendered})")
    lines += ["(deny network*)", "(deny process-fork)", "(deny process-exec*)"]
    return "\n".join(lines) + "\n"
