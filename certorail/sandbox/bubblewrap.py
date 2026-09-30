"""What the bubblewrap backend knows of its own: the toolchain a Linux policy world holds, and the
fork-denial program for a tool that may not create processes (``place.place_bubblewrap`` places a
jail's layers, ``emit.bwrap_command`` writes the command line)."""
import platform
import tempfile
from typing import IO

from certorail.childjail import JailUnavailable
from certorail.selfjail import ARCHES, fork_denial_filter

# what a Linux policy world holds besides the policy's own grants: where programs, their
# libraries, the loader's cache and the name databases ``ls -l`` reads live. Read-only, each only
# if present, stable across a run. Machine-specific toolchains (a homebrew, a nix store) are
# MOUNTS.md's ``world.toml``.
TOOLCHAIN = (
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin",
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/localtime",
)


def seccomp_program() -> IO[bytes]:
    """An open, unlinked file holding the fork-denial program, positioned at its start, for
    bubblewrap to read (``--seccomp FD``)."""
    machine = platform.machine()
    arch = ARCHES.get(machine)
    if arch is None:
        raise JailUnavailable(f"no seccomp filter for machine {machine!r}: spawn = false cannot be enforced")
    program = tempfile.TemporaryFile(prefix="certorail-seccomp-")
    program.write(fork_denial_filter(arch))
    program.flush()
    program.seek(0)
    return program
