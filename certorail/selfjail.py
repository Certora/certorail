"""Self-imposed process-creation denial for the confined child.

srt restricts what a process can *reach* (files, network); it exposes nothing about what a
process can *do*, and in particular nothing about fork/exec. But the bootstrap runs our code
inside the jail before the program does, and a process may always tighten its own cage:

  * Linux: a self-installed seccomp filter denying ``execve``/``execveat`` with EPERM
    (``PR_SET_NO_NEW_PRIVS`` makes that legal unprivileged; the filter is inherited by any
    fork, so there is no spawn-then-exec dodge). Fork itself stays permitted: without exec
    it confers no new capability, only the same jailed image.
  * macOS: ``sandbox_init()`` -- the in-process Seatbelt API -- with
    ``(deny process-exec*) (deny process-fork)``. Applied after our own exec already
    happened, so the denial can be absolute; it intersects with srt's own profile.

This is pure defense in depth for ``certora.exec``: the subset cannot *name* subprocess, the
broker is where exec'd children actually run, and this makes local spawning physically
impossible rather than merely unspellable. Nothing in the child legitimately creates a
process -- checks, execs and network requests are all brokered over the socket.

``deny_process_creation`` returns a warning string when the denial could not be installed
(unknown architecture, missing API), and None on success: the caller decides how loudly to
degrade, mirroring the srt-missing behaviour.
"""
import ctypes
import platform
import struct
import sys

# BPF opcodes and seccomp constants (linux/{bpf,seccomp,audit}.h)
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

# audit arch + syscall numbers, per machine
_ARCHES: dict[str, tuple[int, int, int]] = {
    # machine: (AUDIT_ARCH, execve, execveat)
    "x86_64": (0xC000003E, 59, 322),
    "aarch64": (0xC00000B7, 221, 281),
}


def _filter_program(audit_arch: int, execve: int, execveat: int) -> bytes:
    """A six-instruction BPF program: on this arch, execve/execveat -> EPERM, all else
    allowed; a foreign arch (impossible in-process, but fail open rather than brick) is
    allowed through."""
    instr = struct.Struct("<HBBI")
    return b"".join(
        instr.pack(*i)
        for i in (
            (_BPF_LD_W_ABS, 0, 0, 4),                # load seccomp_data.arch
            (_BPF_JMP_JEQ_K, 0, 3, audit_arch),      # wrong arch -> ALLOW (at 5)
            (_BPF_LD_W_ABS, 0, 0, 0),                # load seccomp_data.nr
            (_BPF_JMP_JEQ_K, 2, 0, execve),          # execve -> ERRNO (at 6)
            (_BPF_JMP_JEQ_K, 1, 0, execveat),        # execveat -> ERRNO (at 6)
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM),
        )
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.c_void_p))


def _linux_seccomp() -> str | None:
    machine = platform.machine()
    if machine not in _ARCHES:
        return f"no seccomp filter for machine {machine!r}"
    audit_arch, execve, execveat = _ARCHES[machine]
    program = _filter_program(audit_arch, execve, execveat)
    buf = ctypes.create_string_buffer(program, len(program))
    prog = _SockFprog(len(program) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return f"PR_SET_NO_NEW_PRIVS failed: errno {ctypes.get_errno()}"
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        return f"seccomp filter rejected: errno {ctypes.get_errno()}"
    return None


def _darwin_sandbox() -> str | None:
    profile = b"(version 1) (allow default) (deny process-exec*) (deny process-fork)"
    try:
        libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError as exc:
        return f"libSystem unavailable: {exc}"
    error = ctypes.c_char_p()
    if libsystem.sandbox_init(profile, 0, ctypes.byref(error)) != 0:
        detail = error.value.decode(errors="replace") if error.value else "unknown"
        return f"sandbox_init failed: {detail}"
    return None


def deny_process_creation() -> str | None:
    """Deny this process (and its forks) the ability to exec. Returns a warning when the
    denial could not be installed, None on success -- except on Windows, which is handled
    with the gravity it deserves (WSL and --no-jail both exist)."""
    if sys.platform == "win32":
        print("here's a nickel kid, get yourself a better computer")
        sys.exit(1)
    if sys.platform == "linux":
        return _linux_seccomp()
    if sys.platform == "darwin":
        return _darwin_sandbox()
    return f"no process-creation denial for platform {sys.platform!r}"
