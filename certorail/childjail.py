"""What a ``[[program]]`` or ``[[validation]]`` grant says about its child (JAILS.md, option B: per
grant, by what the grant declares) -- the grant-level vocabulary, before any lowering.

The confined program runs in the host's jail (``sandbox.program``); the tools and checkers its
grants name run host-side, in the broker, and by default with the host's environment and reach --
the tool is trusted as granted. A grant's media keys and its ``exec`` table narrow that, and every
narrowing is **enforced**, a property of the process rather than a claim::

    network  = false                   # no network at all
    write-fs = false                   # no filesystem writes, save a private TMPDIR discarded after
    exec.env   = ["PATH", "HOME", { GIT_PAGER = "cat" }]   # passed through, or set; the rest is scrubbed
    exec.spawn = false                 # no process creation
    exec.view  = "policy"              # sees only what the policy grants (MOUNTS.md)

``network`` and ``write-fs`` are the grant's *media* (EFFECTS.md): what the tool cannot reach it
cannot write, so the effects analysis and the jail read the same two keys. Region-level claims
that no jail could check stay declarations (``writes = [...]``). Every key defaults to the
unjailed baseline.

The passes: a grant is read here (``Jail``, what ``--describe`` prints); the policy turns it into
a ``Confinement`` (``certorail.confinement``, the filesystem it sees included); a platform
``Spawner`` lowers that to typed binds and filters and spawns under them (``certorail.sandbox``).
A jailed grant whose mechanism is missing fails closed (``JailUnavailable``): the tool does not
run at all.

What ``spawn = false`` does not stop: a tool replacing *itself* with another program (exec
without fork). It denies creating processes -- hooks, ``-exec``, helpers, shells -- which is
where a tool steered by the tree it reads would run something else.
"""
import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


class View(enum.Enum):
    """What a grant's child sees of the filesystem (``exec.view``)."""

    HOST = "host"
    POLICY = "policy"


@dataclass(frozen=True)
class Environment:
    """A grant's ``exec.env``: the variables passed through from the broker's environment and
    the variables set to a literal value. One flat mapping: a name is mentioned once, either
    way."""

    passed: tuple[str, ...] = ()
    sets: tuple[tuple[str, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.passed and not self.sets


# the host's own variable: it names the scratch directory under write-fs = false
_HOST_SET = frozenset({"TMPDIR"})


def environment_spec(items: Iterable[str | Mapping[str, str]]) -> Environment:
    """``exec.env`` as written -- a string passes that variable through, a table sets each of
    its keys -- checked: names are names (no ``=``, non-empty), each mentioned once, and none
    the host sets itself."""
    passed: list[str] = []
    sets: list[tuple[str, str]] = []
    seen: set[str] = set()

    def name(n: str) -> str:
        if not n or "=" in n:
            raise ValueError(f"an environment variable name, not an assignment: {n!r}")
        if n in _HOST_SET:
            raise ValueError(f"{n} is set by the host under write-fs = false and cannot be listed")
        if n in seen:
            raise ValueError(f"environment variable {n} is mentioned twice")
        seen.add(n)
        return n

    for item in items:
        if isinstance(item, str):
            passed.append(name(item))
        else:
            for k, v in item.items():
                if not isinstance(v, str):
                    raise ValueError(f"environment variable {k}: the value must be a string")
                sets.append((name(k), v))
    return Environment(tuple(passed), tuple(sets))


@dataclass(frozen=True)
class Jail:
    """What a grant's child may reach, as the grant declares it: the environment (None: the
    broker's, whole), the network, filesystem writes, process creation, the view. A grant
    assembles one from its media keys and its ``exec`` table (``Program.jail``); the policy
    turns it into the child's ``Confinement``."""

    env: Environment | None = None
    network: bool = True
    write_fs: bool = True
    spawn: bool = True
    view: View = View.HOST

    @property
    def restricts(self) -> bool:
        """Does this jail change anything about how the child runs?"""
        return self.env is not None or not (self.network and self.write_fs and self.spawn) or self.confined

    @property
    def confined(self) -> bool:
        """Does the child see only the policy's view of the filesystem?"""
        return self.view is View.POLICY


UNJAILED = Jail()


class JailUnavailable(Exception):
    """The platform cannot enforce the restriction asked for; the child must not run."""


@dataclass(frozen=True)
class Spawn:
    """What to hand ``subprocess.Popen``: the command (the jail wrapper, then the tool), the
    environment, and any descriptors the wrapper reads."""

    argv: list[str]
    env: dict[str, str]
    pass_fds: tuple[int, ...] = ()
