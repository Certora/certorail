"""Ambient policy discovery: per-root policies in the user's config directory.

    ~/.certorail/policy/<munged-prefix>/*.toml     the policies
    ~/.certorail/checkers/<name>                   the programs their validations run

The config directory is the one auditable place for everything a policy trusts: the
policies themselves under ``policy/``, and under ``checkers/`` the executables their
``[[validation]]`` entries name (by absolute path -- nothing here rewrites ``argv``).

When ``--policy`` is not supplied, the sandbox root's ancestors are probed, nearest first:
for a run rooted at ``/srv/work/repo``, first ``munge(/srv/work/repo)``, then
``munge(/srv/work)``, and so on up to ``/``. The munge turns a path into a single
component (``/`` -> ``-``), so one directory listing shows every configured prefix.

The munge is deliberately readable and therefore NOT injective (``/a/b-c`` and ``/a/b/c``
collide), which is why a munge directory holds any number of ``*.toml`` files, each of which
MUST self-identify via a top-level ``root = "/a/b/c"`` key. Only the file whose ``root``
equals the probed prefix matches; a colliding file that identifies some other path is simply
"check the parent". Two files claiming the same prefix is ambiguity, and ambiguity fails
closed. Only TOML is ever discovered ambiently -- an ambient mechanism that executed Python
found by directory-walking would be a gift to nobody.

The config directory is ``$CERTORAIL_CONFIG_DIR``, else ``$XDG_CONFIG_HOME/certorail``,
else ``~/.certorail``.
"""
import os
import pathlib
import tomllib


class AmbientPolicyError(Exception):
    """A malformed or ambiguous ambient policy configuration: fail closed."""


def config_dir() -> pathlib.Path:
    override = os.environ.get("CERTORAIL_CONFIG_DIR")
    if override:
        return pathlib.Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return pathlib.Path(xdg) / "certorail"
    return pathlib.Path.home() / ".certorail"

def policy_dir() -> pathlib.Path:
    return config_dir() / "policy"


def munge(path: pathlib.PurePath) -> str:
    """A path as a single component: ``/srv/work/x`` -> ``-srv-work-x``, ``/`` -> ``-``.
    Readable, not injective: the ``root`` keys inside the files disambiguate."""
    return "-" + "-".join(path.parts[1:])


def _declared_root(file: pathlib.Path) -> pathlib.Path:
    """The prefix *file* claims to govern. Ambient policies must say; failing to parse, or
    failing to say, fails closed."""
    try:
        data = tomllib.loads(file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AmbientPolicyError(f"{file}: {exc}")
    declared = data.get("root")
    if not isinstance(declared, str) or not declared.startswith("/"):
        raise AmbientPolicyError(
            f"{file}: an ambient policy must self-identify with an absolute "
            'root = "/..." (the munged directory name alone is ambiguous)'
        )
    return pathlib.Path(declared)


def find_policy(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path] | None:
    """The nearest ancestor's self-identified policy for a run rooted at *root*:
    ``(policy file, governed prefix)``, or None. Ambiguity -- two files claiming the same
    prefix -- raises ``AmbientPolicyError``. So does a policy in the pre-``policy/`` layout
    (a munge bucket directly under the config directory) that claims a probed prefix: a
    security tool must not silently fall back to the default policy because its configuration
    moved; it says where the file now belongs."""
    base = policy_dir()
    legacy_base = config_dir()
    if not base.is_dir() and not legacy_base.is_dir():
        return None
    prefix = root.resolve()
    while True:
        legacy = legacy_base / munge(prefix)
        if legacy.is_dir():
            stale = [f for f in sorted(legacy.glob("*.toml")) if _declared_root(f) == prefix]
            if stale:
                raise AmbientPolicyError(
                    f"{stale[0]} is in the old layout: ambient policies now live under {base}; "
                    f"move it to {base / munge(prefix) / stale[0].name}"
                )
        bucket = base / munge(prefix)
        if bucket.is_dir():
            matches = [
                f for f in sorted(bucket.glob("*.toml")) if _declared_root(f) == prefix
            ]
            if len(matches) > 1:
                raise AmbientPolicyError(
                    f"ambiguous ambient policies for {prefix}: "
                    + ", ".join(str(m) for m in matches)
                )
            if matches:
                return matches[0], prefix
        if prefix.parent == prefix:
            return None
        prefix = prefix.parent
