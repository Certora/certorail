"""``certorail policy apply``: bring an installed ruleset into a root policy, bindings and all,
and the ruleset inventory ``certorail policy list`` prints.

    certorail policy apply git.toml where=. remote='{ one-of = ["origin"] }' branch='{ atoms = ["git.ref-name"] }' push-gate='[]'
    certorail policy apply git.toml                 # interactive: asks for each parameter the load says is unbound
    certorail policy list [--root DIR]              # every installed ruleset, described, with who applies it

``apply`` appends one ``[[apply]]`` table to the policy governing ``--root`` (or ``--policy FILE``),
then loads the result against the installed tree before a byte lands, exactly as ``edit`` does.
A binding is ``KEY=VALUE`` with VALUE in TOML (``true``, ``[]``, ``{ one-of = ["origin"] }``); a
value that is not TOML is a string, so ``where=.`` and ``where=repos`` read as one expects. When
the load reports ``parameter 'x' is not bound`` and a terminal is there, ``apply`` asks for ``x``
with the parameter's own ``description`` and tries again; without a terminal it stops and lists
what is missing. It refuses a ruleset the policy already applies, and one the base ruleset
already applies to every root (unless the policy opts out), because a second application
would be a duplicate at best and a conflict at worst.

Deterministic, no model involved. What a ruleset means is its author's to say in its
``description`` keys; this verb only reads them back.
"""
import pathlib
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence

from .install import InstallError, Placement, _place, edit_problems
from .policydir import AmbientPolicyError, find_policy
from .policyfile import BASE_RULESET, rulesets_dir

type Prompt = Callable[[str], str]
type Say = Callable[[str], None]
type Value = str | bool | int | list["Value"] | dict[str, "Value"]

# ---------------------------------------------------------------------------------------------
# what is installed: read raw, so a document that would not load still describes itself
# ---------------------------------------------------------------------------------------------


def document(path: pathlib.Path) -> dict | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    return data if isinstance(data, dict) else None


def applied_by(data: Mapping[str, object]) -> tuple[str, ...]:
    applies = data.get("apply")
    return tuple(
        str(a["ruleset"]) for a in (applies if isinstance(applies, list) else [])
        if isinstance(a, dict) and isinstance(a.get("ruleset"), str)
    )


def base_applies() -> tuple[str, ...] | None:
    """The rulesets the installed base applies, or None when there is no base."""
    path = rulesets_dir() / BASE_RULESET
    if not path.is_file():
        return None
    data = document(path)
    return () if data is None else applied_by(data)


def description_of(ruleset: str) -> str | None:
    data = document(rulesets_dir() / ruleset)
    if data is None:
        return None
    description = data.get("description")
    return description if isinstance(description, str) else None


def params_of(ruleset: str) -> dict[str, tuple[str, str | None]]:
    """name -> (kind, description) for the ruleset's ``[params]``, read raw."""
    data = document(rulesets_dir() / ruleset)
    params = data.get("params") if data is not None else None
    if not isinstance(params, dict):
        return {}
    out: dict[str, tuple[str, str | None]] = {}
    for name, decl in params.items():
        if not isinstance(decl, dict):
            continue
        kind = decl.get("kind")
        description = decl.get("description")
        out[str(name)] = (str(kind) if isinstance(kind, str) else "?", description if isinstance(description, str) else None)
    return out


def installed_rulesets() -> list[str]:
    return sorted(p.name for p in rulesets_dir().glob("*.toml")) if rulesets_dir().is_dir() else []


# ---------------------------------------------------------------------------------------------
# bindings: KEY=VALUE in, TOML out
# ---------------------------------------------------------------------------------------------


def parse_binding(text: str) -> tuple[str, Value]:
    """``key=value``: the value read as TOML (``true``, ``[]``, ``{ one-of = ["x"] }``, ``"x"``),
    or, when it is not TOML, as the string it is (``where=.``, ``where=repos``)."""
    key, sep, raw = text.partition("=")
    key = key.strip()
    if not sep or not key:
        raise InstallError([f"{text!r}: a binding is KEY=VALUE"])
    return key, parse_value(raw.strip())


def parse_value(raw: str) -> Value:
    try:
        return tomllib.loads(f"v = {raw}")["v"]
    except (tomllib.TOMLDecodeError, KeyError):
        return raw


def toml_value(value: Value) -> str:
    match value:
        case bool():
            return "true" if value else "false"
        case int():
            return str(value)
        case str():
            # a literal string keeps backslashes (a regex leaf) as typed; basic only for a quote
            if "'" not in value:
                return f"'{value}'"
            return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        case list():
            return "[" + ", ".join(toml_value(v) for v in value) + "]"
        case dict():
            return "{ " + ", ".join(f"{k} = {toml_value(v)}" for k, v in value.items()) + " }"


def render_apply(ruleset: str, bindings: Mapping[str, Value]) -> str:
    lines = ["", "[[apply]]", f'ruleset = "{ruleset}"']
    width = max((len(k) for k in bindings), default=0)
    lines += [f"{k.ljust(width)} = {toml_value(v)}" for k, v in bindings.items()]
    return "\n".join(lines) + "\n"


def unbound(problems: Sequence[str]) -> list[str]:
    """The parameter names the loader reported as not bound, in order, once each."""
    out: list[str] = []
    for line in problems:
        head, sep, _ = line.partition(" is not bound")
        if sep and "parameter '" in head:
            name = head.rsplit("parameter '", 1)[1].rstrip("'")
            if name not in out:
                out.append(name)
    return out


def ask_binding(name: str, kind: str, description: str | None, prompt: Prompt, say: Say) -> Value:
    """One parameter's value from the terminal, shaped by its kind and explained by its
    description; a directory defaults to ``.``, a constraint is re-asked until it is a table."""
    about = f" ({description})" if description else ""
    if kind == "directory":
        raw = prompt(f"{name}{about} -- a directory, or several comma-separated [.]: ").strip()
        dirs: list[Value] = [p.strip() for p in raw.split(",") if p.strip()]
        if len(dirs) > 1:
            return dirs
        return dirs[0] if dirs else "."
    if kind == "atom":
        raw = prompt(f"{name}{about} -- atom names, comma-separated; empty for none: ").strip()
        atoms: list[Value] = [p.strip() for p in raw.split(",") if p.strip()]
        return atoms
    if kind == "bool":
        raw = prompt(f"{name}{about} -- true or false [false]: ").strip().lower()
        return raw in ("true", "yes", "y")
    while True:
        raw = prompt(f"{name}{about} -- a constraint table, e.g. {{ one-of = [\"origin\"] }} or {{ any = true }}: ").strip()
        value = parse_value(raw)
        if isinstance(value, dict):
            return value
        say(f"  {raw!r} is not a table")


# ---------------------------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------------------------


def apply_ruleset(
    target: pathlib.Path, prefix: pathlib.Path | None, ruleset: str, bindings: Mapping[str, Value], *,
    prompt: Prompt | None, say: Say,
) -> int:
    """Append ``[[apply]] ruleset = <ruleset>`` with *bindings* to *target*, asking for what the
    load says is unbound when a *prompt* is there, and rotate the result into place only when it
    loads. Exit status 0 when applied, 1 otherwise; nothing lands on 1."""
    if not (rulesets_dir() / ruleset).is_file():
        say(f"{ruleset} is not installed under {rulesets_dir()} (`certorail policy list` shows what is)")
        return 1
    original = target.read_text(encoding="utf-8")
    data = document(target)
    if data is None:
        say(f"{target} does not parse; `certorail policy edit` first")
        return 1
    if ruleset in applied_by(data):
        say(f"{target} already applies {ruleset}; `certorail policy edit` changes its bindings")
        return 1
    covered = base_applies() or ()
    if ruleset in covered and data.get("base", True) is not False:
        say(f"the base ruleset already applies {ruleset} to every root, this one included; "
            f"a second application would conflict (base = false in the policy opts out)")
        return 1
    params = params_of(ruleset)
    for key in bindings:
        if key not in params:
            say(f"{key!r} is not a parameter of {ruleset} (its parameters: {', '.join(params) or 'none'})")
            return 1
    bound: dict[str, Value] = dict(bindings)
    while True:
        text = original.rstrip("\n") + "\n" + render_apply(ruleset, bound)
        with tempfile.TemporaryDirectory(prefix="certorail-apply-") as tmp:
            draft = pathlib.Path(tmp) / target.name
            draft.write_text(text, encoding="utf-8")
            problems = edit_problems(draft, prefix)
        if not problems:
            _place([Placement(target, text.encode("utf-8"))], replace=True)
            say(f"applied {ruleset} in {target}:")
            for line in render_apply(ruleset, bound).strip("\n").splitlines():
                say(f"  {line}")
            if prefix is not None:
                say(f"review it: certorail --describe --root {prefix}")
            return 0
        missing = [name for name in unbound(problems) if name in params and name not in bound]
        if missing and prompt is not None:
            for name in missing:
                kind, description = params[name]
                bound[name] = ask_binding(name, kind, description, prompt, say)
            continue
        say(f"{ruleset} does not apply to {target} as bound:")
        for line in problems:
            say(f"  {line}")
        if missing:
            say("bind the missing parameters on the command line, KEY=VALUE:")
            for name in missing:
                kind, description = params[name]
                say(f"  {name} ({kind}{': ' + description if description else ''})")
        return 1


def edit_target(root: pathlib.Path | None, policy: pathlib.Path | None) -> tuple[pathlib.Path, pathlib.Path | None]:
    """What ``apply`` edits: the file named, or the ambient policy governing *root* -- and the
    root it must keep declaring. (The same resolution ``edit`` uses.)"""
    from .install import _edit_target

    return _edit_target(root, policy)


# ---------------------------------------------------------------------------------------------
# the inventory
# ---------------------------------------------------------------------------------------------


def ruleset_lines(root: pathlib.Path | None) -> list[str]:
    """Every installed ruleset: its description, its parameters, and who applies it -- the base,
    another ruleset, or the policy governing *root* when one is given."""
    installed = installed_rulesets()
    if not installed:
        return ["  none"]
    covered = base_applies() or ()
    by_ruleset: dict[str, list[str]] = {}
    for name in installed:
        data = document(rulesets_dir() / name)
        for inner in applied_by(data) if data is not None else ():
            by_ruleset.setdefault(inner, []).append(name)
    by_policy: tuple[str, ...] = ()
    policy_file: pathlib.Path | None = None
    if root is not None:
        try:
            found = find_policy(root.resolve())
        except AmbientPolicyError:
            found = None
        if found is not None:
            policy_file = found[0]
            data = document(policy_file)
            by_policy = applied_by(data) if data is not None else ()
    lines: list[str] = []
    for name in installed:
        if name == BASE_RULESET:
            lines.append(f"  {name}: the base ruleset, applied to every root that does not opt out; applies {', '.join(covered) or 'nothing'}")
            continue
        lines.append(f"  {name}: {description_of(name) or '(no description)'}")
        who = []
        if name in covered:
            who.append("the base")
        if name in by_ruleset:
            who.append(", ".join(by_ruleset[name]))
        if name in by_policy and policy_file is not None:
            who.append(str(policy_file))
        if who:
            lines.append(f"    applied by {'; '.join(who)}")
        params = params_of(name)
        if params:
            lines.append("    parameters: " + "; ".join(
                f"{p} ({kind}{': ' + d if d else ''})" for p, (kind, d) in params.items()
            ))
        if name not in covered and name not in by_policy:
            hint = f'certorail policy apply {name}' + (" where=." if "where" in params else "")
            lines.append(f"    {hint}")
    return lines
