"""Seatbelt profile text: the one place a path or a pattern becomes SBPL, so every string is
escaped the same way wherever a profile is written -- the program's jail (``host``) and the tools'
(``sandbox.seatbelt``, ``childjail``).

A path is a Scheme string: ``\\`` and ``"`` escaped. A pattern is a regex literal (``#"..."``),
whose own backslashes are the regex's, so a pattern that would need a ``"`` inside the literal is
refused (None) rather than guessed at: the caller omits the location and says so."""


def string(text: str) -> str:
    """*text* as an SBPL string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def subpath(path: str) -> str:
    return f"(subpath {string(path)})"


def literal(path: str) -> str:
    return f"(literal {string(path)})"


def regex(pattern: str) -> str | None:
    """A ``(regex #"...")`` filter, or None when the pattern cannot sit in the literal."""
    if '"' in pattern:
        return None
    return f'(regex #"{pattern}")'
