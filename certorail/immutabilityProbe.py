import enum, importlib, inspect, json, pathlib, re, sys, types
from collections.abc import MutableMapping, MutableSequence, MutableSet

# exact types whose instances are immutable
ATOMIC = {
    type(None), bool, int, float, complex, str, bytes, range, slice,
    type(...), type(NotImplemented), types.MappingProxyType,
}
# base classes whose (stdlib) instances are immutable
ATOMIC_BASES = (enum.Enum, pathlib.PurePath, re.Pattern)
MAX_DEPTH, MAX_ITEMS = 8, 10_000

def immutable(obj, depth=0):
    if type(obj) in ATOMIC or isinstance(obj, ATOMIC_BASES):
        return True
    if isinstance(obj, (tuple, frozenset)):          # incl. struct sequences, namedtuples
        if depth >= MAX_DEPTH or len(obj) > MAX_ITEMS:
            return False
        return all(immutable(x, depth + 1) for x in obj)
    return False

def classify(obj):
    if inspect.ismodule(obj):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "module"}
    if isinstance(obj, type):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "class"}
    if inspect.isroutine(obj) or isinstance(obj, (classmethod, staticmethod, property)):
        return {"kind": "function", "type": type(obj).__name__}
    if immutable(obj):
        return {"kind": "immutable", "type": type(obj).__name__, "repr": repr(obj)[:80]}
    if isinstance(obj, (MutableSequence, MutableMapping, MutableSet, bytearray, memoryview)):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "container"}
    return {"kind": "mutable", "type": type(obj).__name__, "why": "object"}

def resolve(path, allowed_roots):
    if not path:
        raise ValueError("empty path")
    if allowed_roots is not None and path[0] not in allowed_roots:
        raise ImportError(f"module {path[0]!r} is not allowed")
    obj = importlib.import_module(path[0])
    for i, name in enumerate(path[1:], 1):
        try:
            obj = getattr(obj, name)
        except AttributeError:
            if not inspect.ismodule(obj):
                raise
            obj = importlib.import_module(".".join(path[: i + 1]))   # a submodule not yet imported
    return obj

def main():
    request = json.load(sys.stdin)
    allowed = request.get("allowed_roots")
    allowed = None if allowed is None else set(allowed)
    out = []
    for path in request["paths"]:
        try:
            out.append(classify(resolve(path, allowed)))
        except BaseException as e:                      # a bad path must not poison the batch
            out.append({"kind": "unresolvable", "error": f"{type(e).__name__}: {e}"[:200]})
    json.dump(out, sys.stdout)

if __name__ == "__main__":
    main()
