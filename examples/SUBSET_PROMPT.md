# Writing Python for the certorail sandbox

Programs are checked statically before they run. A program is rejected on any violation below, or if
any filesystem, subprocess or network operation cannot be proven to stay where the host's policy
allows. Rejections are reported per line: `violation:` means the program breaks a rule of the subset
or the analysis could not follow it; `denied:` means the program is well-formed but the policy does
not permit the operation. Fix the line named; do not work around the checker.

## Imports and names

- Only `import x` / `import x.y`. No `from … import`, no `import … as`.
- Standard library only. Forbidden modules (import is a violation) include: `os` (see allowlist),
  `subprocess`, `shutil`, `tempfile`, `glob`, `fileinput`, `linecache`, `filecmp`, `tarfile`, `zipfile`,
  `gzip`, `bz2`, `lzma`, `zlib`, `sqlite3`, `socket`, `ssl`, `asyncio`, `urllib` (except `urllib.parse`),
  `http`, `ftplib`, `smtplib`, `xmlrpc`, `xml`, `webbrowser`, `threading`, `_thread`, `multiprocessing`,
  `concurrent`, `signal`, `mmap`, `fcntl`, `resource`, `ctypes`, `importlib`, `pkgutil`, `runpy`, `code`,
  `codeop`, `types`, `marshal`, `pickle`, `copyreg`, `shelve`, `dbm`, `gc`, `inspect`, `traceback`, `dis`,
  `pdb`, `bdb`, `trace`, `doctest`, `timeit`, `cProfile`, `profile`, `py_compile`, `compileall`, `unittest`,
  `logging`, `configparser`, `optparse`, `platform`, `pwd`, `grp`, `getpass`, `crypt`, `netrc`, `builtins`,
  `sysconfig`, `distutils`, `setuptools`, `venv`, `pip`, `pydoc`, `tkinter`, `turtle`, `idlelib`,
  `antigravity`, `winreg`, `certorail`.
- `import urllib.parse` is allowed, for its text half only: `urlsplit`, `urlparse`, `urlunsplit`,
  `urlunparse`, `urljoin`, `urlencode`, `quote`, `quote_plus`, `unquote`, `unquote_plus`, `parse_qs`,
  `parse_qsl`. Nothing else under `urllib`.
- `os` is allowlisted member-by-member: `os.path.{join, basename, dirname, split, splitext, isabs, normpath,
  abspath, realpath, commonpath, exists, isfile, isdir}`, `os.sep`, `os.pathsep`, `os.linesep`, `os.fspath`,
  `os.PathLike`, `os.listdir`, `os.walk`. Nothing else under `os` (no `os.environ`, `os.getcwd`, `os.remove`, …).
- `typing` is likewise allowlisted, to annotation vocabulary only: `Annotated`, `Optional`, `Union`,
  `Literal`, `Any`, `Final`, `ClassVar`, `Callable`, `TypeAlias`, `Self`, `Never`, `NoReturn`, `TypeVar`,
  `ParamSpec`, `NamedTuple`, `TypedDict`, `Protocol`, `Generic`, `Sequence`, `Mapping`, `MutableMapping`,
  `Iterable`, `Iterator`, `Collection`. Not `get_type_hints`, `get_args`, `get_origin`, `cast`,
  `runtime_checkable`, `NewType` or any other helper.
- Forbidden members of otherwise-allowed modules include: `sys.{modules, path, meta_path, _getframe,
  settrace, setprofile, exc_info, excepthook, …}`, `functools.{partial, partialmethod, reduce, wraps}`,
  `operator.{attrgetter, methodcaller, itemgetter, getitem, setitem, delitem}`, `copy.{copy, deepcopy}`,
  `io.open`, `codecs.open`.
- A module name (`json`, `sys`, `pathlib`, …) and the `certora` namespace may appear only as the receiver of
  an attribute that is called or subscripted, or in a type position. Never as a value: no `m = json`,
  `f(sys)`, `f = os.path.join`, `g = certora.exec`. `sys.argv[1:]` is fine; `main(sys.argv)` is not.
- Never rebind (by assignment, parameter, loop target, `as`, `match` capture, `def`, `class`): an imported
  name, a builtin name, `certora`, or the name of a class defined in the program.
- No dunder identifiers anywhere (`__name__`, `__dict__`, `__class__`, `__import__`, `x.__foo__`); the only
  dunder that may be defined is `__init__`. There is no `if __name__ == "__main__":` — call `main()` at top level.
- Forbidden builtins: `getattr`, `setattr`, `delattr`, `vars`, `locals`, `globals`, `compile`, `eval`, `exec`,
  `breakpoint`, `help`, `slice`. `type(x)` is allowed; `type(name, bases, ns)` is not.
- Opening a file is only the bare builtin `open(...)` or a pathlib path's `.open()`. Never `open` reached through
  a module — `io.open`, `codecs.open`, `os.open`, `tokenize.open`, `pathlib.Path.open`, … are all forbidden.
- Forbidden attribute names on any receiver: frame/code/generator internals (`f_globals`, `f_locals`, `f_back`,
  `gi_frame`, `co_code`, …), `extract`, `extractall`, `load_extension`, `exec_module`, `load_module`,
  `unlink`, `rmdir`, `rename`, `symlink_to`, `hardlink_to`, `lchmod`, `expanduser`, `get_field`.
- No `async`/`await`, no `:=`, no `nonlocal`, no `global`.
- Callees must be a name or an attribute chain: `f()()`, `fs[0]()`, `(lambda: 0)()` are violations.
  Method calls on computed receivers (`f().g()`, `s.strip().lower()`) are allowed.
- Attribute assignment is allowed only on plain variables (`obj.x = v`): never on a module or class member,
  never through a computed receiver (`f().x = v`).

## Classes

- Every base must be a *name*: a class defined in the program, or one of `object`, `dict`, `list`, `tuple`, `set`,
  `frozenset`, `int`, `float`, `enum.Enum`, `enum.IntEnum`, `enum.Flag`, `enum.IntFlag`, `abc.ABC`,
  `typing.NamedTuple`, `typing.TypedDict`, `typing.Protocol`, `typing.Generic`, or any builtin exception class.
  In particular not `str`, `bytes`, `type`, `pathlib.*`, `enum.StrEnum`, nor any expression.
- No `metaclass=` or `**kwargs` in a class statement. No class factories: `type(...)` with 3 arguments,
  `abc.ABCMeta(...)`, the functional `enum` API (`enum.Enum("X", …)`, `enum.StrEnum(…)`),
  `dataclasses.make_dataclass`, `types.new_class`.
- Each class name is defined once.
- The only decorators (on functions, methods or classes) are `@staticmethod`, `@classmethod`, `@property`,
  `@dataclasses.dataclass`, `@functools.cache`, `@functools.lru_cache`, `@enum.unique` and `@abc.abstractmethod`,
  bare or with arguments. Do not define or use any other decorator.

## Filesystem operations are sinks

Every one of these is accepted only if the location of its path is proven (below) *and* the policy permits
that kind of access there; otherwise the program is rejected: `open(path, …)`, `os.listdir(p)`, `os.walk(p)`,
`os.path.exists/isfile/isdir(p)`, and on a `pathlib.Path`: `.open()`, `.read_text()`, `.read_bytes()`,
`.write_text()`, `.write_bytes()`, `.iterdir()`, `.glob()`, `.rglob()`, `.exists()`, `.is_file()`, `.is_dir()`,
`.mkdir()`, `.touch()`, `.chmod()`. These methods may only be called, never referenced (`f = p.read_text` is a
violation). The mode of `open` decides read vs write; listing and existence probes count as `list`.

Locations are relative to the sandbox root (the working directory); `"."` is the root. A literal beginning
with `/` names a location under the *filesystem* root instead. It is accepted only where the policy grants
that absolute location explicitly, and the two anchors never relate: no relative path satisfies an absolute
grant or vice versa. Prefer relative paths.

### What proves a location

- A relative string literal without `..` (`"data/x.txt"`); `pathlib.Path(...)` of such literals or of
  located values; `a / b`, `pathlib.Path(a, b, …)`, `os.path.join(a, b, …)`, `f"{a}/{b}"`, `a + "/" + b`
  where `a` is located and each further component is a literal or a *safe component* (below);
  `str(p)` / `os.fspath(p)` of a located `p`.
- Loop variables: `for p in base.iterdir() / base.glob(pat) / base.rglob(pat)` with `base` located (also through
  `sorted`, `list`, `reversed`, `enumerate`); `for name in os.listdir(...)` yields safe components;
  `for dirpath, dirnames, filenames in os.walk(top)` with `top` located gives a located `dirpath`.
- Parameters annotated with a location marker (see contracts); results of contracted functions.
- A containment guard (below) on a value whose text is otherwise unknown.

### What a guard establishes

A guard is `assert C`, or `if not C: raise …` / `return` / `continue` / `break` (`C` holds afterwards), or
`if C:` (`C` holds in the body). `C` is one of the forms below, or several joined with `and`. Anything else
establishes nothing — the analysis is never fooled, it just learns nothing, and the operation that needed
the fact is rejected.

Text facts, on a `str` `s` (or a `pathlib.Path` `p` where a `p` form is given):

- *no slash*: `"/" not in s`, `os.sep not in s`, `s.find("/") == -1`, `s.count("/") == 0`.
- *no parent traversal*: `".." not in s`, `".." not in s.split("/")`, `".." not in p.parts`.
- *not `..` itself*: `s != ".."`, `s not in (".", "..")`.
- *not absolute*: `not s.startswith("/")`, `not os.path.isabs(s)`, `s[0] != "/"`, `not p.is_absolute()`.
- *bare name* (no slash and not absolute; says nothing about `..`): `os.path.basename(s) == s`,
  `os.path.dirname(s) == ""`, `pathlib.PurePath(s).name == s`.
- *shape*: `s == "lit"`, `s in ("a", "b")`, `s == "a" or s == "b"`, `s.startswith("pre")`,
  `s.endswith(".txt")` (a tuple of literals also works for both), `re.fullmatch(r"…", s)` (also
  `… is not None`, `re.compile(r"…").fullmatch(s)`, `re.match(r"…\Z", s)` with no top-level `|`);
  `s.isalnum()`, `s.isalpha()`, `s.isdecimal()`, `s.isdigit()`, `s.isnumeric()`, `s.isidentifier()` (each of
  these also gives all four atoms above).
- *type*: `isinstance(s, str)`, `isinstance(p, pathlib.Path)`.

A **safe path component** needs *no slash* and either *no parent traversal* or *not `..`*.

Containment, making `s`/`p` a located value under `BASE` (a literal or a located value, possibly through
`str()`, `pathlib.Path()` or `.resolve()`):

- Lexical, trusted only once *no parent traversal* is established earlier in the same condition or block:
  `s.startswith("data/")` (the trailing slash is required; also `str(BASE) + "/"` or `+ os.sep`),
  `p.is_relative_to(BASE)`, `p.parent == BASE`, `BASE in p.parents`, `os.path.commonpath([s, BASE]) == BASE`.
- Resolving, needing nothing else: `p.resolve().is_relative_to(BASE)`,
  `os.path.realpath(s).startswith(str(BASE) + "/")`.

Rules of use:

- Guards apply in source order, once. Within a condition, put `isinstance` first and the `..` exclusion
  before the containment (or URL) test that depends on it:
  `assert isinstance(s, str) and ".." not in s and pathlib.Path(s).is_relative_to("repos")`.
- A value of unknown type — a JSON field, a dict lookup, the result of an unmodelled call — takes no text
  facts until its type is known: guard `isinstance(s, str)` first, or receive it through a parameter
  annotated `str`. `sys.argv[i]` and string-method results are already known to be `str`.
- A guard on a derived view says nothing about the variable: `s.strip().isalnum()` proves nothing about
  `s`. Assign the derived value to a variable, then guard that variable.
- A guard holds for the remaining statements of its block and nested blocks only; nothing established inside a
  `try` body, a loop body, or a `with` body (other than `with open(...)`) survives that statement.
- Facts belong to a variable and are lost when it is reassigned; a variable assigned anywhere inside a loop is
  unknown throughout the loop (except a `for` target bound by the header).
- Any string method (`replace`, `strip`, `lower`, `format`, `join`, …) yields a plain string with no path facts:
  re-establish them with a guard afterwards.
- Module-level constants are visible inside functions and keep their facts (`DATA = pathlib.Path("data")`
  at module level, then `DATA / name` inside a function). This holds only for a name assigned exactly once
  at module level; a name reassigned there carries no fact into functions. A parameter or local of the same
  name shadows the constant, as in normal Python.
- These prove nothing: `re.match`/`re.search` without `\Z`, `s.startswith("data")` without a trailing slash,
  `not s.startswith("..")`, `"../" not in s`, `os.path.normpath(s) == s`, `.lower() in …`, `p.exists()`,
  `len(s) > 0`, chained comparisons.

## Function contracts

- Only module-level functions may carry marker annotations; nested functions and methods may use plain types only.
  Each function name is defined once. Calls to a contracted function may not use `*args`/`**kwargs`.
  A function whose parameters carry markers is only ever called directly by name: never passed as a value
  (`key=f`, `map(f, …)`) or assigned to another name.
- Rely (parameter): `def f(p: typing.Annotated[pathlib.Path, certora.within("data")])` — inside `f`, `p` is
  located under `data/`; every call must pass an argument already proven to satisfy the annotation.
- Guarantee (return): `def g(s: str) -> typing.Annotated[str, certora.no_slash, certora.not_dot_dot]` — every
  `return` must return a value proven to satisfy it (build it, or guard it before returning). At a call site
  the guarantee attaches only when the call is the entire right side of an assignment: `x = g(...)` gives `x`
  the facts; `base / g(...)` or `f(g(...))` sees an unknown value. Assign first, then use the variable.
- Plain type annotations (`str`, `pathlib.Path`, `list[str]`) are not checked statically; scalar ones are
  checked at runtime. Markers go on a `str`/`pathlib.Path` parameter or return value, or on the element type
  of a typed container (below); never on `*args`/`**kwargs`.
- Markers, under `typing.Annotated[<str or pathlib.Path>, …]`:
  `certora.within(prefix, leaf=…)` (at or below `prefix`; `"."` is the root),
  `certora.exactly("a/b", …)` (components: literals, `certora.matches(r)`, `certora.one_of("a", "b")`),
  `certora.matches(r"…")`, `certora.one_of("a", "b")`, `certora.seq("pre-", certora.matches(r"\d+"))`,
  `certora.no_slash`, `certora.no_parent_traversal`, `certora.not_absolute`, `certora.not_dot_dot`,
  `certora.validated("atom", …)` (the value carries the named policy facts — see validations),
  `certora.url(scheme="https", netloc="api.github.com", path_within="/repos")` (the value is a URL with these
  components; each keyword is optional and claims only what it names — see network).
  A location marker (`within`/`exactly`) does not combine with text markers; constrain the file name with
  `within(prefix, leaf=certora.matches(...))`. At most one location marker and one regex marker per annotation.
  `validated` combines with anything.

## Typed containers

A `list` or `set` whose elements all carry facts, declared and tracked by name:

```python
slugs: list[typing.Annotated[str, certora.no_slash, certora.not_dot_dot]] = []
```

- Tracking begins only at an annotated assignment (`x: list[typing.Annotated[…]] = …`,
  `set[…]` likewise) whose right side is a constructor: a display `[a, b]` / `{a, b}`, `list()` / `set()`,
  the copy `list(other)` / `set(other)`, or a comprehension with exactly one `for` (its element, evaluated
  under the loop variable and the `if` filters, must satisfy the annotation). Every element is checked at
  construction. `x: list[…] = y` is not a constructor: spell the copy as `list(y)`.
- Reads give the element facts: `x[i]`, `for e in x` (also through `sorted`, `list`, `tuple`, `reversed`,
  `iter`, `enumerate`), `x.pop()`, `len(x)`, `v in x`, `if x:`, `list(x)`, `set(x)`, iterating `x` in a
  comprehension.
- Writes must satisfy the annotation: `x.append(v)`, `x.insert(i, v)`, `x[i] = v` (a direct single-target
  store only), `x.extend(ys)` / `x += ys` (`ys` a display or another typed container with at least as strong an
  element type), `x.add(v)`; also `x.remove(v)`, `x.discard(v)`, `x.clear()`, `x.sort()`.
- **Any other use of the name is a violation**: aliasing (`y = x`), passing it to `print`, `json.dumps`, or
  a parameter that is not itself a typed container, `(x[0], z) = …`, `x[i] += v`, `x[1:] = …`, storing it in
  another container. `x[1:]` is a copy with no facts (allowed, useless).
- Passing: a `list[P]` argument binds only to a `list[P]` parameter with the *same* element type (the callee
  may write), or to a `typing.Sequence[Q]` parameter with `P` at least as strong as `Q` — inside such a function
  the parameter is read-only (no mutators, no aliasing). A `Sequence` can only be received, never constructed.
- Returning: a *local* typed container may be returned against `-> list[…]` / `-> set[…]` with the same
  element type (it moves out; the caller's variable receives the facts). A *parameter* container may not be
  returned.
- Element facts die like any other: an environmental validation fact on the elements is lost at the next
  effectful call (see validations); text facts and pure facts persist.
- Nested containers, dicts and tuples of marked values are not tracked; `list[str]` without `Annotated` is an
  ordinary untracked list.

## Subprocesses

- Only `certora.exec(program, *args, cwd=<located path>)`. `program` is a string literal (or a name bound to
  one); arguments are separate strings, no `*`/`**` splats; the only keyword is `cwd`, and it is required and
  must be a proven location. No shell; output is captured. A call the host refuses raises.
- The result is a `CompletedProcess` with `.returncode`, `.stdout` and `.stderr` (bytes), plus decoded views:
  `.stdout_string()`, `.stdout_lines()`, `.stderr_string()`, `.stderr_lines()` (UTF-8, lines split like
  `str.splitlines`). **The views raise `certora.CalledProcessError` when the command exited non-zero**, so
  `for line in certora.exec("git", "log", "--oneline", cwd=repo).stdout_lines()[:10]:` is the whole
  pipeline and fails loudly if `git` did. To handle failure yourself, test `.returncode` and read the bytes.
  There is no shell: do filtering (`head`, `tail`, `grep`, `wc`) in Python on the lines.
- The policy may pin subcommands: if it declares `git log` and `git push origin`, any other `git`
  invocation — including one whose subcommand is not a literal — is rejected.
- The policy may refuse arguments it cannot vouch for: anything other than a string literal, a module-level
  constant, or a proven path (an f-string or `.strip()` result is not vouched for). It may confine path
  arguments to locations. Spell arguments out as literals where you can; pass paths as located values.
- Arguments after the subcommand may be required to carry validation facts; a value whose text is statically
  known (a literal, a constant) automatically satisfies any fact the policy defines as a text property or whose
  checker the host can run on the literal directly — no `certora.check` needed for constants.

## Network

- Only `certora.network.get/head/delete(url, headers=…, timeout=…)` and
  `certora.network.post/put/patch(url, headers=…, body=<bytes>, timeout=…)`. One positional argument, the
  URL; no other keywords; no splats. Returns a response with `.status`, `.reason`, `.headers` (a tuple of
  pairs), `.body` (bytes) and `.url` (the final URL after redirects, which the host follows). A refused or
  failed request raises.
- The URL's scheme and host must be proven, and the policy must permit that host, port and method. A string
  literal is proven outright. A URL built from parts (`f"https://api.github.com/repos/{owner}"`) is not:
  guard the finished string, with `u` the variable holding it:
  `urllib.parse.urlsplit(u).scheme == "https"`, `urllib.parse.urlsplit(u).netloc == "api.github.com"` (or
  `in ("a.com", "b.com")`), `urllib.parse.urlsplit(u).path == "/v1/users"`,
  `urllib.parse.urlsplit(u).path.startswith("/repos/")` (with `".." not in u` earlier in the condition).
  `urlparse` is accepted for `.scheme` and `.netloc`, not for `.path`. Once a value is read as a URL no more
  text facts attach to it: put text guards first.
- The policy may require validation facts on the URL (see validations): a literal URL that matches the
  policy's definition of the fact carries it; a computed URL needs a `certora.check` on it first.
- Headers and bodies are ordinary values; credentials in headers are not forwarded across hosts on redirect.
- A network call is an effectful call: it kills environmental validation facts (below).

## Runtime validations

- The host's policy may declare named validations: runtime predicates, run by the host, whose success
  establishes policy-defined facts ("atoms"). `certora.check(name, key=value, ..., cwd=<located path>)` runs
  the validation `name` (a string literal) and raises on failure, so the statements after it may rely on
  what it established. It must be a bare statement. The keywords are fixed by the validation's declaration;
  `cwd=` is required and must be a proven location when the validation declares one, and must be omitted when
  it does not; other arguments are strings.
- A fact is established on the *variable* passed in the corresponding keyword — pass a plain variable, not an
  expression. `certora.check_single(name, value)` (plus `cwd=` if declared) is the expression form for
  validations with exactly one parameter: it returns `value` on success and the fact rides the *result* —
  `branch = certora.check_single("not-force-check", sys.argv[1])` — so it also works as the element of a
  container comprehension. The argument itself gains nothing; use the result.
- Facts are consumed by policy rules ("`git push` requires a cwd validated by X") and by
  `certora.validated("…")` markers in `typing.Annotated` contracts.
- A fact the policy defines by a regex needs no check: a literal matching it carries it, and
  `assert re.fullmatch(r"…", s)` with that exact regex text establishes it on a dynamic `s`. A
  different guard for the same property is not recognised.
- Every validation fact dies when its variable is reassigned or a new value is derived from it.
  A fact about the *environment* (e.g. "this directory is a clean checkout") additionally dies at every call
  that may have effects: any call to a program-defined function, a method on a non-path value, a class
  instantiation, `certora.exec`, `certora.network.*`, and any `certora.check` not declared effect-free.
  Effect-free operations preserve it: `str`, `repr`, `len`, `print`, `format`, `int`, `float`, `bool`,
  `isinstance`, `os.fspath`, `os.path.*`, `pathlib.Path(...)`, `re.fullmatch/match/search/compile`,
  `json.dumps/loads`, reads and listings on a proven path, and validations the policy declares effect-free.
  Check immediately before the operation that needs the fact; inside a loop, check inside the body. Facts about
  the value's *text* alone (as declared by the policy) survive any number of calls. In a comprehension only
  text facts accumulate: an environmental `check_single` establishes nothing on the container.

## Everything else

Ordinary Python is fine: functions, classes with the bases above, dataclasses (`@dataclasses.dataclass`),
`enum.Enum`, comprehensions, lambdas, `match`, `try`/`except` with builtin or module exception classes,
`with open(...)`, f-strings, `json`, `re`, `math`, `collections`, `itertools`, `datetime`, `pathlib`,
`urllib.parse`.

A small program using most of the above, against a policy that permits read, write and list under `repos/`,
`git log` and `git push origin` there (the push requiring an `org-checkout` fact on the cwd and a `not-force`
fact on its arguments), and `GET` on `api.github.com`:

```python
import json
import pathlib
import sys
import typing

REPOS = pathlib.Path("repos")


def slug_of(name: str) -> typing.Annotated[str, certora.no_slash, certora.not_dot_dot]:
    # untrusted API data becomes a safe path component by exactly one guard
    assert "/" not in name and name not in (".", "..")
    return name


def push(repo: typing.Annotated[pathlib.Path, certora.within("repos"), certora.validated("org-checkout")],
         branch: typing.Annotated[str, certora.validated("not-force")]) -> bool:
    result = certora.exec("git", "push", "origin", branch, cwd=repo)
    return result.returncode == 0


def main() -> None:
    response = certora.network.get("https://api.github.com/orgs/certora/repos")
    names = [r["name"] for r in json.loads(response.body)]
    branches: list[typing.Annotated[str, certora.validated("not-force")]] = [
        certora.check_single("not-force-check", b) for b in sys.argv[1:]
    ]
    for name in names:
        slug = slug_of(name)                     # the guarantee lands on the variable
        repo = REPOS / slug                      # located: repos/<safe component>
        if not (repo / ".git").is_dir():
            continue
        (repo / "AUDIT.md").write_text("checked\n")
        for branch in branches:
            certora.check("org-repo", cwd=repo)  # right before the use: any effectful call kills it
            if not push(repo, branch):
                print(f"push of {branch} to {name} failed")


main()
```
