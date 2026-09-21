# Writing Python for the certorail sandbox

The `certorail` sandbox lets you run "arbitrary" Python programs that can be proven to
conform to user specific security policies. In addition to kernel-level runtime enforcement,
`certorail` statically analyzes your Python programs to judge conformance to the user's provided
policies.

In full generality, Python is near impossible to statically analyze; accordingly the Python you author
must fall within a restricted subset that is amenable to static checking. In addition, conformance to security
policy requires reasoning about the effects of the program you author. Thus all effectful operations *must*
go through specific, named entry points.

The subset of Python that is statically analyzable by certorail is called `SafePy`. Programs can be rejected
by certorail for two reasons: failure to fall within the `SafePy` dialect, or violating the security policy.
In the former case, the rejection is labeled with `violation`, the latter is labeled `denied`.
We will describe `SafePy` first; a description of how to work within the policy follows.

## The SafePy Dialect

### Imports and names

- Only `import x` / `import x.y`. No `from ... import`, no `import ... as`.
- Standard library only. Forbidden modules (import is a violation) include:
  * `os` (with narrow exceptions, see allowlist)
  * Process/Code execution: `subprocess`, `shutil`, `runpy`, `code`, `timeit`, `profile`, `py_compile`, `compileall`, `unittest`
  * Filesystem accessors: `tempfile`, `glob`, `fileinput`, `linecache`, `filecmp`, `sqlite3`, `xml`, `mmap`, `fcntl`, `resource`
  * Compression modules: `tarfile`, `zipfile`, `gzip`, `bz2`, `lzma`, `zlib`
  * Network: `socket`, `ssl`, `asyncio`, `urllib` (except `urllib.parse`, see below), `http`, `ftplib`, `smtplib`, `xmlrpc`, `webbrowser`,
  * Concurrency/execution internals: `threading`, `_thread`, `multiprocessing`, `concurrent`, `signal`, `ctypes`, `importlib`, `pkgutil`, `codeop`, `types`, `marshal`, `pickle`, `copyreg`, `shelve`, `dbm`, `gc`, `inspect`, `traceback`, `dis`,
    `pdb`, `bdb`, `trace`, `doctest`, `cProfile`, `builtins`, `sysconfig`, `distutils`, `setuptools`, `venv`, `pip`
  * Other: `logging`, `configparser`, `optparse`, `platform`, `pwd`, `grp`, `getpass`, `crypt`, `netrc`, `pydoc`, `tkinter`, `turtle`, `idlelib`, `antigravity`, `winreg`, `certorail` (see below)
- `import urllib.parse` is allowed, for its text half only: `urlsplit`, `urlparse`, `urlunsplit`,
  `urlunparse`, `urljoin`, `urlencode`, `quote`, `quote_plus`, `unquote`, `unquote_plus`, `parse_qs`,
  `parse_qsl`. Nothing else under `urllib` may be imported.
- `os` is allowlisted member-by-member: `os.path.{join, basename, dirname, split, splitext, isabs, normpath,
  abspath, realpath, commonpath, exists, isfile, isdir}`, `os.sep`, `os.pathsep`, `os.linesep`, `os.fspath`,
  `os.PathLike`, `os.listdir`, `os.walk`. Nothing else under `os` (no `os.environ`, `os.getcwd`, `os.remove`, …).
- `typing` is likewise allowlisted, to annotation vocabulary only: `Annotated`, `Optional`, `Union`,
  `Literal`, `Any`, `Final`, `ClassVar`, `Callable`, `TypeAlias`, `Self`, `Never`, `NoReturn`, `TypeVar`,
  `ParamSpec`, `NamedTuple`, `TypedDict`, `Protocol`, `Generic`, `Sequence`, `Mapping`, `MutableMapping`,
  `Iterable`, `Iterator`, `Collection`.
- In addition, some members of otherwise allowed modules are forbidden:
  * `sys`: `modules`, `path`, `meta_path`, `_getframe`, `settrace`, `setprofile`, `exc_info`, `excepthook`, (among others),
  * `functools`: `partial`, `partialmethod`, `reduce`, `wraps`,
  * `operator` `attrgetter`, `methodcaller`, `itemgetter`, `getitem`, `setitem`, `delitem`,
  * `copy`: `copy`, `deepcopy`
  * `io`: `open`
  * `codecs`: `open`,
- A module name (`json`, `sys`, `pathlib`, …) and the `certora` namespace may appear only as the receiver of
  an attribute that is called or subscripted, or in a type position. Never as a value: no `m = json`,
  `f(sys)`, `f = os.path.join`, `g = certora.exec`. `sys.argv[1:]` is fine; `main(sys.argv)` is not.
- Never rebind (by assignment, parameter, loop target, `as`, `match` capture, `def`, `class`): an imported
  name, a builtin name, `certora`, or the name of a class defined in the program (the program is rejected if this is done)
- No dunder identifiers anywhere (`__name__`, `__dict__`, `__class__`, `__import__`, `x.__foo__`); the only
  dunder that may be defined is `__init__`. There is no `if __name__ == "__main__":` — call `main()` at top level.

Most of the environment interactions are accessed through the dedicated `certora` module. Do **NOT** import
this module yourself; it is preloaded into the namespace of your program by the `certorail` sandbox.

### Builtins

The following builtins: `getattr`, `setattr`, `delattr`, `vars`, `locals`, `globals`, `compile`, `eval`, `exec`,
  `breakpoint`, `help`, `slice`. `type(x)` is allowed; `type(name, bases, ns)` is not.

### Attributes

- Forbidden attribute names on any receiver: frame/code/generator internals (`f_globals`, `f_locals`, `f_back`,
  `gi_frame`, `co_code`, …), `extract`, `extractall`, `load_extension`, `exec_module`, `load_module`,
  `unlink`, `rmdir`, `rename`, `symlink_to`, `hardlink_to`, `lchmod`, `expanduser`, `get_field`.
- Attribute assignment is allowed only on plain variables (`obj.x = v`): never on a module or class member,
  never through a computed receiver (`f().x = v`).

### Method Invocation

- Callees must be a name or an attribute chain: `f()()`, `fs[0]()`, `(lambda: 0)()` are violations.
  Method calls on computed receivers (`f().g()`, `s.strip().lower()`) are allowed.

### Classes

- Every base must be a *name*: either a class defined in the program, or one of `object`, `dict`, `list`, `tuple`, `set`,
  `frozenset`, `int`, `float`, `enum.Enum`, `enum.IntEnum`, `enum.Flag`, `enum.IntFlag`, `abc.ABC`,
  `typing.NamedTuple`, `typing.TypedDict`, `typing.Protocol`, `typing.Generic`, or any builtin exception class.
- `str`, `bytes`, `type`, `pathlib.*`, `enum.StrEnum`, may **not** be subclassed
- Computed base classes are forbidden
- No `metaclass=` or `**kwargs` in a class statement.
- No class factories: `type(...)` with 3 arguments, `abc.ABCMeta(...)`, the functional `enum` API (`enum.Enum("X", …)`, `enum.StrEnum(…)`),
  `dataclasses.make_dataclass`, `types.new_class`.
- Each class name is defined once.
- The only decorators (on functions, methods or classes) are `@staticmethod`, `@classmethod`, `@property`,
  `@dataclasses.dataclass`, `@functools.cache`, `@functools.lru_cache`, `@enum.unique` and `@abc.abstractmethod`,
  bare or with arguments. Do not define or use any other decorator.

### Other Restrictions
- No `async`/`await`, no `:=`, no `nonlocal`, no `global`.

## Policy Enforcement

Certorail focuses on controlling 3 types of effectful operations: filesystem writes, network requests, and subprocess spawning.
In addition, Certorail prevents sensitive data disclosure by restricting the network locations and files that can be read by the
process. Each broad category of effect/source (filesystem, network, process) is treated in the following sections.

### Filesystem

The Certorail policy defines a fixed set of locations that the Certorail process can access. Any filesystem
access (read, write, or directory listing) that cannot be proven to fall within one of these allowed locations leads the program being
rejected. Filesystem permissions are stated as a combination of zero or more "relative path grants", and zero or more
"absolute path grants". "Relative path grants" are always resolved from the CWD of the Certorail process.

#### Direct operations are "sinks"

Every one of these operations accesses a path; the path component `p` must be
proven (see below) to fall within the relevant access grant:
* open builtin: `open(p, …)`
* `os` accessors: `os.listdir(p)`, `os.walk(p)`, `os.path.exists/isfile/isdir(p)`
* `pathlib.Path` methods: `p.open()`, `.read_text()`, `.read_bytes()`,
   `.write_text()`, `.write_bytes()`, `.iterdir()`, `.glob()`, `.rglob()`, `.exists()`, `.is_file()`, `.is_dir()`,
   `.mkdir()`, `.touch()`, `.chmod()`, `.replace(target)` (both the path and `target` are writes).

The `pathlib.Path` methods must be fully applied at reference; `f = p.read_text` is a violation.

The mode of `open` (which must be resolvable to a static string at analysis time) determines
the grant that allows access to `p`, `r` requires read grant, `w` a write grant.
Listing and existence probes count as `list`. The writer methods `write_text` and `write_bytes` require
a "write" graph.

The current sandbox root (CWD of the Certorail process) is denoted `"."` as per usual.

#### What proves a location

As described above, the paths that flow to filesystem sinks must be proven to fall within the filesystem
grants of the policy. The following describes (roughly) how how Certorail infers "located facts"; each located
fact carries enough information to allow Certorail to place a filesystem access *through* that fact at a
(potentially approximate) location on the filesystem. Filesystem accesses through values that are not "located facts"
are denied.

- A string literal that is a valid POSIX path (e.g., `"data/x.txt"` or `/home/user/data.txt`) denotes the named
 located path precisely.
- A `pathlib.Path(...)` of such literals is also modeled precisely.
- Composition: if `a` is a located fact, child traversal is modeled. `a / b`, `pathlib.Path(a, b, …)`,
  `os.path.join(a, b, …)`, `f"{a}/{b}"`, `a + "/" + b`, where `b` and each further component is a literal or a *safe component* (below)
- Type conversion: `str(a)` / `os.fspath(a) / pathlib.Path(a)` for any located fact `a` is itself a "located fact"
  at the same location.
- Loop variables: `for p in base.iterdir() / base.glob(pat) / base.rglob(pat)` where `base` is located yield located facts
  (these facts survive through `sorted(base.iterdir())`, `list(...)`, `reversed(...)`, `enumerate(...)`).
- `for name in os.listdir(...)` yields *safe components* (see below)
- `for dirpath, dirnames, filenames in os.walk(top)` where `top` is located yields location fact on `dirpath`.
- Parameters annotated with a location marker (see contracts); results of contracted functions.
- A containment guard (below) on a value whose text is otherwise unknown.

#### Path Safety

A **safe path component** is a component that can be appended to an existing located fact (either via string concatenation or
`pathlib.Path`'s `/` operator) and provably yield a child path (modulo filesystem links).

In particular a **safe path component** must satisfy two conditions:
* It must not be an absolute path, i.e., it cannot start with `/`
* It must not contain a parent directory traversal, i.e., `../`

Thus `foo/bar` is a safe path component (it definitely descends in the filesystem tree), `foo/bar/../baz` is *technically*
safe (it ultimately resolves to `foo/baz`) but Certorail conservatively rejects *any* parent traversal.

#### On Precision

Over-approximation accumulates in a located fact, and precise located facts may lose their precision at control-flow
join, as usual in a static analysis. A located fact may simply encode "some path below `data/repos`" (usually
denoted `data/repos/**`). Further, `for p in base.iterdir()` attaches to `p` the fact "some direct descendant of the location
denoted by `base`". If `base` is already imprecise (e.g., its located fact is `data/repos/**`) then the "located fact" of `p`
will likewise be precise; Certorail can only conclude the path of `p` points somewhere within `data/repos/**`.

Precision can be recovered via runtime guards (see below), but you should strive whenever possible
to write code which doesn't require these runtime assertions. For straightforward, "simple" traversal of filesystem
facts (without computed names, for example) the Certorail inference works out of the box.

`certora.reveal_fact(x)` is a runtime inert function in the style of `typing.reveal_type` which requests `certorail`
dump all information it knows about the name `x` (named variables only, no complex expressions). You should
only use this feature only as a last resort if you are unable to convince Certorail to accept a program you are certain
is correct. Do **NOT** abuse this feature to "double check" the inference of certorail before running scripts "for real";
do not second guess Certorail until it gives you a reason to do so.

#### Recovering Precision with Runtime Guards

A guard is `assert C`, or `if not C: raise …` / `return` / `continue` / `break` (`C` holds afterwards), or
`if C:` (`C` holds in the body). `C` is one of the forms below, or several joined with `and`.

##### Text Facts

In addition to "located facts", program values may be associated with "atoms" that establish facts
about their shape.

Text facts, on a `str` `s` (or a `pathlib.Path` `p` where a `p` form is given):

- *no slash*: `"/" not in s`, `os.sep not in s`, `s.find("/") == -1`, `s.count("/") == 0`.
- *no parent traversal*: `".." not in s`, `".." not in s.split("/")`, `".." not in p.parts`.
- *not `..` itself*: `s != ".."`, `s not in (".", "..")`.
- *not absolute*: `not s.startswith("/")`, `not os.path.isabs(s)`, `s[0] != "/"`, `not p.is_absolute()`.

A `pathlib.Path` or a `str` with the textual atoms:
* "not absolute", and
* Any of:
  * "no parent traversal"
  * "no slash" and "not `..` itself*
is considered a "safe path component".

For example the following is accepted, assuming a read grant on `data/files/**`:

```python
name = sys.argv[1]
assert "/" not in name
assert name != ".."
open(f"data/files/{name}", "r").read()
```

##### Textual shape

Certorail has limited support for tracking the regular language that accepts a textual fact.
A guard `s == "lit"` establishes that `s` is exactly `"lit"`, `s in ("a", "b")`, `s == "a" or s == "b"` establishes
alternation. `s.startswith("pre")`, `s.endswith(".txt")` (a tuple of literals also works for both), establishes a regex
shape `^pre.*` and `.*\.txt` respectively. 
`re.fullmatch(r"…", s)` (also`… is not None`, `re.compile(r"…").fullmatch(s)`, `re.match(r"…\Z", s)`) establish the target
matches the provided regex. Certorail does not support a full regular expression domain, but you should only rely
on regex shapes when the policy demands regex shapes.

##### Containment

Containment, ensuring a located fact on `p` is known to fall under under `BASE`
(where `BASE` may be a literal or a located fact itself).

The guards below understand casts through `str()`, `pathlib.Path()` or `.resolve()`:

- Lexical, only if *no parent traversal* is established on `p`: `s.startswith(str(BASE) + "/")` or `+ os.sep`,
  `p.is_relative_to(BASE)`, `p.parent == BASE`, `BASE in p.parents`, `os.path.commonpath([s, BASE]) == BASE`.
- Resolving form, needing nothing else: `p.resolve().is_relative_to(BASE)`, `os.path.realpath(s).startswith(str(BASE) + "/")`, ...
- **The policy's own spelling**: `certora.pathmatch(s, "repos/*/foundry.toml")`
  establishes exactly that location on `s`. See below for the mini-DSL used for the path component.
  Prefer this for complex paths with multiple constraints.

##### Types

Certorail does not trust the type annotations in the program and does not assume well-typedness in any event.
Accordingly, the above guards only work when the interrogated object is known to be a type that
supports the guards.

The type of an object can be established via `isinstance(s, str)`, `isinstance(p, pathlib.Path)`.

#### Effective Runtime Guard Use

- Guards apply in source order, once. Within thus, if the type needs to be established,
  put `isinstance` first and any shape constraints later, e.g.,
  `assert isinstance(s, str) and ".." not in s and pathlib.Path(s).is_relative_to("repos")`.
- Aside from the exceptions enumerated above, a guard on a derived view says nothing about the variable:
  `pathlib.Path(s.strip()).is_relative_to(BASE)` proves nothing about `s`.
  Assign the derived value to a variable, then guard that variable.
- A guard holds for the remaining statements of its block and nested blocks only; nothing established inside a
  `try` body, a loop body, or a `with` body survives that statement.
- Facts belong to a variable and are lost when it is reassigned; a variable assigned anywhere inside a loop is
  unknown at the start of the loop (except a `for` target bound by the header).
- Any string method (`replace`, `strip`, `lower`, `format`, `join`, …) yields a plain string with no path facts:
  re-establish them with a guard afterwards.
- Module-level constants are visible inside functions and keep their facts (`DATA = pathlib.Path("data")`
  at module level, then `DATA / name` inside a function). These module level facts only work
  for a module name proven to be constant, i.e., assigned exactly once at module level.
  A parameter or local of the same name shadows the constant, as in normal Python.


## Subprocesses

- Only `certora.exec(program, *args, cwd=<located path>)`. `program` is a string literal (or a name bound to
  one); arguments are separate strings, no `*`/`**` splats; `cwd` is required and must be a proven location.
  No shell; output is captured. A call the host refuses raises. `stream=True` (a literal, the only other
  option) sends the command's output straight to the terminal as it happens -- for a build or a test run
  you want to watch -- and the result then has the exit code and empty `stdout`/`stderr`: live output or
  output to read, one or the other per call.
- The result is a `CompletedProcess` with `.returncode`, `.stdout` and `.stderr` (bytes), plus decoded views:
  `.stdout_string()`, `.stdout_lines()`, `.stderr_string()`, `.stderr_lines()` (UTF-8, lines split like
  `str.splitlines`). **The views raise `certora.CalledProcessError` when the command exited non-zero**, so
  `for line in certora.exec("git", "log", "--oneline", cwd=repo).stdout_lines()[:10]:` is the whole
  pipeline and fails loudly if `git` did. To handle failure yourself, test `.returncode` and read the bytes.
  There is no shell: do filtering (`head`, `tail`, `grep`, `wc`) in Python on the lines.
- The policy may pin subcommands: if it declares `git log` and `git push origin`, any other `git`
  invocation — including one whose subcommand is not a literal — is rejected.
- The policy may declare a command's *shape* (a template): literal words, then typed *holes*. A
  template binds like a function call: spell the literal words positionally, then fill the holes
  positionally in order — `certora.exec("git", "push", "origin", branch, cwd=repo)`,
  `certora.exec("find", where, "-mindepth", "1", "-name", "*.py", cwd=here)` — or by keyword
  (`BRANCH=branch`). Some holes are keyword-only (the description says which):
  `certora.exec("git", "log", REVS=["main..HEAD"], PATHS=[src], cwd=repo)`. A flags list before
  other holes ends at the first argument that provably is not a flag (a literal, a path, a guarded
  string): `certora.exec("tar", "-c", "-z", out, a, b, cwd=here)`. If the next argument could be a
  flag (text read from a file or `sys.argv`), the call is rejected: name the holes instead,
  `certora.exec("grep", FLAGS=["-r"], PATTERN=pat, FILES=[repo], cwd=here)`. A list hole takes a
  list display (or a typed container); a flags hole takes a list of flag names with their values
  following, and only the flags the policy lists. Never spell the words the host inserts (`--`,
  `-f`). Every hole is checked like a parameter annotation (a proven path within a location, text
  matching a regex, a validation fact). A value that may begin with `-` where the tool could read
  it as an option is rejected: use a path under a named directory, or a literal.
- Run `certorail --describe` (or read the description in your context) for the exact shapes,
  hole names, flags and validations this policy permits.
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
  `urllib.parse.urlsplit(u).path.startswith("/repos/")` (with `".." not in u` earlier in the condition), or
  `certora.pathmatch(urllib.parse.urlsplit(u).path, r"/repos/*/*/issues/<\d+>/comments")` for a path shape the
  policy spells out (a raw string when it contains a regex; this one needs no `..` guard and may come after
  the scheme and netloc guards).
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

## Sources and extraction

- The policy may mark a program, a network host, or a readable location as a *source* yielding a
  named fact (the description lists them: "yields gh-api"). A value carries that fact only if it
  came out of the source's result **unmodified**, through one of four extractors:
  `certora.extract(x, ".data.repos[0].name")` (one value), `certora.extract_all(x, ".data[].name")`
  (a list; exactly one `[]` in the path), `certora.lines(x)` (a list of lines), and
  `certora.field(line, i, sep=None)` (one field of an extracted line). `x` is the result of
  `certora.exec` or `certora.network.*`, a file object from `with open(...)`, or text from
  `.read_text()` / `f.read()`. Iterating a file (`for line in f`) and `f.readlines()` count as
  `lines`. The path is a string literal in a small jq subset: `.key`, `."quoted key"`, `[0]`,
  `[]`; no pipes or filters. Scalars come back as text; `null`, a missing path and non-scalars raise.
- The result of `extract_all` / `lines` / `readlines` is a typed container: annotate it,
  `xs: list[typing.Annotated[str, certora.source("gh-api")]] = certora.extract_all(...)`
  (`certora.source`, not `certora.validated`: provenance is spelled as what it is).
- Any string operation (`strip`, `+`, f-strings, `split`) drops the fact, as does `json.loads`
  followed by indexing; guards (`assert re.fullmatch(...)`) keep it. A literal never has it.
  Where a hole or contract demands a source fact, the extractor is the only spelling that works.

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
  `certora.not_option` (the text does not begin with `-`; `assert not s.startswith("-")` establishes it),
  `certora.validated("atom", …)` (the value carries the named policy facts — see validations),
  `certora.source("atom", …)` (the value came, unmodified, from the source that yields the atom — see provenance),
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
