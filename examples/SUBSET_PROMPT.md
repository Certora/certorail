# Writing Python for the certorail sandbox

Programs are checked statically before they run. A program is rejected on any violation below,
or if any filesystem/subprocess operation cannot be proven confined.

## Imports and names

- Only `import x` / `import x.y`. No `from … import`, no `import … as`.
- Standard library only. Forbidden modules (import is a violation): `os` (see allowlist), `subprocess`,
  `shutil`, `tempfile`, `glob`, `fileinput`, `linecache`, `tarfile`, `zipfile`, `gzip`, `bz2`, `lzma`, `zlib`,
  `sqlite3`, `socket`, `ssl`, `asyncio`, `urllib`, `http`, `ftplib`, `smtplib`, `xmlrpc`, `xml`, `webbrowser`,
  `threading`, `_thread`, `multiprocessing`, `concurrent`, `signal`, `mmap`, `fcntl`, `resource`, `ctypes`,
  `importlib`, `pkgutil`, `runpy`, `code`, `codeop`, `types`, `marshal`, `pickle`, `copyreg`, `shelve`, `dbm`,
  `gc`, `inspect`, `traceback`, `dis`, `pdb`, `bdb`, `trace`, `doctest`, `timeit`, `cProfile`, `profile`,
  `py_compile`, `compileall`, `unittest`, `logging`, `platform`, `pwd`, `grp`, `getpass`, `crypt`, `netrc`,
  `builtins`, `sysconfig`, `distutils`, `setuptools`, `venv`, `pip`, `turtle`, `idlelib`, `antigravity`, `winreg`.
- `os` is allowlisted member-by-member: `os.path.{join, basename, dirname, split, splitext, isabs, normpath,
  abspath, realpath, commonpath, exists, isfile, isdir}`, `os.sep`, `os.pathsep`, `os.linesep`, `os.fspath`,
  `os.PathLike`, `os.listdir`, `os.walk`. Nothing else under `os`.
- `typing` is likewise allowlisted, to annotation vocabulary only: `Annotated`, `Optional`, `Union`, `Literal`,
  `Any`, `Final`, `ClassVar`, `Callable`, `TypeVar`, `NamedTuple`, `TypedDict`, `Protocol`, `Generic`, and the
  like. Not `get_type_hints`, `get_args`, `get_origin`, `cast` or any other reflection helper.
- Forbidden members of otherwise-allowed modules include: `sys.{modules, path, meta_path, _getframe,
  settrace, setprofile, exc_info, excepthook, …}`, `functools.{partial, partialmethod, reduce}`,
  `operator.{attrgetter, methodcaller, itemgetter, getitem, setitem, delitem}`, `copy.{copy, deepcopy}`.
- A module name (`json`, `sys`, `pathlib`, …) and the `certora` namespace may appear only as the receiver of
  an attribute that is called or subscripted, or in a type position. Never as a value: no `m = json`,
  `f(sys)`, `f = os.path.join`, `g = certora.exec`. `sys.argv[1:]` is fine; `main(sys.argv)` is not.
- Never rebind (by assignment, parameter, loop target, `as`, `match` capture, `def`, `class`): an imported
  name, a builtin name, `certora`, or the name of a class defined in the program.
- No dunder identifiers anywhere (`__name__`, `__dict__`, `__class__`, `__import__`, `x.__foo__`); the only
  dunder that may be defined is `__init__`. There is no `if __name__ == "__main__":` — call `main()` at top level.
- Forbidden builtins: `getattr`, `setattr`, `delattr`, `vars`, `locals`, `globals`, `compile`, `eval`, `exec`,
  `breakpoint`. `type(x)` is allowed; `type(name, bases, ns)` is not.
- Opening a file is only the bare builtin `open(...)` or a pathlib path's `.open()`. Never `open` reached through
  a module — `io.open`, `codecs.open`, `os.open`, `tokenize.open`, `pathlib.Path.open`, … are all forbidden.
- Forbidden attribute names on any receiver: frame/code/generator internals (`f_globals`, `f_locals`, `f_back`,
  `gi_frame`, `co_code`, …), `extract`, `extractall`, `load_extension`, `exec_module`, `load_module`,
  `unlink`, `rmdir`, `rename`, `symlink_to`, `hardlink_to`, `lchmod`, `expanduser`.
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

Every one of these is accepted only if the location of its path is proven (below); otherwise the program is
rejected: `open(path, …)`, `os.listdir(p)`, `os.walk(p)`, `os.path.exists/isfile/isdir(p)`, and on a
`pathlib.Path`: `.open()`, `.read_text()`, `.read_bytes()`, `.write_text()`, `.write_bytes()`, `.iterdir()`,
`.glob()`, `.rglob()`, `.exists()`, `.is_file()`, `.is_dir()`, `.mkdir()`, `.touch()`. These methods may only be
called, never referenced (`f = p.read_text` is a violation). All locations are relative to the sandbox root
(the working directory).

### What proves a location

- A relative string literal without `..` (`"data/x.txt"`; `"."` is the root); `pathlib.Path(...)` of such literals
  or located values; `a / b`, `pathlib.Path(a, b, …)`, `os.path.join(a, b, …)`, `f"{a}/{b}"`, `a + "/" + b`
  where `a` is located and each further component is a literal or a *safe component* (below);
  `str(p)` / `os.fspath(p)` of a located `p`.
- Loop variables: `for p in base.iterdir() / base.glob(pat) / base.rglob(pat)` with `base` located (also through
  `sorted`, `list`, `reversed`, `enumerate`); `for name in os.listdir(...)` yields safe components;
  `for dirpath, dirnames, filenames in os.walk(top)` with `top` located gives a located `dirpath`.
- Parameters annotated with a location marker (see contracts); results of contracted functions.

### What proves a safe component / text property

Only a guard — `assert C` or `if not C: raise …` / `return` / `continue` / `break` — with `C` one of
(conjunctions with `and` allowed): `"/" not in s`, `os.sep not in s`, `".." not in s`, `".." not in s.split("/")`,
`s not in (".", "..")`, `s != ".."`, `not s.startswith("/")`, `not os.path.isabs(s)`, `s.isalnum()`, `s.isalpha()`,
`s.isdecimal()`, `s.isdigit()`, `s.isidentifier()`, `re.fullmatch(r"…", s)`, `s == "lit"`, `s in ("a", "b")`,
`s.startswith("pre")`, `s.endswith(".txt")`, `isinstance(s, str)`, `isinstance(p, pathlib.Path)`,
`not p.is_absolute()`, `".." not in p.parts`, `p.resolve().is_relative_to(base)`,
`os.path.realpath(s).startswith(str(base) + "/")`, `p.is_relative_to(base)` (only together with `".." not in p.parts`).
A safe component needs both "no `/`" and "not `..`" (`".." not in s` or `s not in (".", "..")`).

- A guard holds for the remaining statements of its block and nested blocks only; nothing established inside a
  `try` body, a loop body, or a `with` body (other than `with open(...)`) survives that statement.
- Facts belong to a variable and are lost when it is reassigned; a variable assigned anywhere inside a loop is
  unknown throughout the loop (except a `for` target bound by the header).
- These prove nothing: `re.match`/`re.search`, `s.startswith(base)` without a trailing `/`, `not s.startswith("..")`,
  `"../" not in s`, `os.path.normpath(s) == s`, `.lower() in …`, `p.exists()`.
- Any string method (`replace`, `strip`, `lower`, `format`, `join`, …) yields a plain string with no path facts:
  re-establish them with a guard afterwards.
- Module-level constants are visible inside functions and keep their facts (`DATA = pathlib.Path("data")`
  at module level, then `DATA / name` inside a function). This holds only for a name assigned exactly once
  at module level; a name reassigned there carries no fact into functions. A parameter or local of the same
  name shadows the constant, as in normal Python.
- Unknown values (JSON fields, `sys.argv`, results of unmodelled calls) have no facts.

## Function contracts

- Only module-level functions may carry marker annotations; nested functions and methods may use plain types only.
  Each function name is defined once. Calls to a contracted function may not use `*args`/`**kwargs`.
  A function whose parameters carry markers is only ever called directly by name: never passed as a value
  (`key=f`, `map(f, …)`) or assigned to another name.
- Rely (parameter): `def f(p: typing.Annotated[pathlib.Path, certora.within("data")])` — inside `f`, `p` is
  located under `data/`; every call must pass an argument already proven to satisfy the annotation.
- Guarantee (return): `def g(s: str) -> typing.Annotated[str, certora.no_slash, certora.not_dot_dot]` — every
  `return` must return a value proven to satisfy it (build it, or guard it before returning); at a call site
  `x = g(...)` gives `x` the guaranteed facts.
- Plain type annotations (`str`, `pathlib.Path`, `list[str]`) are not checked statically; scalar ones are
  checked at runtime. Markers go directly on a `str`/`pathlib.Path` parameter or return value — never inside
  a container (`list[typing.Annotated[...]]`) and never on `*args`/`**kwargs`.
- Markers, under `typing.Annotated[<str or pathlib.Path>, …]`:
  `certora.within(prefix, leaf=…)` (at or below `prefix`; `"."` is the root),
  `certora.exactly("a/b", …)` (components: literals, `certora.matches(r)`, `certora.one_of("a", "b")`),
  `certora.matches(r"…")`, `certora.one_of("a", "b")`, `certora.seq("pre-", certora.matches(r"\d+"))`,
  `certora.no_slash`, `certora.no_parent_traversal`, `certora.not_absolute`, `certora.not_dot_dot`.
  A location marker (`within`/`exactly`) does not combine with text markers; constrain the file name with
  `within(prefix, leaf=certora.matches(...))`. At most one location marker and one regex marker per annotation.

## Subprocesses

- Only `certora.exec(program, *args, cwd=<located path>)`. `program` is a string literal (or a name bound to
  one); arguments are separate strings, no `*`/`**` splats; the only keyword is `cwd`, and it is required and
  must be a proven location. No shell; output is captured. Returns a `CompletedProcess` with `.returncode`,
  `.stdout` and `.stderr` (bytes).

## Everything else

Ordinary Python is fine: functions, classes with the bases above, dataclasses (`@dataclasses.dataclass`),
`enum.Enum`, comprehensions, lambdas, `match`, `try`/`except` with builtin or module exception classes,
`with open(...)`, f-strings, `json`, `re`, `math`, `collections`, `itertools`, `datetime`, `pathlib`.
