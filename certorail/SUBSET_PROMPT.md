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
process. The vocabulary in which a policy states what it permits comes first; the categories of effect and source (filesystem,
process, network) follow, each an instance of that vocabulary.

### Policies and Vocabulary

A policy grants operations: the locations a program may read, write and list; the programs it may run and the command lines it
may run them with; the hosts it may send requests to. Certorail accepts an operation when a grant covers it and every value
flowing into the operation provably meets the grant's constraints. The description of the policy in your context (the text
`certorail describe` prints) lists every grant in a fixed vocabulary, used throughout this document:

- A **constraint** is a requirement on one value flowing into an operation: the path given to `open`, an argument of
  `certora.exec`, the URL of a request. The description writes constraints as `<...>`:
  * `<path within L>`: the value denotes a path within the location `L` (see Location Facts, below).
  * `</re/>`: text matching the regex; `<(a|b)>`: one of the literals.
  * `<literal>`: text your program itself names, a literal or a module constant.
  * `<... validated X>`: the value carries the atom `X`; `<... from S>`: the value came, unmodified, from the source `S`.
  * `<any>`: anything.

  Claims combine: `</dev-\w+/ literal>` is a literal of that shape.
- A **location fact** is what Certorail knows about where a path value points: an exact path, or some path within a location.
  A location fact within `L` is what satisfies `<path within L>`.
- An **atom** is a named fact carried by a value. The built-in atoms describe text: *no-slash*, *no-parent-traversal*,
  *not-absolute*, *not-dot-dot*, and *not-option* (the text does not begin with `-`). The policy defines further atoms by a
  regex on the text, by a validation, or by a source.
- A **validation** is a named check the policy declares, called with `certora.check` or `certora.check_single`;
  it establishes atoms on the values passed to it.
- A **source** is a program, host or readable location the policy marks as yielding a provenance atom; values extracted from
  its results carry that atom.

A value meets a constraint by construction (a literal, a path joined from located parts), through a validation, through
extraction from a source, or through a runtime guard on its text (see Runtime Guards).

### Location Facts

Locations are spelled as paths. `repos/**` is `repos` and everything below it; `repos/*/x` has one arbitrary component;
`<re>` is one component matching the regex `re`; `{a,b}` is one of the names `a` and `b`; a leading `/` is the filesystem
root. Any other location is relative to the sandbox root, the working directory of the Certorail process, spelled `.`.

A **location fact** on a value places the path it denotes at a location, exactly (`data/x.txt`) or approximately
(`data/**`: some path at or below `data`; `repos/*`: some direct child of `repos`). A value satisfies `<path within L>` when
its location lies within `L`: a value at `data/**` satisfies `<path within data/**>` and `<path within **>`, and no narrower
constraint.

Location facts arise from:

- A string literal that is a valid POSIX path (`"data/x.txt"`, `"/home/user/data.txt"`), and `pathlib.Path(...)` of such
  literals: the exact path.
- Joins below a located `a`: `a / b`, `pathlib.Path(a, b, …)`, `os.path.join(a, b, …)`, `f"{a}/{b}"`, `a + "/" + b`, where
  `b` and each further component is a literal or a *safe component* (below). A literal component keeps the location exact
  (`pathlib.Path("data") / "x.txt"` is at `data/x.txt`); a non-literal safe component gives some path below `a`
  (`pathlib.Path("data") / name` is at `data/**`).
- Conversions: `str(a)`, `os.fspath(a)`, `pathlib.Path(a)` have the location of `a`.
- Traversal loops over a located `base`: `for p in base.iterdir()`, `base.glob(pat)` or `base.rglob(pat)` places `p` below
  `base`; `for dirpath, dirnames, filenames in os.walk(base)` places `dirpath` below `base`. The fact survives
  `sorted(...)`, `list(...)`, `reversed(...)` and `enumerate(...)` around the iterable.
- A module-level constant, assigned exactly once at module level (`DATA = pathlib.Path("data")`): it keeps its fact inside
  functions. A parameter or local of the same name shadows it.
- A parameter annotated with a location, and the result of a function whose return is so annotated (see Function Contracts).
- A runtime guard on a value whose text is otherwise unknown (see Runtime Guards).

#### Safe components

A **safe component** is text that, joined below a located path, stays below it: it does not begin with `/` (*not-absolute*)
and has no `..` component (*no-parent-traversal*). A single name with no `/` that is not exactly `..` itself is a safe component.
`foo/bar` is a safe component; `foo/../baz` is not. A literal with these properties is a safe component. `for name in os.listdir(base)`
gives `name` the atoms that establish a "safe component":
*no-slash*, *not-dot-dot*, *not-absolute*, *no-parent-traversal*. Other text (an argument, a line of a file, a field of a response)
becomes a safe component through a runtime guard (see Runtime Guards).

### Effects

Atoms are of two kinds. A *text* atom (the built-in atoms, the regex-defined atoms, provenance, and the validation atoms the
policy declares pure) is a property of the value and holds as long as the variable holds that value. An *environmental* atom
is a property of the world a validation examined (e.g.that a directory is a clean checkout, that a branch is not protected); it
holds only while that state is unchanged.

State is divided into **regions**. A region is a named piece of state that a validation can observe and an operation can
change; it lives on the filesystem at some footprint it names, or it is remote. The description lists them under
`Regions: the state checks depend on and commands change`:

```
- repo-state (on disk at .git/**): the checkout's history and index
- remote-branches (remote): the branches of the origin repository
```

A whole medium, `anything on the filesystem` or `anything remote`, stands for every region of the given medium.

Every operation **writes** a set of regions (i.e., its effects); every environmental atom **depends on** a set of regions. An
atom on a fact dies at an effectful operation when the two sets meet: they share a region,
or one names a whole medium and the other a region within that medium.
The description states both sides:

- A program run writes what its shape's `effects:` line says: `none`, `writes repo-state`, or `writes anything on the filesystem`.
  A program that names a region kills all atoms that read that region.
- A network request writes what its entry says; an entry admitting only `GET` and `HEAD` writes nothing.
- A validation writes what its own `effects:` line says.
- A file write (`open` for writing, `write_text`, `write_bytes`, `mkdir`, `touch`, `chmod`, `replace`, `print(..., file=f)`)
  writes `anything on the filesystem`: every filesystem region, wherever the file is. Reads and listings write nothing.
- A call to a function defined in the program writes what its body writes. A method call on an instance of a class defined
  in the program, or on a value whose type is unknown, writes everything.
- An environmental atom's entry in the atoms section says what it depends on and what kills it:
  `depends on repo-state; dies on: git push; any file write`. An atom with no stated
  dependencies depends on everything and dies at any effectful call.

Only calling the validation again re-establishes an atom that died. Call the validation immediately before the operation that
needs the atom.

Every fact, atom or location, belongs to the variable it was established on, and is lost when the variable is reassigned. A
value derived from the variable carries only what the derivation preserves: a path join keeps a location, a string method
(`strip`, `replace`, `lower`, `format`, `join`, …) keeps nothing.

### Filesystem

The policy grants filesystem access as three lists of locations, *read*, *write* and *list*, printed at the top of the
description (`- read: data/**, /etc/hosts`); a location listed as *protected* admits no write whatever the write grants say.
Every filesystem accessor is constrained by these grants: its path must carry a location fact within a location of the
matching kind.

- `open(p, mode)`: a mode containing `w`, `a`, `x` or `+` needs *write*, any other mode *read*. The mode is a literal; a
  computed mode counts as a write.
- `os.listdir(p)`, `os.walk(p)`, `os.path.exists(p)`, `os.path.isfile(p)`, `os.path.isdir(p)`: *list*.
- `pathlib.Path` methods on `p`: `.open()` (the mode as for `open`), `.read_text()`, `.read_bytes()` need *read*;
  `.write_text()`, `.write_bytes()`, `.mkdir()`, `.touch()`, `.chmod()`, `.replace(target)` (both `p` and `target`) need
  *write*; `.iterdir()`, `.glob()`, `.rglob()`, `.exists()`, `.is_file()`, `.is_dir()` need *list*. Each is called fully
  applied where it is named; `f = p.read_text` is a violation.

### Subprocess Exec

The policy grants programs as **shapes**: the program, the literal words that follow it, and typed *holes* for the values you
supply, each hole carrying a constraint from the vocabulary above. `certora.exec` names a shape and fills its holes, the way a
call fills a signature. The description lists every shape under `Programs: certora.exec(<words>, <holes>, cwd=<proven path>)`:

```
- ls FLAGS... -- FILES...    [from coreutils-ro.toml (where=.)]
    cwd within **
    effects: none (effect-free: kills no facts)
    FLAGS... ends at the first positional that is not a flag; FILES begins there (a value that could be either is rejected: bind by keyword)
    inserted by the host, do not spell: --
    FLAGS...: a list of flags --
        bare: --color=never --full-time -1 -A -F -R -S -a -d -h -l -r -t
        -I <any>
        --time-style </[a-z-]+/>
        bundled short flags accepted: -lr is -l -r (bare single-letter flags only)
    FILES...: each <path within **>
```

Reading an entry:

- The head line is the shape: the program, the literal words, and the holes in order. `NAME...` takes a list; `NAME` takes
  one value. A word of the head line that is not a hole is a literal word of the shape (`--` here, a subcommand such as `log`
  elsewhere).
- `cwd within L`: the constraint on your `cwd=` argument, a location fact within `L`. `cwd validated by X`: the directory
  must also carry the atom `X` (see Calling validations).
- `effects:`: what the run writes (see Effects).
- `inserted by the host, do not spell: --`: these literal words of the shape are placed for you; spelling them is rejected.
  Without this line, a `--` in the head line is spelled like any other literal word.
- `bind by keyword: NAME`: the hole is bound by keyword only (see below).
- One line per hole gives its constraint in the `<...>` notation; `each <...>` constrains every element of a list hole.
- A flags hole lists the only flags that exist for the shape: `bare` flags take no value. Valued options describe the constraint (if any) on the value.
  A valued flag is two separate arguments (see "Calling a shape" below); a bundle such as `-la` is accepted only where the entry says so.

#### Calling a shape

The permissions for a `certora.exec` call is decided on the static prefix of the shape. The static prefix are all of the
literal words up to the first named hole. In the above example, `ls` is the entirety of the static prefix, for
an invocation of a git subcommand, the static prefix might be `git status` or `git log`.

There are two ways to call a shape. The first is positionally, spelling the static prefix, and then the hole values in order. Do **NOT** include
any literal words after any hole (these are marked as "do not spell" in the description).

The program and the literal words are string literals:

```python
certora.exec("ls", "-l", "-a", "src", cwd=".")
certora.exec("cat", "-n", "README.md", cwd=".")
certora.exec("git", "status", "--short", cwd="repos/app")
```

`cwd=` is required: a location fact within the shape's `cwd within`. NB: A string literal that is a valid path is a location fact;
`pathlib.Path` is for paths you build (`REPOS / name`, an element of `iterdir()`).

Positional invocation is only possible if the parse is unambiguous. In the `ls` example above, `"-l"` and `"-a"`
can be statically determined to be declared flags, `"src"` clearly is not, and is assigned automatically to the `FILES` hole.
This "flag termination" is common enough that Certorail has special reasoning to make it easy, the first
positional argument proven to not be an option (anything proven to not start with "-", including a value carrying the fact *not-option*) terminates the flag list.
Successive list shaped holes always parse ambiguously, and templates which include them cannot be invoked positionally and must
use the keyword shape.

Keyword invocation lists the static prefix, but then binds all holes using from the head line:

```python
certora.exec("grep", FLAGS=["-n", "-E"], PATTERN=pattern, FILES=["src"], cwd=".")
certora.exec("git", "log", FLAGS=["--oneline", "-n", "20"], REVS=["main..HEAD"], cwd=repo)
```

A list hole takes a list display (or a typed container, see Containers); a single hole takes one value.

Where the description ends with a `DEFAULT-ALLOW` line, a program it does not name runs with any positional arguments and no holes; every environmental atom dies at such a run.

##### Flags

Any flag hole must be unambiguously parsed. A flag list (passed "splatted" positionally or as a keyword list) must satisfy the following constraints:
* Every program value in a flag name position must be a literal string
* The first element of the flags sequence is always a flag name position
* The position after a "bare" flag is also a flag name position
* The position after a value taking flag must be a program value that satisfies that argument's constraint. The position after this value is also a flag name position (unless the flag list is terminated)

Thus `certora.exec("ls", FLAGS=["-l", unknown])` is rejected. Likewise `certora.exec("ls", FLAGS=["-l", "--time-style"])` also also rejected (missing flag value).

#### What goes into a hole

The hole's constraint decides, as everywhere:

- `<path within L>`: a location fact within `L`. The tool receives the value's text and resolves it against its own working
  directory, so spell an operand as the tool expects it from `cwd`.
- `<any>`: any text, unknown values included. Where no `--` precedes the hole in the head line, the value also needs
  *not-option*: a literal, a located path, or a guarded variable (see Runtime Guards).
- `<literal>`: a literal or a module constant of your program.
- `</re/>`: a literal matching the regex, or a variable guarded with `re.fullmatch` on that exact regex text (see Runtime
  Guards).
- `<... validated X>`: a value carrying the atom `X`. A literal matching a regex-defined atom carries it; otherwise the value
  goes through the validation that establishes `X` (below). `<... from S>`: a value extracted from the source `S` (see
  Sources).
- Flags: the flags listed, as separate list elements; a flag's value meets the constraint next to it, and a flag may require
  an atom elsewhere (`--force (requires BRANCH validated by not-force)`), stated next to it.

Build the value, establish its fact on a variable, then pass the variable.

#### Reading the output

`certora.exec` returns once the process has exited, with `.returncode`, and `.stdout` and `.stderr` as bytes. Four decoded
views do what a pipeline would: `.stdout_string()`, `.stdout_lines()`, `.stderr_string()`, `.stderr_lines()` (UTF-8,
undecodable bytes replaced). The views raise `certora.CalledProcessError` when the process exited non-zero:

```python
for line in certora.exec("git", "log", FLAGS=["--oneline"], cwd=repo).stdout_lines()[:20]:
    print(line)
```

is `git log --oneline | head -20`, and raises if `git` failed. Where a non-zero exit is an answer (`grep` finding nothing exits
1), test `.returncode` and decode the bytes yourself:

```python
result = certora.exec("grep", FLAGS=["-c"], PATTERN="TODO", FILES=["src"], cwd=".")
if result.returncode == 1:
    print("no TODOs")
else:
    print(result.stdout.decode("utf-8", "replace"))
```

For a run whose output you want to watch, a build or a test suite, pass `stream=True` (a literal): stdout and stderr go to the
terminal, and the result carries the exit code with empty `stdout` and `stderr`.

#### Calling validations

The description's `Validations` section lists each validation as the call that runs it and what the call establishes:

```
- certora.check("org-checkout", cwd=<path within repos/*>)
    establishes on cwd: org-checkout (environmental)
    effects: none (effect-free: kills no facts)
- certora.check("not-force-check", branch=<str>)
    establishes on branch: not-force (pure)
    effects: none (effect-free: kills no facts)
    also as an expression: certora.check_single("not-force-check", value)
```

- `certora.check("name", key=value, ..., cwd=path)` is a statement on its own. The name is a literal; the keywords are the
  declared parameters, each a string; `cwd=` is given only when the validation entry shows it,
  and like program declarations the value of `cwd=` must satisfy the provided location constraint.
  On success the declared atoms are established on the variables passed: pass variables, not expressions. Failure raises,
  so the statements after the call may rely on the atoms.
- `certora.check_single("name", value)` (plus `cwd=` when declared) is the expression form of a validation with one
  parameter: the atom rides the result. Assign it and use that variable:
  `rev = certora.check_single("git-rev", sys.argv[1])`, then `certora.exec("git", "show", REVS=[rev], cwd=repo)`.
- A regex-defined atom does not need a `certora.check` invocation: a literal matching the regex automatically carries that atom,
  and `assert re.fullmatch(r"…", s)` with that exact regex text establishes it on `s` (see Runtime Guards).
- An environmental atom follows the Effects section: call the validation immediately before the operation that needs it, on
  the same variable you pass to that operation.

#### Putting it together

Against a policy that applies coreutils grants under `.`, git read grants `repos`, and explicitly grants
`uv run pytest FLAGS... TESTS...`:

```python
import pathlib
import sys
import typing

REPOS = pathlib.Path("repos")


def python_files(under: typing.Annotated[str, certora.within("src")]) -> list[str]:
    # find WHERE FLAGS...: no -- precedes WHERE, so it needs not-option; a path within src begins with "src/"
    return certora.exec("find", under, "-name", "*.py", "-type", "f", cwd=".").stdout_lines()


def recent_commits(repo: typing.Annotated[pathlib.Path, certora.within("repos")], n: int) -> list[str]:
    # git log FLAGS... REVS... -- PATHS...: REVS is bound by keyword
    return certora.exec("git", "log", FLAGS=["--oneline", "-n", str(n)], REVS=["HEAD"], cwd=repo).stdout_lines()


def main() -> None:
    pattern = sys.argv[1]
    # grep FLAGS... -- PATTERN FILES...: PATTERN follows the host's --, so any text is data
    hits = certora.exec("grep", FLAGS=["-r", "-n"], PATTERN=pattern, FILES=["src"], cwd=".")
    if hits.returncode == 0:                      # 1 is no match
        for line in hits.stdout_lines()[:50]:
            print(line)
    for path in python_files("src"):
        print(path)
    for repo in sorted(REPOS.iterdir()):          # a direct child of repos
        for line in recent_commits(repo, 5):
            print(repo.name, line)
    certora.exec("uv", "run", "pytest", FLAGS=["-q"], TESTS=["tests"], cwd=".", stream=True)


main()
```

### Network

The policy grants requests by method, scheme and host, optionally with a location the URL's path lies within; the description
lists them under `Network: certora.network.<method>(url)` (`- GET, HEAD https://api.github.com; path within /repos/**`).

- `certora.network.get(url, headers=…, timeout=…)`, `head` and `delete` likewise
- `post(url, headers=…, body=<bytes>, timeout=…)`, `put` and `patch` likewise.
- The response of a `certora.network` call has `.status`, `.reason`, `.headers` (a tuple of pairs), `.body` (bytes) and `.url` (the final URL, after redirects).
  A refused or failed request raises.
- The constraint on `url`: its scheme and host are known and granted with the method, and where the grant names a path
  location, the path is a location fact within it. A string literal satisfying the stated constraints is acceptd ouright.
  A URL built from parts is text: guard the finished string, held in a variable `u`, with `urllib.parse.urlsplit(u).scheme == "https"`,
  `urllib.parse.urlsplit(u).netloc == "api.github.com"` (or `in ("a.com", "b.com")`), and for the path
  `urllib.parse.urlsplit(u).path == "/v1/users"` or
  `certora.pathmatch(urllib.parse.urlsplit(u).path, r"/repos/*/*/issues/<\d+>/comments")` with the location as the
  description spells it. `urlparse` serves for `.scheme` and `.netloc`. Text guards on `u` (a regex-defined atom, for
  instance) come before the URL guards.
- `the URL must be validated by X`: the URL carries the atom `X`, a literal matching a regex-defined atom or a value passed
  through the validation (see Calling validations).
- Headers and bodies are ordinary values.
- A request writes what its entry states (see Effects); `GET` and `HEAD` write nothing.

### Advanced features

#### Function Contracts

A module-level function states constraints on its parameters and its result with markers under `typing.Annotated`:

```python
def push(repo: typing.Annotated[pathlib.Path, certora.within("repos"), certora.validated("org-checkout")],
         branch: typing.Annotated[str, certora.validated("not-force")]) -> bool:
    return certora.exec("git", "push", "origin", branch, cwd=repo).returncode == 0


def slug_of(name: str) -> typing.Annotated[str, certora.no_slash, certora.not_dot_dot]:
    assert "/" not in name and name not in (".", "..")
    return name
```

A parameter marker is a *rely*: inside the function the parameter carries the facts, and every call passes an argument
already carrying them. A return marker is a *guarantee*: every `return` returns a value carrying the facts, and at the call
site they attach when the call is the whole right side of an assignment, `slug = slug_of(name)`; assign first, then use the
variable.

The markers, each under `typing.Annotated[<str or pathlib.Path>, …]`, come in three families.

Text markers describe the value's text. `certora.matches(r"…")` is text matching the regex in full; `certora.one_of("a", "b", …)`
is exactly one of the literals; `certora.seq(piece, …)` is the pieces concatenated in order, each a literal or another text
marker, so `certora.seq("release-", certora.matches(r"\d+"))` is text matching `release-\d+`.

Location markers place the value. `certora.within(prefix, leaf=…)` is a path at or below `prefix`, where `"."` is the sandbox
root and a leading `/` the filesystem root; `leaf=` gives one component the file name must satisfy, a literal or a text
marker. `certora.exactly(fragment, …)` is a path at exactly the location the fragments spell in order: a literal of one or
more path components (`"data/uploads"`), or text marker, so 
`certora.exactly("repos", certora.matches(r"[a-z]+"), "foundry.toml")` is the location `repos/<[a-z]+>/foundry.toml`.
`certora.url(scheme="https", netloc="api.github.com", path_within="/repos")`
does the same for a URL: each keyword is optional and claims only what it names.

Atom markers state what the value carries. `certora.no_slash`, `certora.no_parent_traversal`, `certora.not_absolute`,
`certora.not_dot_dot` and `certora.not_option` are the built-in atoms; `certora.validated("atom", …)` names any atoms; and
`certora.source("atom", …)` is provenance: the value came, unmodified, from the source yielding that atom (see Sources).

An annotation carries either a location marker or text markers, with at most one of `matches`, `one_of` and `seq` among
them; `validated` combines with either. Markers go on a `str` or `pathlib.Path` parameter or return value, or on the element type of a typed
container (below). Only module-level functions carry markers; nested functions and methods use plain types, which state
nothing to the policy. Each function name is defined once, and a contracted function is called directly by name, without
`*args` or `**kwargs`.

#### Containers

A `list` or `set` whose elements all carry facts, declared by annotation and owned by the one name it is assigned to:

```python
slugs: list[typing.Annotated[str, certora.no_slash, certora.not_dot_dot]] = []
branches: list[typing.Annotated[str, certora.validated("not-force")]] = [
    certora.check_single("not-force-check", b) for b in sys.argv[1:]
]
```

- Tracking begins at an annotated assignment whose right side is a constructor: a display `[a, b]` / `{a, b}`, `list()` /
  `set()`, the copy `list(other)` / `set(other)`, or a comprehension with exactly one `for` (its element, under the loop
  variable and the `if` filters, meets the annotation). Every element is checked at construction; a copy is spelled
  `list(y)`.
- Reads give the element facts: `x[i]`, `for e in x` (also through `sorted`, `list`, `tuple`, `reversed`, `iter`,
  `enumerate`), `x.pop()`, `len(x)`, `v in x`, `if x:`, iterating `x` in a comprehension, and `x` as a list hole of
  `certora.exec`.
- A write that adds an element checks it against the annotation: `x.append(v)`, `x.insert(i, v)`, `x[i] = v`, `x.add(v)`,
  and `x.extend(ys)` / `x += ys` with `ys` a display or a typed container with at least as strong an element type. The
  mutators that add nothing, `x.remove(v)`, `x.discard(v)`, `x.clear()` and `x.sort()`, are permitted and check nothing.
- The name is used in those ways only; aliasing it (`y = x`), storing it in another container, passing it to a parameter
  that is not itself a typed container, `x[i] += v` and `x[1:] = …` are violations.
- Passing moves or borrows: a `list[P]` argument binds to a `list[P]` parameter with the same element type (the callee may
  write), or to a `typing.Sequence[Q]` parameter with `P` at least as strong as `Q`, read-only inside the function. A local
  typed container is returned against `-> list[…]` / `-> set[…]` with the same element type and moves to the caller's
  variable; a parameter container is not returned.
- Element atoms follow the Effects section. Nested containers, dicts and tuples of marked values are untracked; `list[str]`
  without `Annotated` is an ordinary list.

### Runtime Guards

A guard is `assert C`, or `if not C: raise …` / `return` / `continue` / `break` (`C` holds afterwards), or `if C:` (`C` holds
in the body). `C` is one of the forms below, or several joined with `and`. A guard establishes atoms or a location fact on
the variable it interrogates.

#### Text atoms

On a `str` `s` (or a `pathlib.Path` `p` where a `p` form is given):

- *no-slash*: `"/" not in s`, `os.sep not in s`, `s.find("/") == -1`, `s.count("/") == 0`.
- *no-parent-traversal*: `".." not in s`, `".." not in s.split("/")`, `".." not in p.parts`.
- *not-dot-dot*: `s != ".."`, `s not in (".", "..")`.
- *not-absolute*: `not s.startswith("/")`, `not os.path.isabs(s)`, `s[0] != "/"`, `not p.is_absolute()`.
- *not-option*: `not s.startswith("-")`, `s[0] != "-"`.

*not-absolute* with either *no-parent-traversal* or both *no-slash* and *not-dot-dot* makes a safe component (see above). With a read
grant on `data/files/**`:

```python
name = sys.argv[1]
assert "/" not in name
assert name != ".."
open(f"data/files/{name}", "r").read()
```

#### Text shape

`s == "lit"` establishes that `s` is exactly `"lit"`; `s in ("a", "b")` and `s == "a" or s == "b"` establish the
alternation. `s.startswith("pre")` and `s.endswith(".txt")` (a tuple of literals also works for both) establish the shapes
`^pre.*` and `.*\.txt`. `re.fullmatch(r"…", s)` (also `… is not None`, `re.compile(r"…").fullmatch(s)`,
`re.match(r"…\Z", s)`) establishes that `s` matches the regex. Where a constraint is a regex (`</re/>`, a regex-defined
atom), guard with that exact regex text.

#### Containment

Containment establishes a location fact on `p` under `BASE`, a literal or a located value. The guards understand casts
through `str()`, `pathlib.Path()` or `.resolve()`:

- Lexical, once *no-parent-traversal* is established on `p`: `s.startswith(str(BASE) + "/")` or `+ os.sep`,
  `p.is_relative_to(BASE)`, `p.parent == BASE`, `BASE in p.parents`, `os.path.commonpath([s, BASE]) == BASE`.
- Resolving, needing nothing else: `p.resolve().is_relative_to(BASE)`, `os.path.realpath(s).startswith(str(BASE) + "/")`.
- The location's own spelling: `certora.pathmatch(s, "repos/*/foundry.toml")` establishes exactly that location on `s`, in
  the notation of the Location Facts section. Prefer it for a location with several constraints.

#### Types

The guards above apply to a value known to be a `str` or a `pathlib.Path`; `isinstance(s, str)` and
`isinstance(p, pathlib.Path)` establish the type.

#### Effective guard use

- Guards apply in source order, once: `isinstance` first, then text atoms, then containment:
  `assert isinstance(s, str) and ".." not in s and pathlib.Path(s).is_relative_to("repos")`.
- Aside from the casts named above, a guard on a derived view says nothing about the variable:
  `pathlib.Path(s.strip()).is_relative_to(BASE)` establishes nothing on `s`. Assign the derived value to a variable, then
  guard that variable.
- A guard holds for the remaining statements of its block and nested blocks; nothing established inside a `try` body, a
  loop body, or a `with` body survives that statement.
- Facts belong to a variable and are lost when it is reassigned; a variable assigned anywhere inside a loop is unknown at
  the start of the loop (except a `for` target bound by the header). Guard it inside the body, after the assignment.
- A string method (`replace`, `strip`, `lower`, `format`, `join`, …) yields a plain string with no facts: re-establish them
  with a guard afterwards.

`certora.reveal_fact(x)` is a runtime inert function in the style of `typing.reveal_type`: Certorail reports everything it
knows about the variable `x` at that point (named variables only, no complex expressions). Use it only as a last resort when
you are unable to convince Certorail to accept a program you are certain is correct. Do **not** use it to "double check" the
inference before running scripts for real; do not second guess Certorail until it gives you a reason to do so.

### Sources

The policy marks a program, a host or a readable filesystem location as a *source* yielding a provenance atom; the entry says so
(`yields gh-api`), as does the atoms section. Holes with provenance atoms as requirements require values that flow
from the named sources to their use sites, without any modification by the Certorail host program (modulo extraction, see below).

Reads of filesystem locations identified as a source yields string values with the source provenance atom.
If location `data/*.txt` is listed as a source for atom `important-data`, the `f = open("data/code.txt", "r"); content = f.read()`
will tag `content` with `important-data`. Similarly `for l in f` or `for l in f.readlines()` will tag `l` with the same atom.
Accessing the same location via pathlib's `read_text()` will also tag the resulting string with a source atom.

Sources accessed through network requests or program invocations (which we will call a "source invocation")
must be "unwrapped" via an extractor. Suppose we have
`x = certora.network.<method>(...)` or `x = certora.exec("...")`. Source tagged values can then be retrieved by the following methods:
- `certora.extract(x, p)`, returning a single value, where `p` is a literal JQ-style path, and where it is assumed the network request/program returned json data
- `certora.extract_all(x, p)`, where `p` is a literal JQ-style path, with the same assumption around a JSON format.
- `certora.lines(x)`: returns a list of the lines from the source invocation; the list contents are tagged with the source atom (see "Containers" above)

The path component of `extract` and `extract_all` must be a literal string written in a small subset of jq: `.key`, `."quoted key"`, `[0]`, `[]`.
Scalars come back as text; `null`, a missing path and a non-scalar raise. The path for `extract_all` must yield a list of scalars; the
path must therefore contain only one `[]`.

Any guards on the value (`assert ...`) can add other atoms to a provenance tagged value. Any transformation *not* performed
through an extractor (`.split()`, substring operations, etc.) yields an untagged value.
