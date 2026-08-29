"""Enumerated blocklist for the certorail static checker.

This module is *data*, not logic. It enumerates the standard-library surface
that is `getattr`/`setattr`/`eval`/`exec`/`__import__`/frame-access in disguise.

Soundness precondition (enforced in analysis.py, not here):

  1. Dangerous `module.attr` is flagged at the ``ast.Attribute`` node, not only
     at ``ast.Call`` -- so grabbing a reference (``f = os.system``) is caught,
     not just calling it.
  2. A module name may appear ONLY as the receiver of an attribute access --
     never as a value (assignment RHS, call arg, container element, return).
     This makes value-aliasing (``x = os; x.system(...)``) impossible, so the
     ``(module, attr)`` pairs below cannot be laundered through a local name.
  3. Import aliasing is already banned (no ``import x as y`` / ``from x import
     y``), so a module is always bound to its canonical dotted name.

Categories:
  * FORBIDDEN_MODULES        -- importing at all is a violation.
  * DANGEROUS_MEMBERS        -- module -> members that are escapes, for modules
                                you might otherwise allow. (Also documents the
                                escape surface of FORBIDDEN_MODULES, in case one
                                is later allowed or reached via ``sys.modules``.)
  * ALLOWED_MEMBERS          -- the dual: module -> the only members that may be
                                accessed, for modules that are mostly escape
                                surface (default deny).
  * FORBIDDEN_ATTRIBUTES     -- non-dunder attribute names banned regardless of
                                receiver (the frame/code/generator structural
                                surface + a few rare-but-lethal method names).
                                Complements the existing dunder ban.
  * EXTRA_FORBIDDEN_BUILTINS -- add to `sensitive_builtins`.
  * CLASS_FACTORIES          -- callables whose *application* manufactures a class
                                from data; a violation in call position only.
  * ALLOWED_BASES /          -- the static-inheritance rule: what a ``class``
    SENSITIVE_CLASSES /         statement may name as a base, what it may never
    FORBIDDEN_CLASS_KEYWORDS    subclass, and the ``metaclass=`` hole.
  * REVIEW_*                 -- plausibly-legitimate names; ban if your policy
                                can afford the false positives (recommended for
                                a locked-down sandbox).
"""

import builtins
from typing import Literal

from .markers import NAMESPACE

# ---------------------------------------------------------------------------
# Whole-module bans: no legitimate sandbox use; import is itself a violation.
# (Enforce in visit_Import: reject if the imported dotted name, or any prefix
# of it, is in this set. `import os.path` binds `os`, so match on prefixes.)
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES: frozenset[str] = frozenset({
    # process / shell / native code execution
    # (`os` itself is allowlisted member-by-member: see ALLOWED_MEMBERS)
    "posix", "nt", "subprocess", "_posixsubprocess", "pty",
    "multiprocessing", "_multiprocessing", "concurrent",
    "ctypes", "_ctypes", "cffi",
    "signal",            # os.kill / setitimer -> control & DoS
    "mmap",              # map files/memory
    "fcntl",             # fcntl/ioctl
    "resource",          # setrlimit -> lift limits / DoS
    "faulthandler",
    "_thread", "threading",   # run obtained callables; settrace -> frames
    # arbitrary code / import machinery
    "builtins", "__builtin__",
    "importlib", "imp", "zipimport", "pkgutil", "pkg_resources", "runpy",
    "modulefinder",      # ModuleFinder scans/loads modules; freeze/packaging tooling only
    "site", "sitecustomize", "usercustomize",  # sys.path + .pth machinery: addsitedir() runs .pth code
    "certorail",         # the host itself: its runner takes a policy and a root of the caller's choosing
    "code", "codeop", "types", "marshal",
    "pickle", "_pickle", "cPickle", "copyreg", "shelve", "dbm", "dill",
    "jsonpickle",
    "gc", "ctypes",
    "timeit", "cProfile", "profile", "pstats",
    "pdb", "bdb", "trace", "doctest", "py_compile", "compileall",
    "dis",               # exposes code objects
    "unittest",          # unittest.mock -> setattr machinery
    # filesystem beyond the `open` guard
    "shutil", "tempfile", "fileinput", "linecache", "glob",
    "tarfile", "zipfile", "lzma", "bz2", "gzip", "zlib",  # + decompression bombs
    "sqlite3",           # connect(path) + load_extension(.so)
    # network / exfiltration / SSRF
    "socket", "_socket", "ssl", "asyncio",
    "urllib", "http", "ftplib", "poplib", "imaplib", "nntplib", "smtplib",
    "telnetlib", "xmlrpc", "socketserver", "wsgiref", "webbrowser",
    # xml attacks (prefer defusedxml if XML is truly needed)
    "xml", "xmlrpc", "pyexpat",
    # host / credentials / platform
    "platform",          # several functions shell out
    "pwd", "spwd", "grp", "crypt", "getpass", "netrc",
    "logging",           # logging.config.dictConfig -> RCE
    # windows
    "winreg", "_winreg", "msvcrt", "_winapi", "ctypes.wintypes",
    # cutesy import side effects
    "antigravity", "turtle", "idlelib",
    # introspection into the live runtime
    "inspect", "traceback", "sysconfig", "distutils", "setuptools",
    "venv", "ensurepip", "pip", "pydoc",
    "mailbox",
    "configparser",
    "tkinter", "lib2to3", "wave", "optparse", "tracemalloc", "zipapp", "filecmp"

    # PEP 594 "dead batteries" (deprecated for removal; gone by 3.13). A few are live hazards, the
    # rest are simply dead and have no business in a work script. crypt/spwd (credentials, above)
    # and nntplib/telnetlib (network, above) complete the PEP 594 set.
    "pipes",                     # pipes.Template shells out via os.system
    "mailcap",                   # mailcap.findmatch -> command injection (CVE-2015-20107)
    "nis",                       # Sun NIS / yellow-pages network lookups
    "asynchat", "asyncore", "smtpd",         # async network I/O + an SMTP server
    "cgi", "cgitb",
    "aifc", "sunau", "chunk", "sndhdr", "imghdr", "audioop", "ossaudiodev",  # media parsers/codecs
    "uu", "xdrlib",              # legacy encodings
    "msilib",                    # windows installer
})


# ---------------------------------------------------------------------------
# Member-level bans: `module -> {members}`. Use for modules you choose to ALLOW
# despite them having a few sharp edges, and as documentation of the escape
# surface for the forbidden ones. Match `module.member` (and submodule paths).
# ---------------------------------------------------------------------------

DANGEROUS_MEMBERS: dict[tuple[str, ...], frozenset[str]] = {
    # ---- reflection / attribute access in disguise (the explicit ask) ----
    ("operator", ): frozenset({
        "attrgetter", "methodcaller", "itemgetter",
        "setitem", "getitem", "delitem",
    }),
    ("functools", ): frozenset({
        "reduce",          # reduce(getattr, names, obj) attribute walk
        "partial", "partialmethod",  # wrap an escape callable
        "update_wrapper", "singledispatch", "wraps"
    }),
    ("inspect", ): frozenset({
        "getattr_static", "getmembers", "getmembers_static",
        "currentframe", "stack", "trace",
        "getouterframes", "getinnerframes", "getframeinfo",
        "getmodule", "getfile", "getsourcefile",
        "getsource", "getsourcelines", "findsource",
        "unwrap", "get_annotations",
    }),
    ("gc",): frozenset({
        "get_objects", "get_referrers", "get_referents", "get_stats",
    }),

    # ---- frame / interpreter internals ----
    ("sys",): frozenset({
        "_getframe", "_current_frames",
        "modules",                       # sys.modules["os"]
        "settrace", "setprofile",        # callbacks receive frames
        "exc_info", "last_traceback", "last_value",
        "addaudithook", "audit",
        "meta_path", "path_hooks", "path_importer_cache", "path",  # import hooks
        "setrecursionlimit",             # DoS
        "breakpointhook", "excepthook", "unraisablehook", "displayhook",
        "_clear_type_cache", "_debugmallocstats",
    }),
    ("traceback",): frozenset({
        "walk_stack", "walk_tb", "extract_stack",
    }),

    # ---- eval / exec / compile in disguise (from strings) ----
    ("timeit", ): frozenset({"timeit", "repeat", "Timer"}),
    ("cProfile", ): frozenset({"run", "runctx", "Profile"}),
    ("profile", ): frozenset({"run", "runctx", "Profile"}),
    ("pdb", ): frozenset({"run", "runeval", "runcall", "set_trace",
                      "post_mortem", "pm", "Pdb"}),
    ("bdb",): frozenset({"Bdb"}),
    ("trace",): frozenset({"Trace"}),
    ("doctest",): frozenset({"run_docstring_examples", "testmod", "testfile",
                          "DocTestRunner"}),
    ("code",): frozenset({"interact", "InteractiveInterpreter",
                       "InteractiveConsole", "compile_command"}),
    ("codeop",): frozenset({"compile_command", "Compile", "CommandCompiler"}),
    ("py_compile",): frozenset({"compile"}),
    ("compileall",): frozenset({"compile_dir", "compile_file"}),
    ("runpy",): frozenset({"run_path", "run_module", "_run_code",
                        "_run_module_code"}),
    ("json",): frozenset({"tool"}),
    # ---- code / function / module object construction ----
    ("types",): frozenset({
        "FunctionType", "LambdaType", "CodeType", "CellType",
        "ModuleType", "MethodType", "new_class", "prepare_class",
        "DynamicClassAttribute", "coroutine",
    }),
    ("marshal",): frozenset({"load", "loads", "dump", "dumps"}),

    # ---- import machinery (also whole-module-banned) ----
    ("importlib",): frozenset({"import_module", "__import__", "reload"}),
    ("importlib", "util"): frozenset({"find_spec", "module_from_spec",
                                 "spec_from_file_location",
                                 "spec_from_loader"}),
    ("importlib", "machinery"): frozenset({
        "SourceFileLoader", "ExtensionFileLoader", "SourcelessFileLoader",
        "ModuleSpec", "FileFinder", "PathFinder",
    }),

    # ---- serialization RCE ----
    ("pickle",): frozenset({"load", "loads", "Unpickler"}),
    ("shelve",): frozenset({"open", "Shelf"}),
    ("copy",): frozenset({"copy", "deepcopy"}),  # invoke __reduce__ machinery

    # ---- config-driven RCE ----
    ("logging", "config"): frozenset({"dictConfig", "fileConfig", "listen"}),

    # ---- filesystem beyond the open() guard ----
    ("io",): frozenset({"open", "FileIO", "open_code"}),
    # ("pathlib",): frozenset({"Path", "PosixPath", "WindowsPath",
    #                       "PurePath", "PurePosixPath", "PureWindowsPath"}),
    ("shutil",): frozenset({
        "rmtree", "copy", "copy2", "copyfile", "copytree", "move",
        "which", "make_archive", "unpack_archive", "chown", "disk_usage",
    }),
    ("tempfile",): frozenset({"mkstemp", "mkdtemp", "NamedTemporaryFile",
                           "TemporaryFile", "SpooledTemporaryFile",
                           "TemporaryDirectory"}),
    ("fileinput",): frozenset({"input", "FileInput"}),
    ("linecache",): frozenset({"getline", "getlines", "updatecache",
                            "checkcache"}),
    ("codecs",): frozenset({"open"}),
    ("gzip",): frozenset({"open", "GzipFile"}),
    ("bz2",): frozenset({"open", "BZ2File"}),
    ("lzma",): frozenset({"open", "LZMAFile"}),
    ("tarfile",): frozenset({"open", "TarFile"}),
    ("zipfile",): frozenset({"ZipFile", "PyZipFile"}),
    ("sqlite3",): frozenset({"connect", "Connection"}),

    # ---- network / exfil ----
    ("urllib", "request"): frozenset({
        "urlopen", "urlretrieve", "URLopener", "FancyURLopener",
        "build_opener", "install_opener",
    }),
    ("webbrowser",): frozenset({"open", "open_new", "open_new_tab", "get",
                             "register"}),

    # ---- setattr machinery ----
    ("unittest", "mock"): frozenset({
        "patch", "Mock", "MagicMock", "NonCallableMock", "PropertyMock",
        "create_autospec", "seal",
    }),
    ("mock",): frozenset({
        "patch", "Mock", "MagicMock", "create_autospec",
    }),

    # ---- windows ----
    ("winreg",): frozenset({
        "OpenKey", "OpenKeyEx", "CreateKey", "CreateKeyEx", "SetValue",
        "SetValueEx", "DeleteKey", "DeleteValue", "QueryValue",
        "QueryValueEx", "ConnectRegistry", "SaveKey", "LoadKey",
    }),
    ("typing",): frozenset({"cast"}),
    ("zoneinfo",): frozenset({"reset_tzpath"}),
    ("uuid",): frozenset({"_get_command_stdout"})
}


# ---------------------------------------------------------------------------
# Member allowlists: `module -> {members}`, default DENY. For modules that are
# overwhelmingly escape surface (`os`: system, popen, remove, fork, exec*,
# environ, kill, ...) but carry a small sub-surface the analysis has semantics
# for. The invariant this buys: everything reachable under such a module is
# something the analysis *models*, so nothing is "allowed but unmodelled".
#
# `typing` is here for a second reason: it is a types-only module in this subset,
# and its runtime-reflection members are the hazard -- `get_type_hints` in
# particular eval()s string annotations, which re-animates a laundered callable
# (`def g(x: "open"): ...; get_type_hints(g)["x"]` *is* the `open` builtin).
# Allowlisting the annotation vocabulary denies get_type_hints/get_args/get_origin/
# cast/assert_type/runtime_checkable/NewType/... by omission, which a denylist
# would keep leaking.
#
# Enforce in visit_Attribute on the access path: if any prefix of the path is a
# key here, the next component must be in its set (``os.path.join`` checks
# ``path`` against ("os",) and ``join`` against ("os", "path")). The root name
# itself is governed by the escape rules like any other module.
#
# NB: `os.listdir`/`os.walk`/`os.path.exists` & co. are read sinks -- listing or
# probing a directory outside the sandbox leaks -- and belong to the same
# containment audit as `open`.
# ---------------------------------------------------------------------------

ALLOWED_MEMBERS: dict[tuple[str, ...], frozenset[str]] = {
    ("os",): frozenset({
        "path", "sep", "pathsep", "linesep", "fspath", "PathLike",
        "listdir", "walk",
    }),
    ("os", "path"): frozenset({
        "join", "basename", "dirname", "split", "splitext",
        "isabs", "normpath", "abspath", "realpath", "commonpath",
        "exists", "isfile", "isdir",
    }),
    ("typing",): frozenset({
        # annotation vocabulary only -- none of these evaluates a name or reflects
        # on an object. The reflection members are absent on purpose (see above).
        "Annotated", "Optional", "Union", "Literal", "Any", "Final", "ClassVar",
        "Callable", "TypeAlias", "Self", "Never", "NoReturn", "LiteralString",
        "Concatenate", "Unpack",
        "TypeVar", "ParamSpec", "TypeVarTuple",
        # these also name a base (see ALLOWED_BASES)
        "NamedTuple", "TypedDict", "Protocol", "Generic",
        # abstract collection types used in annotations
        "Sequence", "Mapping", "MutableMapping", "Iterable", "Iterator", "Collection",
    }),
}


# ---------------------------------------------------------------------------
# Path sinks: operations that touch the filesystem at a path the program
# supplies. None of these is banned outright; each is legal iff the dataflow
# walker can prove the path's location (a `Located` fact). Reading, listing and
# even probing existence outside the sandbox leaks; writing outside it is worse.
# `resolve()`/`realpath()` are deliberately absent: they are the guard idiom
# that *establishes* a location and are applied to unconfined paths by design.
# Enforce in walker.ValidationWalker.visit_Call.
# ---------------------------------------------------------------------------

# What a sink does to the path, for the security policy: "list" covers listing a directory and
# probing for existence.
type AccessKind = Literal["read", "write", "list"]

# builtins and module-level functions: dotted callee -> (index of the path argument, kind).
# A missing argument (``os.listdir()``) means the current directory, i.e. the sandbox root.
# For ``open`` the mode decides between read and write; "read" is the default mode.
PATH_SINK_FUNCTIONS: dict[tuple[str, ...], tuple[int, AccessKind]] = {
    ("open",): (0, "read"),
    ("os", "listdir"): (0, "list"), ("os", "walk"): (0, "list"),
    ("os", "path", "exists"): (0, "list"), ("os", "path", "isfile"): (0, "list"),
    ("os", "path", "isdir"): (0, "list"),
}

# pathlib.Path methods: the receiver is the path. An unknown receiver counts as unproven, not
# as "probably not a Path": a user class may define these names, but a Path from an unknown
# source must not slip through on that account. For ``open`` the mode decides.
PATH_SINK_METHODS: dict[str, AccessKind] = {
    "open": "read",
    "read_text": "read", "read_bytes": "read",
    "write_text": "write", "write_bytes": "write", "mkdir": "write", "touch": "write",
    "iterdir": "list", "glob": "list", "rglob": "list",
    "exists": "list", "is_file": "list", "is_dir": "list", "replace": "write", "chmod": "write",
    "link_to": "write"
    # NB: Path.rename is banned outright (FORBIDDEN_ATTRIBUTES); Path.replace(target) is not,
    # because `replace` is also str.replace -- its *target* path goes unaudited today.
}


# ---------------------------------------------------------------------------
# Controlled APIs: the sandbox's replacements for forbidden surface, reached
# through the injected `certora` namespace (markers.py holds the runtime half).
#
# certora.exec(program, *args, cwd=...) is the only way to run a subprocess:
# no shell, output always captured, cwd mandatory. Statically (walker):
#   * no *args / **kwargs -- a command that cannot be read cannot be reported;
#   * exactly the keywords below, with the required ones present;
#   * the program is a string literal (or a name bound to exactly one): it is
#     the thing a reviewer needs to see;
#   * cwd is a sink like open(): legal iff its location is proven;
#   * the remaining arguments are reported with whatever is known about them.
# The namespace itself is a module root for the lexical rules, so `certora.exec`
# may only ever be applied, never taken as a value.
# ---------------------------------------------------------------------------

EXEC_CALLEE: tuple[str, ...] = (NAMESPACE, "exec")
EXEC_ALLOWED_KEYWORDS: frozenset[str] = frozenset({"cwd"})
EXEC_REQUIRED_KEYWORDS: frozenset[str] = frozenset({"cwd"})


# ---------------------------------------------------------------------------
# Dynamic class creation.
#
# The analysis assumes that no subclass of a sensitive class exists (so that
# `str`/`pathlib` method resolution is fixed) and that no class carries a
# dunder the program wrote (so that operator semantics are fixed). A `class`
# statement is checked for both; everything below manufactures a class from
# *data* at runtime and so bypasses the statement: arbitrary bases
# (``abc.ABCMeta("X", (pathlib.Path,), {})``, ``enum.StrEnum("Codec", "gz xz")``
# is a `str` subclass) and/or an arbitrary namespace (``type("X", (), {"__reduce__":
# f})`` injects a dunder through a string key).
#
# Enforce in visit_Call, on the *callee* path: calling one of these is a
# violation. Naming one as a base or in isinstance() is governed by
# ALLOWED_BASES / the escape rules instead -- ``class Color(enum.Enum)`` is fine,
# ``enum.Enum("Color", "RED GREEN")`` is not.
# ---------------------------------------------------------------------------

CLASS_FACTORIES: frozenset[tuple[str, ...]] = frozenset({
    ("abc", "ABCMeta"),                      # ABCMeta(name, bases, ns): type() with a hat on
    ("enum", "EnumType"), ("enum", "EnumMeta"),
    # the functional API: Enum("X", "a b"), also with type=str / a member mapping
    ("enum", "Enum"), ("enum", "IntEnum"), ("enum", "StrEnum"), ("enum", "ReprEnum"),
    ("enum", "Flag"), ("enum", "IntFlag"),
    ("dataclasses", "make_dataclass"),       # bases=(...), namespace={"__reduce__": f}
    ("types", "new_class"), ("types", "prepare_class"),   # (the module is forbidden anyway)
})

# `type` is a builtin, not a module member, and its one-argument form is
# legitimate and common. Enforce in visit_Call on the bare name: more positional
# arguments than this, or any keyword argument, is the class-creating form.
TYPE_CALL_MAX_ARGS = 1

# ``class X(metaclass=M)`` hands class creation to M -- ABCMeta, EnumType, or a
# user class deriving from `type` -- which is a class factory in disguise.
# `abc.ABC` as a base covers the one legitimate use. Enforce in visit_ClassDef
# on `node.keywords`.
FORBIDDEN_CLASS_KEYWORDS: frozenset[str] = frozenset({"metaclass"})

# Classes the program may never subclass, by any route: their method tables are
# what the analysis' expression and guard semantics are *about*.
SENSITIVE_CLASSES: frozenset[tuple[str, ...]] = frozenset({
    ("str",), ("bytes",), ("bytearray",), ("type",),
    ("pathlib", "Path"), ("pathlib", "PurePath"),
    ("pathlib", "PosixPath"), ("pathlib", "PurePosixPath"),
    ("pathlib", "WindowsPath"), ("pathlib", "PureWindowsPath"),
    ("os", "PathLike"),
    ("enum", "StrEnum"),                     # a str subclass by construction
})

# The static-inheritance rule: every base of a `class` statement must be a
# *name* -- never a computed expression -- and that name must be either a class
# the program itself defined with a `class` statement, or one of these. An
# allowlist, not a blocklist: anything not listed is a violation, which is what
# keeps SENSITIVE_CLASSES (and their stdlib subclasses) out without enumerating
# the stdlib.
#
# Enforcement preconditions: names bound by `class` statements join the
# unrebindable set (like imports and builtins), or ``class A: ...; A = str;
# class B(A): ...`` reopens the hole; and a program-defined base must itself
# have passed this check (transitively static).
ALLOWED_BASES: frozenset[tuple[str, ...]] = frozenset({
    ("object",),
    ("dict",), ("list",), ("tuple",), ("set",), ("frozenset",), ("int",), ("float",),
    ("enum", "Enum"), ("enum", "IntEnum"), ("enum", "Flag"), ("enum", "IntFlag"),
    ("abc", "ABC"),
    ("typing", "NamedTuple"), ("typing", "TypedDict"), ("typing", "Protocol"),
    ("typing", "Generic"),
}) | frozenset(
    # every builtin exception class: `class MyError(ValueError)` is idiomatic
    (name,)
    for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, BaseException)
)

# The decorators a program may use, bare (`@staticmethod`) or applied
# (`@dataclasses.dataclass(frozen=True)`). A decorator is an application without
# a Call node -- `@p.unlink` would delete the file with nothing audited, `@f`
# would run a contracted body with its rely undischarged -- and a work script has
# no business defining its own, so this is an allowlist rather than an audit.
ALLOWED_DECORATORS: frozenset[tuple[str, ...]] = frozenset({
    ("staticmethod",), ("classmethod",), ("property",),
    ("dataclasses", "dataclass"),
    ("functools", "cache"), ("functools", "lru_cache"),
    ("enum", "unique"),
    ("abc", "abstractmethod"),
})


# ---------------------------------------------------------------------------
# Receiver-independent attribute-name bans. These names are (a) non-dunder, so
# the existing dunder check misses them, and (b) meaningless / vanishingly rare
# on legitimate sandbox objects, so banning them regardless of receiver is safe
# and closes the frame/code/generator escape routes structurally.
# Enforce in visit_Attribute alongside is_dunder(node.attr).
# ---------------------------------------------------------------------------

FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset({
    # frame internals -> globals/builtins/caller
    "f_globals", "f_locals", "f_builtins", "f_back", "f_code", "f_trace",
    "f_lasti", "f_lineno", "f_valuestack",
    # generator / coroutine / async-gen -> their suspended frame + code
    "gi_frame", "gi_code", "gi_yieldfrom", "gi_running",
    "cr_frame", "cr_code", "cr_await", "cr_running", "cr_origin",
    "ag_frame", "ag_code", "ag_running", "ag_await",
    # traceback -> frame chain
    "tb_frame", "tb_next", "tb_lasti", "tb_lineno",
    # code object internals -> nested code objects / bytecode
    "co_consts", "co_code", "co_names", "co_varnames", "co_freevars",
    "co_cellvars", "co_filename", "co_qualname",
    # legacy function-attribute aliases (py2-era, some still resolve)
    "func_globals", "func_code", "func_closure", "func_dict",
    # sqlite extension loading (method on Connection objects)
    "load_extension", "enable_load_extension",
    # archive extraction (method on TarFile/ZipFile objects) -> zip-slip
    "extractall", "extract",
    # pathlib Path methods that create links or leave the sandbox (the read/write/list family is
    # a *sink* instead: legal iff the path's provenance is proven -- see PATH_SINK_METHODS)
    "unlink", "rmdir", "rename", "symlink_to", "hardlink_to", "lchmod",
    "expanduser",
    # module loader methods (from __loader__ / find_spec().loader)
    "exec_module", "load_module", "get_code", "get_source", "create_module",
    # field getters
    "get_field",
})


# ---------------------------------------------------------------------------
# Builtins to add to `sensitive_builtins`.
# NB: __import__ is a *bare dunder Name*; the current dunder logic only inspects
# Attribute/def nodes, so it is NOT caught today -- add it here explicitly, and
# also extend the Name check to reject dunder identifiers in general
# (__builtins__, __loader__, __spec__, __class__, __globals__, ...).
# ---------------------------------------------------------------------------

EXTRA_FORBIDDEN_BUILTINS: frozenset[str] = frozenset({
    "__import__",     # bare-name import bypass, currently unguarded
    "breakpoint",     # sys.breakpointhook -> pdb -> arbitrary code
})

# Dunder identifiers that must be rejected as bare Names (not just Attributes):
FORBIDDEN_BARE_DUNDER_NAMES: frozenset[str] = frozenset({
    "__import__", "__builtins__", "__loader__", "__spec__",
    "__class__", "__globals__", "__dict__", "__bases__", "__subclasses__",
    "__mro__", "__base__", "__code__", "__closure__",
})


# ---------------------------------------------------------------------------
# Plausibly-legitimate names. Ban these too if the policy tolerates the false
# positives -- recommended for a locked-down sandbox, since each is a known
# stepping stone.
# ---------------------------------------------------------------------------

REVIEW_BUILTINS: frozenset[str] = frozenset({
    "type",        # NOT for reflection: type(x).mro() only walks UP to `object`,
                   # which is a free builtin anyway, so it completes no escape by
                   # itself. The real reason to flag `type` is the 3-arg form:
                   # type(name, bases, {"__reduce__": f, ...}) INJECTS dunder
                   # methods via string dict keys, bypassing the def-name check
                   # in visit_FunctionDef. See also class-body `__x__ = f`
                   # assignments (bare-Name Store target, not an Attribute).
    "help",        # pydoc; help("os.system") imports os
    "input",       # reads stdin
    "memoryview",  # buffer surgery (with ctypes/array)
    "dir",         # attribute enumeration aid
    # NOT `super`: under a *complete* dunder ban it is not independently
    # exploitable -- every reflective attribute on a super object (__self__,
    # __thisclass__, __self_class__, and thence __subclasses__/__mro__) is a
    # banned dunder, and super().__init__ resolves to an inert object.__init__.
    # super()'s escape reputation is a RUNTIME-sandbox artifact: it bypasses
    # __getattribute__ proxies to read the raw object. certorail is static and
    # has no such proxy to bypass, so the reputation does not transfer.
})

REVIEW_CLASS_FACTORIES: frozenset[tuple[str, ...]] = frozenset({
    # Classes from data, but harmless ones: the base is fixed (tuple / dict) and
    # field names starting with "_" are rejected, so neither a sensitive base nor
    # a dunder can get in. Ban only if "static inheritance" is to mean exactly that.
    ("collections", "namedtuple"),
    ("typing", "NamedTuple"), ("typing", "TypedDict"),   # the functional forms
})

REVIEW_ATTRIBUTES: frozenset[str] = frozenset({
    # NOT `mro`: it only reaches ancestors/`object` (a free builtin) and never
    # subclasses or globals, so it is inert without a string-attr primitive that
    # can then call __subclasses__ -- and those (Part 2) work on bare `object`
    # directly, needing neither `mro` nor `type`. Ban the primitives, not `mro`.
    "register",    # ABCMeta.register, atexit.register, codecs.register
    "system",      # os.system if `os` ever leaks as a value
    "popen",       # os.popen / platform legacy
    "format_map",  # str.format_map with a hostile mapping
})
