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
  * FORBIDDEN_ATTRIBUTES     -- non-dunder attribute names banned regardless of
                                receiver (the frame/code/generator structural
                                surface + a few rare-but-lethal method names).
                                Complements the existing dunder ban.
  * EXTRA_FORBIDDEN_BUILTINS -- add to `sensitive_builtins`.
  * REVIEW_*                 -- plausibly-legitimate names; ban if your policy
                                can afford the false positives (recommended for
                                a locked-down sandbox).
"""

# ---------------------------------------------------------------------------
# Whole-module bans: no legitimate sandbox use; import is itself a violation.
# (Enforce in visit_Import: reject if the imported dotted name, or any prefix
# of it, is in this set. `import os.path` binds `os`, so match on prefixes.)
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES: frozenset[str] = frozenset({
    # process / shell / native code execution
    "os", "posix", "nt", "subprocess", "_posixsubprocess", "pty",
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
    "xml", "xmlrpc",
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
    "venv", "ensurepip", "pip",
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
    ("pathlib",): frozenset({"Path", "PosixPath", "WindowsPath",
                          "PurePath", "PurePosixPath", "PureWindowsPath"}),
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
}


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
    # pathlib Path methods (receiver is a Path variable, not the module)
    "read_text", "read_bytes", "write_text", "write_bytes",
    "unlink", "rmdir", "symlink_to", "hardlink_to", "lchmod",
    "expanduser",
    # module loader methods (from __loader__ / find_spec().loader)
    "exec_module", "load_module", "get_code", "get_source", "create_module",
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
