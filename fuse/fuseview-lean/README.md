# fuseview-lean

certorail's FUSE view (`certorail/fuseview.py`) ported to Lean 4, executable only, with no proofs. It asks the Rust port's question again (`scratch/fuseview-rs`): what does native execution buy? This is a scratch experiment, and nothing in certorail runs it.

It follows the same algorithm as the Python view, check for check, except for one redundant check it drops (below): the d_path checks through `/proc/self/fd`, identity by (device, inode, type), directories by key and files by place, the folding test, the deferred `O_TRUNC`, the same filter over the same layers. There is no FUSE library underneath. It speaks the kernel's protocol itself, request by request, over a `/dev/fuse` descriptor that someone else mounted.

## Layout

- `c/shim.c` holds the system calls Lean's IO library does not make: the `*at` family, `O_PATH`, raw descriptors, all of `stat(2)`, the `/proc/self/fd` links. Each call returns `Except Errno α` and never throws. The request counters and the thread that reports them are also here.
- `Fuseview/Bytes.lean` handles names as raw bytes and the protocol's little-endian fields.
- `Fuseview/Sys.lean` declares the FFI.
- `Fuseview/Json.lean` reads the specification.
- `Fuseview/Regex.lean` matches `<...>` components.
- `Fuseview/Filter.lean` holds the layers and their meaning.
- `Fuseview/Spec.lean` reads a `view.json`.
- `Fuseview/Proto.lean` encodes the reply bodies, field for field after `fuse.h`.
- `Fuseview/View.lean` holds the inode tables and every operation. They run in an `Op` monad whose state sits outside its errors, so what an operation changed before it failed stays changed, as in the Python view.
- `Fuseview/Handle.lean` decodes each request and runs the loop.
- `Main.lean` parses the arguments and starts the loop.

## Build and test

    lake -d scratch/fuseview-lean build fuseview-lean
    lake -d scratch/fuseview-lean exe fuseview-tests

The toolchain is pinned to `v4.32.1`, and there are no dependencies to fetch. The executable lands at `.lake/build/bin/fuseview-lean`.

The tests cover:
- the filter's cases from `tests/test_fuseview.py`, as the Rust port has them;
- a decoded specification;
- the regex, including its refusals;
- the protocol, with no kernel involved. The tests build a small tree under `.lake/build/test-tree`, serve it through the real tables, and answer hand-built requests: lookups (hidden and missing names included), getattr, open and read, a listing, readlink, refused writes, statfs, and a directory moved behind the view's back.

## Run

    .venv/bin/python scripts/probe_view_find.py --lean scratch/fuseview-lean/.lake/build/bin/fuseview-lean
    .venv/bin/python scripts/view_shell.py ~/certora --lean scratch/fuseview-lean/.lake/build/bin/fuseview-lean

Both scripts run the daemon jailed, as they run the Rust port (`scripts/native_view.py`). The jail holds the served directory read-only, the binary, the specification, a `/proc` of its own and bubblewrap's minimal `/dev`. Lean's toolchain links against its own glibc, which has no static archive, so the executable is dynamic. Its jail also binds the loader and each library `ldd` resolves, read-only at their own paths, and nothing else. The daemon's protocol is the Rust port's: it prints `ready`, prints a JSON line of request counts for each line on stdin, and exits when the view is unmounted.

## Where it is not the Python view

- **A directory can be renamed, under the narrow rule**, as in the Rust port. The Python view refuses every directory rename. Here a directory may move from A to B when some writable grant covers both ends wholly and no layer after that grant covers or reaches below either end. The recorded paths of the directories the kernel holds under it are then rewritten. Cargo creates `target` by renaming a temporary directory into place, which the Python view refuses.
- **Listed entries don't re-check their parent**, as in the Rust port. Admitting an entry a listing found skips the parent's path check the Python view makes, one `readlink` per entry. The scan already checked the directory; a file is recorded untouched and re-checked at every later use; a directory checks its own full path. A lookup still checks. The tests pin the one visible effect: a listing's later pages keep serving after its directory moves, while a lookup under it is ESTALE.
- **Protocol 7.31, spoken directly.** It asks for the INIT flags libfuse gives pyfuse3: listings with attributes, `auto_inval_data`, atomic `O_TRUNC`, parallel directory operations. It writes a name's cache time and its attributes' separately everywhere. The Rust port can't: fuser takes one time for both in listings.
- **Its own regex.** A Pike VM runs Python's syntax for the part a name pattern uses: literals and escapes, `.`, sets, `\d \w \s`, groups, alternation, the repeats, `^ $ \A \Z`. Anything else refuses the specification: lookarounds, backreferences, flags, atomic groups, `\b`. Here `\d \w \s` are ASCII, while Python's are Unicode. So on a non-ASCII name, a pattern holding one of them has no answer, and the filter fails closed.
- **Non-UTF-8 names fail closed** under a regex, as in the Rust port.
- **No memoised decisions**, as in the Rust port.
- **Single-threaded.** One request at a time, with no lock to take.
- **Not a view daemon, and read-only when jailed**, as with the Rust port.
- **Panics don't fail the request.** An out-of-range index prints a panic and goes on with a default value. The Python and Rust views answer that request EIO instead.
- **`--keep-cache` is opt-in**, as in the Rust port.
