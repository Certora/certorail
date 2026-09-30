# fuseview-lean

certorail's view daemon: the FUSE filesystem that serves a directory under a policy's layers where a bind mount cannot (patterns, redlines under writable paths). `certorail/viewdaemon.py` mounts it, jails it and retires it when idle. It began (2026-09-25) as a Lean 4 port of the Python view, `certorail/fuseview.py`, alongside the Rust port (`fuse/fuseview-rs`), to measure what native execution buys; since 2026-09-29 it is the only view daemon, and the Python one is retired.

It keeps the Python view's checks, check for check, except for one redundant check it drops (below): the d_path checks through `/proc/self/fd`, identity by (device, inode, type), directories by key and files by place, the deferred `O_TRUNC`. What a layer *means* it does not decide itself: every name's state comes from the placement checker's definitions (`proofs/place`, below). There is no FUSE library underneath. It speaks the kernel's protocol itself, request by request, over a `/dev/fuse` descriptor that someone else mounted.

## Layout

- `c/shim.c` holds the system calls Lean's IO library does not make: the `*at` family, `O_PATH`, raw descriptors, all of `stat(2)`, the `/proc/self/fd` links. Each call returns `Except Errno α` and never throws. The request counters and the thread that reports them are also here.
- `Fuseview/Bytes.lean` handles names as raw bytes and the protocol's little-endian fields.
- `Fuseview/Sys.lean` declares the FFI.
- `Fuseview/NamePattern.lean` reads a `<...>` component's regex in Python's syntax and has [lean-regex](https://github.com/pandaman64/lean-regex) match it.
- `Fuseview/Match.lean` matches a pattern's components against a path's names, totally (no `partial`), spells names as the checker does (`Name.encode`/`decode`), and proves `Pattern.denotesAt_top`: a path a pattern denotes lies under one of its literal prefixes.
- `Fuseview/Filter.lean` turns a specification's layers into the checker's `Place.Layer`s and asks the checker's `Place.stateFrom` and `Place.movable` about paths, with the daemon's patterns as the matcher. `Filter.make_wellFormed` proves that matcher is what the checker's theorems assume of a view (`Place.WellFormed`). What is the daemon's own: which names show, and the closed answer to a question no regex can answer.
- `Fuseview/Spec.lean` reads a `view.json`, with Lean's own `Lean.Data.Json`.
- `Fuseview/Proto.lean` encodes the reply bodies, field for field after `fuse.h`.
- `Fuseview/View.lean` holds the inode tables and every operation. They run in an `Op` monad whose state sits outside its errors, so what an operation changed before it failed stays changed, as in the Python view.
- `Fuseview/Handle.lean` decodes each request and runs the loop.
- `Main.lean` parses the arguments and starts the loop.

## Build and test

    lake -d fuse/fuseview-lean build fuseview-lean
    lake -d fuse/fuseview-lean exe fuseview-tests

The toolchain is pinned to `v4.32.1`. Two dependencies: lean-regex, pinned at its `v4.32.0` tag, which has no dependencies of its own, and the placement checker, `proofs/place`, by path. `lake -d fuse/fuseview-lean update` fetches lean-regex once (from your shell, not from a certorail jail: lake may re-clone), and building needs no network after that. The executable lands at `.lake/build/bin/fuseview-lean`, where `certorail.native.locate_view_daemon` finds it in a checkout (`$CERTORAIL_VIEW_DAEMON` or a `fuseview-lean` on PATH otherwise).

The tests cover:
- the filter's cases (the layer semantics the Python view's tests once held), as the Rust port has them;
- a decoded specification;
- the regex, including its refusals;
- the protocol, with no kernel involved. The tests build a small tree under `.lake/build/test-tree`, serve it through the real tables, and answer hand-built requests: lookups (hidden and missing names included), getattr, open and read, a listing, readlink, refused writes, statfs, and a directory moved behind the view's back;
- locks, the same way: `flock` and POSIX locks conflicting between opens, owners and a descriptor of the test's own on the backing file, a waiting lock answered when another lets go, interrupts (before and after their request), and releases letting go of their owner's locks. Through a real mount, against a process outside: `scripts/probe_view_locks.py`.

The binary carries Lean's runtime, lean-regex (both Apache-2.0) and, through Lean's toolchain, a
static GMP (LGPL v3): what that means for shipping it is in `THIRD_PARTY.md` at the repository
root.

## Run

    .venv/bin/python scripts/probe_view_find.py --lean fuse/fuseview-lean/.lake/build/bin/fuseview-lean
    .venv/bin/python scripts/view_shell.py ~/certora --lean fuse/fuseview-lean/.lake/build/bin/fuseview-lean

Both scripts run the daemon jailed, as they run the Rust port (`scripts/native_view.py`, a thin wrapper over `certorail.native`, which is how certorail itself runs it). The jail holds the served directory (read-only from the probes, writable under certorail: the layers decide what is written), the binary at `/daemon`, the specification at `/view.json`, a `/proc` of its own and bubblewrap's minimal `/dev`. Lean's toolchain links against its own glibc, which has no static archive, so the executable is dynamic. Its jail also binds the loader and each library `ldd` resolves, read-only at their own paths, and nothing else. The mount is made outside the jail (`fusermount3`), and the descriptor is passed in as `--fd`. The daemon's protocol is the Rust port's: it prints `ready`, prints a JSON line of request counts for each line on stdin, and exits when the view is unmounted; `viewdaemon.serve` uses the counts to retire an idle view.

The specification's `cache` field sets the kernel's name caching: `"cached"` keeps a directory's entry for a second (a file's for none), `"strict"` keeps nothing, so a replacement made outside under a bind mount on the view is seen at once, at a cost to every path walk through the view. `world.toml`'s `view-daemon = "cached" | "strict"` chooses.

## Where it is not the Python view it replaced

- **Every name is decided by the placement checker's definitions.** `Filter.decided` is `Place.stateFrom` over the layers in order, `Filter.mayMoveDir` is `Place.movable`, both on the daemon's patterns as the matcher; the checker certifies a plan's mounts and the daemon serves its views by one meaning of a layer. `Filter.make_wellFormed` discharges what the checker's soundness theorems (`Place.sound`, `Place.run_sound`) assume of that matcher. A question no regex can answer (`NamePattern`) makes every answer about the path the closed one; a hide has the last word over a grant before it, and over nothing at all.
- **File locks are held on the backing files**, which neither other view can do: pyfuse3 has no lock operations, and fuser drops the flag that tells a `flock` from a POSIX lock. The daemon asks for `FUSE_POSIX_LOCKS` and `FUSE_FLOCK_LOCKS`, so the kernel sends it every lock instead of keeping them on the view's own inodes, where a process outside never meets them. A `flock` is taken on the open file's backing descriptor, one per open, so it is exactly that open file's. A POSIX lock is an open-file-description lock on one descriptor per owner (a process, to the kernel), reopened from a handle on the file: owners then conflict with each other and with a process outside, an owner never with itself, and a close of any of its descriptors (`FLUSH`) lets go of all its locks, as POSIX has it. A lock that must wait (`SETLKW`) is set aside and tried again after every request and every 10 ms, so the one-request-at-a-time loop never blocks in a call; an interrupt answers it `EINTR`, including one the kernel delivered before its request.
- **A directory can be renamed, under the narrow rule**, as in the Rust port and the Python view. A directory may move from A to B when some writable grant covers both ends wholly and no layer after that grant covers or reaches below either end. The recorded paths of the directories the kernel holds under it are then rewritten. Cargo creates `target` by renaming a temporary directory into place.
- **A hidden name shows, and refuses the rest with EACCES**, files and directories alike: the name lists and looks up where its directory is readable; opening the file, listing the directory, and looking anything up inside it are `EACCES`, never `ENOENT`, so a tool meets a refusal and not an absence (a missing `~/.gitconfig` is silently defaults; a refused one at least says so).
- **Listed entries don't re-check their parent**, as in the Rust port. Admitting an entry a listing found skips the parent's path check the Python view makes, one `readlink` per entry. The scan already checked the directory; a file is recorded untouched and re-checked at every later use; a directory checks its own full path. A lookup still checks. The tests pin the one visible effect: a listing's later pages keep serving after its directory moves, while a lookup under it is ESTALE.
- **Protocol 7.31, spoken directly.** It asks for the INIT flags libfuse gives pyfuse3: listings with attributes, `auto_inval_data`, atomic `O_TRUNC`, parallel directory operations. It writes a name's cache time and its attributes' separately everywhere. The Rust port can't: fuser takes one time for both in listings.
- **A verified regex engine, fed Python's syntax.** lean-regex's matchers are proven sound and complete against its own semantics. Policies spell patterns in Python's `re` syntax, so `NamePattern` parses the part of it a name pattern uses: literals and escapes, `.`, sets, `\d \w \s`, groups, alternation, the repeats, `^ $ \A \Z`. It then prints the pattern again in lean-regex's syntax with nothing left to interpretation: every character spelled `\u{…}`, `.` as "anything but a newline", `{,n}` as `{0,n}`, the whole anchored at both ends. Anything else refuses the specification: lookarounds, backreferences, flags, atomic groups, `\b`, possessive repeats. Where the two engines could still differ, a name has no answer and the filter fails closed:
  - lean-regex's `\d \w \s` are ASCII and its `\s` leaves out the vertical tab, while Python's are Unicode. So a pattern holding one of them has no answer on a name with a character outside printable ASCII.
  - Python's `$` also matches just before a final newline. So no pattern has an answer on a name holding a newline.
- **Non-UTF-8 names fail closed** under a regex, as in the Rust port.
- **No memoised decisions**, as in the Rust port.
- **Single-threaded.** One request at a time, with no lock to take; a file lock that must wait waits outside the loop (above).
- **Panics don't fail the request.** An out-of-range index prints a panic and goes on with a default value. The Python and Rust views answer that request EIO instead.
- **`--keep-cache` is opt-in**, as in the Rust port.
