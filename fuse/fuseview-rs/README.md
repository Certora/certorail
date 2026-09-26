# fuseview-rs

certorail's FUSE view (`certorail/fuseview.py`) ported to Rust, to answer one question: how much of the view's cost comes from the interpreter? Nothing in certorail runs it yet.

The algorithm is the same as the Python view's, check for check and system call for system call, except for one redundant check it drops (below): the d_path checks through `/proc/self/fd`, identity by (device, inode, type), directories by key and files by place, the folding test, the deferred `O_TRUNC`, the same filter over the same layers.

## Build

fuser 0.18 needs Rust 1.85 or later. Build from this directory, where `.cargo/config.toml` makes the executable static; its jail holds no libraries:

    cd fuse/fuseview-rs && cargo build --release

The executable lands at `target/x86_64-unknown-linux-gnu/release/fuseview-rs`. No libfuse is needed. Linking statically wants glibc's static archives (`libc6-dev` on Debian and Ubuntu). `cargo test` runs the filter's cases from `tests/test_fuseview.py` and a decoded specification.

## Run

    .venv/bin/python scripts/probe_view_find.py --rust fuse/fuseview-rs/target/x86_64-unknown-linux-gnu/release/fuseview-rs
    .venv/bin/python scripts/view_shell.py ~/certora --rust fuse/fuseview-rs/target/x86_64-unknown-linux-gnu/release/fuseview-rs

Both scripts run the daemon jailed (`scripts/native_view.py`, shared with the Lean port in `fuse/fuseview-lean`). bubblewrap gives it the served directory read-only at its own path, the executable, the specification, a `/proc` of its own and bubblewrap's minimal `/dev`, and nothing else: no other file of the host, no network, no environment. A jailed process cannot mount, so the script makes the mount outside the jail the way libfuse does. fusermount3 opens `/dev/fuse`, mounts it, and hands back the descriptor, which the daemon serves (`--fd N`). Unmounting the view ends the daemon.

The daemon's protocol:

- It prints `ready` once the kernel has connected.
- It prints a JSON line of request counts, and clears them, for each line it reads on stdin. Signals would not reach it through bubblewrap.
- It exits when the view is unmounted.

Run without `--fd`, it makes its own mount through fusermount3 (`fuseview-rs VIEW.JSON MOUNTPOINT`) and unmounts it at SIGTERM or Ctrl-C. VIEW.JSON is what `ViewSpec.document()` writes, the same as a view daemon's `view.json`. `--help` lists the cache times and the other options.

## Where it is not the Python view

- **A directory can be renamed, under the narrow rule.** The Python view refuses every directory rename. Here a directory may move from A to B when some writable grant covers both ends wholly (a subtree, or a `pre/**` pattern without a leaf) and no layer after that grant covers or reaches below either end. Every path below either end is then decided alike before and after the move. After the move, the recorded paths of every directory the kernel holds at or below A are rewritten to B; file records follow their directory. Cargo needs this: it creates `target` by renaming a freshly made temporary directory into place.
- **Listed entries don't re-check their parent.** Admitting an entry a listing found skips the parent's path check the Python view makes, one `readlink` per entry. The listing's scan already checked the directory, and nothing more is acted on: a file is recorded untouched, and every later use of it checks its parent again; a directory checks its own full path, which vouches for every directory above it. A lookup still checks: its stat goes through the parent and is judged by the parent's path. One visible effect is allowed by the contract: a listing's later pages keep serving what its first page found after the directory moves, where the Python view answers them ESTALE.
- **One cache time per listed entry.** fuser's listing and create replies carry one cache time for a name and its attributes together, so the Rust view sends the shorter of the two. Under the shipped times, a file found by a listing has its name cached for 0 s, where the Python view says 1 s. A stat-heavy walk after a listing (`find -size`, `ls -lR`, `du`) therefore sends a LOOKUP for each file where the Python view sends a GETATTR. The probe's request counts show this.
- **No memoised decisions.** The Python filter caches its decisions in an LRU of 200 000 entries. This one recomputes every decision.
- **fancy-regex, not `re`.** Names are fullmatched the way `re.fullmatch` would match them. The two dialects agree on ordinary patterns and differ at their edges. A regex that does not compile refuses the whole specification.
- **Non-UTF-8 names fail closed.** A name that is not UTF-8 matches no regex component, and any decision that needs one fails closed: the name is not there. Python would decode it with surrogate escapes and match it.
- **Untouched times stay untouched.** setattr leaves alone any time it was not asked to change (`UTIME_OMIT`). The Python view reads that time and writes it back.
- **Not a view daemon.** There are no leases, no idle retirement and no keydir. It serves until the view is unmounted, and the probe and `view_shell.py` start and stop it.
- **Read-only when jailed.** Its jail holds the directory read-only, so every write through the view fails EROFS, whatever the layers grant.
- **`--keep-cache` is opt-in.** With it, a file's cached pages survive across opens; without it, each open drops them. pyfuse3's default for `FileInfo.keep_cache` is undocumented. If the Python view's second `grep -r` run in the probe reads nothing, it keeps the cache, and the fair comparison is with `--keep-cache`.
- **`--threads N` adds threads.** It serves requests on N threads. Everything but `read` and `write` still runs one request at a time, under one lock.
