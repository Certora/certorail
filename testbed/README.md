# The certorail testbed

One sandbox root and one policy that exercise every mechanism together:
- the analysis' filesystem, network and exec checks;
- `no-write` protections, concrete and patterned;
- the FUSE view on Linux and Seatbelt on macOS, around the tools the program runs;
- stored-spelling handling in a case-folding directory;
- hard links and renames through the view;
- provenance, redirect credentials, checks through the broker, `strict`, the lints, and the
  policies that must not load.

| File | What it is |
|---|---|
| `policy.toml` | the policy: every grant commented with what it exercises |
| `strict.toml` | `strict = true` over a location no jail can express |
| `lints.toml` | legal but probably unintended: what `certorail describe` flags |
| `refused/*.toml` | policies that must not load |
| `probes/*.py` | the programs, one behaviour each, headed by what they show |
| `scenario.toml` | what every probe must do: the analysis' verdict, then the run's exit and output |
| `build.py` | builds the tree under the root, and `/tmp/certorail-testbed-outside` beside it |
| `serve.py` | the local API the network probes talk to (127.0.0.1:8765 and :8766) |
| `run.py` | runs the scenario, PASS / FAIL / SKIP per item |

`tests/test_testbed.py` asserts the static half on every run of the suite: each probe's verdict
and the reason for it, and each refused policy. The run-time half needs the jail, the view and
a built root, so that is `run.py`.

## Setting up

The root defaults to `/mnt/certorail-testbed`. Folding needs a case-folding directory there,
`cf/`: an ext4 made with the casefold feature, mounted at the root, with `+F` set on `cf/`.
The attribute can only be set on an empty directory, so the build runs twice:

```sh
truncate -s 64M /var/tmp/certorail-testbed.img
mkfs.ext4 -O casefold /var/tmp/certorail-testbed.img
sudo mount -o loop /var/tmp/certorail-testbed.img /mnt/certorail-testbed
sudo chown "$USER:" /mnt/certorail-testbed
python3 testbed/build.py              # makes cf/ empty and says so
chattr +F /mnt/certorail-testbed/cf
python3 testbed/build.py              # fills cf/; from now on cf/ itself is never removed
```

Without that, `build.py --no-casefold` fills `cf/` anyway. The casefold probe then SKIPs, and its
control line (a host-view `head` through a folded spelling) fails if you run it by hand. On
macOS APFS folds by default: build under any directory you own. Then edit the one absolute path
in `lints.toml` to match the root, and do the same on Linux if you mount elsewhere.

## Running

```sh
python3 testbed/run.py                          # rebuilds, runs everything
python3 testbed/run.py view-casefold -v         # one probe, with its output
python3 testbed/run.py --certorail 'uv run certorail'
```

A probe passes when the analysis gives the verdict `scenario.toml` names, for the reason it
names. If that verdict is acceptance, the run must also exit and print as listed. Probes print
one line per attempt, so a failure shows exactly which attempt differed. To look at one by hand:

```sh
certorail run --root /mnt/certorail-testbed --policy testbed/policy.toml testbed/probes/view_write.py
certorail describe --root /mnt/certorail-testbed --policy testbed/policy.toml
```

## The tree

```
src/main.py, util.py      read src/**: a tree grant (a bind on Linux, a subpath on macOS)
src/link-out -> outside   a granted name whose file is outside every grant
notes/**                  read notes/**/<[a-z]+\.txt>: a pattern (the FUSE view, a Seatbelt regex)
catalog/                  read catalog: a literal directory, its listing and none of its files
drop/, drop/sub/          read drop and drop/*: one level; drop/sub lists, drop/sub/three.txt does not open
out/                      write out/**; out/keep protected (concrete); hard-a.txt and hard-b.txt one file
repos/alpha/.git          write repos/**; **/.git protected (a pattern)
cf/                       read and write cf/**; casefolded; Stored.txt, Docs/, .git/
data/alpha, data/beta     write data/*/x.txt: exactly one component between
private/                  under no grant: absent for a tool under the view
/tmp/certorail-testbed-outside/{abs,alt}/   absolute grants, exploded into two binds
```

## What differs on macOS

Seatbelt is the jail on macOS, and three things it cannot say show up as `[probe.darwin]`
expectations in `scenario.toml`:
- **No directory "on the way to a grant".** The root does not list for a tool under the view,
  and a pattern grant's directories do not list either. Its files open by name, but `grep -r`
  cannot find them.
- **Folded spellings reach the stored name's grant.** `cat cf/STORED.TXT` succeeds there, judged
  as `Stored.txt`. Linux's view refuses the spelling instead.
- **No hard-link or rename rules.** `view-links` is Linux only.

`view-casefold` on macOS is also the test of the working assumption that Seatbelt compares the
*stored* name. If `touch cf/.GIT/config` exits 0 there, it compares the spelled one, and the
`spelling` lint and the macOS docs are wrong.
