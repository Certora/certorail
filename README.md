# certorail

Static confinement for LLM-authored Python.

A program written in a restricted subset of Python is analysed, checked against a security
policy, and — only if every filesystem and subprocess operation is *proven* to stay where the
policy allows — run in an isolated interpreter. Anything unprovable is rejected before it runs.

## Getting Started

See the instructions in the [setup guide](SETUP.md). You will need at least `srt` and `uv` plus, on Linux, `bubblewrap`.
There is no support (yet) for Windows platforms, MacOS and Linux only for now.

## Usage

There are two main entry points; `certorail` and `certorail-run`. The former is the control plane,
and is the expect method for you to manage your certorail installation and policies. `certorail-run` is
how the LLM is expected to execute programs via certorail. As part of the first time
`certorail init` process, you will have the option to configure Claude Code to whitelist `certorail-run`.

## Control Plane

`certorail init` initializes a policy within its working folder (or the folder specified by the `--root` option).
It conducts a short interview to determine your bootstrap needs.

The actual policy in a folder can be edited by simply running `certorail policy edit`; this will drop
you into your preferred editor with a copy of the policy. On exit, it will parse and validate the file, warning you of
any incompatibilities prompting you to re-edit (in the style of git interactive patch editing.)

Rulesets are shared vocabularies of allowed commands. `certorail policy install coreutils` installs the
read-only coreutils pack that ships with certorail, `certorail policy install some-pack/` installs a pack from
a directory. NB that installing a pack is *not* the same thing as *enabling* it within a give root; you will
still need to add the relevant `[[apply]]` directives to your root's policy file (see `policy apply` below).

`certorail policy install my-policy.toml` takes the named policy file and installs it for the root it declares.
Nothing lands unless the whole thing validates against what is already installed.

`certorail policy apply git.toml where=.` brings an installed ruleset into your folder's policy, with its
bindings given as `KEY=VALUE`; whatever you leave out, it asks for. `certorail policy list` shows what is
installed and who applies it. `certorail policy verify` re-checks every pinned checker against its recorded
hash, for after anything other than the installer has touched the config directory.

`certorail describe` prints what your folder's policy permits, in the form the LLM sees it: every grant,
program shape, validation and atom. `certorail explore` is the same policy as a navigable tree in your
terminal.

`certorail check prog.py` analyses a program against the policy without running it and reports every
operation with its proven location, or the reason it was denied; `certorail run prog.py` does the same and
then runs it. Both take `--policy FILE` to try a draft policy before you install it.

`certorail view status` lists the filesystem views certorail keeps mounted for jailed tools under a
patterned policy, and `certorail view stop` unmounts them. These are both Linux only, and you will rarely need either.

## License

GPL-3.0-only. © Certora Ltd.
