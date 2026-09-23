# certorail

Static confinement for LLM-authored Python.

A program written in a restricted subset of Python is analysed, checked against a security
policy, and — only if every filesystem and subprocess operation is *proven* to stay where the
policy allows — run in an isolated interpreter. Anything unprovable is rejected before it runs.

## Getting Started

See the instructions in the [setup guide](SETUP.md). You will need `uv` and, on Linux, `bubblewrap`.
There is no support (yet) for Windows platforms, MacOS and Linux only for now.

## Usage

There are two main entry points; `certorail` and `certorail-run`. The former is the control plane,
and is the expect method for you to manage your certorail installation and policies. `certorail-run` is
how the LLM is expected to execute programs via certorail. As part of the first time
`certorail init` process, you will have the option to configure Claude Code to whitelist `certorail-run`.

## What certorail does, and does not

certorail confines the programs that are run through it. It does not stop an agent from doing
anything else. If the agent can run a shell, edit files or call tools outside certorail, none of that
is checked, so certorail is only as good as the harness that makes `certorail-run` the agent's one
unprompted way to execute code. Claude Code's permission rules can do that; nothing in certorail
enforces it.

Programs run with your authority. A policy grant is trust you extend: a program that is allowed to
write under a directory, run a command or reach a host does so as you, and the tools it runs do
whatever those tools do. The analysis proves that the Certorail program stays within the grants; it does not
judge whether the grants were wise. Read the policy as carefully as you would a sudoers file. For
information on how to lockdown programs launched via certorail, see the [grants guide](GRANTS.md).

A policy talks about names, not objects. A grant or a protection constrains the path a program
spells, never the file that path ends up at. The rule of thumb has four consequences worth
knowing:

- A symbolic link inside a granted tree is followed. A read through it reaches wherever the link
  points; the OS jail confines writes to the root and does not confine reads.
- A relative `no-write` protection does not cover an absolute spelling of the same file. If the
  policy also grants an absolute write over the root, the protection holds only for relative
  names.
- A location hole in a program rule constrains how the argument is spelled, not how the tool
  resolves it. A network rule's `source` tags whatever comes back through that URL, redirects
  included.
- On macOS the OS jail around a tool matches paths without regard to case, so a grant written
  `notes/**/<[a-z]+\.txt>` lets a tool open `notes/NO.txt`. On the default case-insensitive
  volume that reaches no file the program could not open anyway: the same file is also
  `notes/no.txt`, which the grant admits. A grant that tells names apart by case tells spellings
  apart, not files. On a case-sensitive volume `NO.txt` and `no.txt` are two files, and there a
  grant must not rely on case to keep a tool away from one of them.

A program is rejected before it runs if any operation cannot be proven to stay within the policy.
The OS jail backs the analysis at run time; on Linux, without `bubblewrap` installed the program
runs unjailed, and certorail says so. Checkers you install run with your authority and are trusted
as written.

Programs must be written in certorail's restricted subset of Python. Arbitrary Python, other
languages and Windows are out of scope.

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
