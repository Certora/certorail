# Rejected against delegation.toml, twice over.
import pathlib

repo = pathlib.Path("checkout") / "example-repo"

# `git` has subcommand rules, so it fails closed: `push` is denied by the absence of a rule.
certora.exec("git", "push", "origin", "main", cwd=repo)

# No rule names ssh. In nono this is `"session": "deny"` beside a grant that lets git reach
# ssh; here it is the default, and there is no way to write the grant git would have used.
certora.exec("ssh", "git@github.com", cwd=repo)
