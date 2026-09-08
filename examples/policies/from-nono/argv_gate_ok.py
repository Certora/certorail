# Accepted against argv_gate.toml: two read-only subcommands, and a `gh api` call whose every
# argument carries `read-only-token` because its text does.
import pathlib

here = pathlib.Path(".")
certora.exec("gh", "issue", "list", "--repo", "example-org/example-repo", cwd=here)
certora.exec("gh", "issue", "view", "1", cwd=here)
certora.exec("gh", "api", "/repos/example-org/example-repo/issues", cwd=here)
