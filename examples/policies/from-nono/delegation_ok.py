# Accepted against delegation.toml: four read-only git subcommands, each with a literal
# program name, literal subcommand words, and a cwd the analysis can place.
import pathlib

work = pathlib.Path("checkout")
certora.exec("git", "clone", "https://github.com/example-org/example-repo.git", cwd=work)

repo = work / "example-repo"
certora.exec("git", "fetch", "origin", cwd=repo)
certora.exec("git", "pull", "--ff-only", cwd=repo)
certora.exec("git", "ls-remote", "--heads", "origin", cwd=repo)
