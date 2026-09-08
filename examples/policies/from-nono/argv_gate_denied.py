# Rejected against argv_gate.toml. The three flag spellings nono has to enumerate one rule at a
# time, plus the one it misses, plus the graphql endpoint its first deny entry is about; here
# they are one rule, and the denial names the first argument that fails to carry the atom.
import pathlib

here = pathlib.Path(".")
certora.exec("gh", "issue", "comment", "1", "--body", "hi", cwd=here)
certora.exec("gh", "api", "-X", "POST", "/repos/example-org/example-repo/issues", cwd=here)
certora.exec("gh", "api", "-XPOST", "/repos/example-org/example-repo/issues", cwd=here)
certora.exec("gh", "api", "--method=post", "/repos/example-org/example-repo/issues", cwd=here)

# `gh api graphql` sends a mutation without naming a method anywhere in the argv, so the atom
# has to name the endpoint itself.
certora.exec("gh", "api", "graphql", "-f", "query=mutation{}", cwd=here)
