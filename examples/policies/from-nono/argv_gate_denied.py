# Rejected against argv_gate.toml. The last three lines are the three flag spellings nono has
# to enumerate one rule at a time, plus the one it misses; here they are one rule, and the
# denial names the first argument that fails to carry the atom.
import pathlib

here = pathlib.Path(".")
certora.exec("gh", "issue", "comment", "1", "--body", "hi", cwd=here)
certora.exec("gh", "api", "-X", "POST", "/repos/example-org/example-repo/issues", cwd=here)
certora.exec("gh", "api", "-XPOST", "/repos/example-org/example-repo/issues", cwd=here)
certora.exec("gh", "api", "--method=post", "/repos/example-org/example-repo/issues", cwd=here)
