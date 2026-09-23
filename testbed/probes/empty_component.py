import re
import sys

# No "/" and not "..": a safe component, by the atoms. But [a-z.]* also admits "" and ".", and
# data/<either>/x.txt is data/x.txt -- not one component between, so data/*/x.txt cannot cover
# it. Compare one_component.py: the same guards, a regex that admits neither.
name = sys.argv[1]
assert "/" not in name and name != ".."
assert re.fullmatch(r"[a-z.]*", name)
open(f"data/{name}/x.txt", "w").write("x\n")
