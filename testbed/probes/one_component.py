import re
import sys

# The guards of empty_component.py, with a regex that is never "" and never ".": exactly one
# component between, as data/*/x.txt says.
name = sys.argv[1]
assert "/" not in name and name != ".."
assert re.fullmatch(r"[a-z]+", name)
open(f"data/{name}/x.txt", "w").write("x\n")
print(f"wrote data/{name}/x.txt")
