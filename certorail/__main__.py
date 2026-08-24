from .analysis import ValidationAnalysis
from ast import parse
import sys

with open(sys.argv[1], "r") as r:
    file = parse(r.read(), sys.argv[1])
    v = ValidationAnalysis()
    v.visit(file)

for (where, what) in v.violations:
    print(f"Found illegal code @ line {where.lineno} -> {what}")

for audit in v.report:
    print(audit)
