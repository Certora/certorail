from .safepy import _ImportAnalysis, ValidationAnalysis
from ast import parse
import sys

with open(sys.argv[1], "r") as r:
    file = parse(r.read(), sys.argv[1])

i = _ImportAnalysis()
i.visit(file)

if i.report_violations():
    sys.exit(1)

a = ValidationAnalysis(frozenset(i._imports))
a.visit(file)

if a.report_violations():
    sys.exit(1)
sys.exit(0)
