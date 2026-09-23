import sys

# check: every declared parameter by name; the atom lands on the variable passed.
value = sys.argv[1]
certora.check("slug", value=value)
print("slug ok:", value)
