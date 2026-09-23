import sys

# check_single: the value binds the validation's one parameter, and the atom rides the result.
# The text is unknown until run time, so the broker runs the check.
value = certora.check_single("slug", sys.argv[1])
print("slug ok:", value)
