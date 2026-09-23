import sys

# `finally` also runs when the body raises -- here, after `path` names the protected file and
# before it is set back. Both states reach the write.
path = "out/finally.txt"
try:
    path = "out/keep/final.txt"
    if sys.argv[1:] == ["raise"]:
        raise ValueError("asked to")
    path = "out/finally.txt"
finally:
    open(path, "w").write("x\n")
