# A lambda body runs when called, not where it is written: by then `target` names the protected
# file. A body sees only module constants, and `target` is bound twice, so it is not one.
target = "out/lambda.txt"
write = lambda: open(target, "w").write("x\n")
target = "out/keep/final.txt"
write()
