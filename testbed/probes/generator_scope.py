# A generator expression's element runs as it is consumed: `name` is rebound before the loop
# pulls the first element.
name = "out/generator.txt"
files = (open(name, "w") for _ in range(1))
name = "out/keep/final.txt"
for f in files:
    f.write("x\n")
