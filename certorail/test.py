import sys

__builtins__["eval"]("print(3)")

ex = open
with ex("haha", "w") as d:
    d.write("asdfasdf")

with (
    certora_within(sys.argv[1], ".") as t1,
    certora_matches(t1, r"\.txt$") as t2,
    open(t2, "w") as f
):
    f.write("HAHAHAHA")
