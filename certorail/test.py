import sys

with (
    certora_within(sys.argv[1], ".") as t1,
    certora_matches(t1, r"\.txt$") as t2,
    open(t2, "w") as f
):
    f.write("HAHAHAHA")

if (x := 3 > 5):
    print(x)

print(f"welp{x!r}")
