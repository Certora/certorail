import pathlib
import re
import sys

hello = "hi"
p = pathlib.Path(hello, "foo")

r = sys.argv[1]
as_path = pathlib.Path(r)
assert not as_path.is_absolute()
assert ".." not in as_path.parts
# assert ".." not in r
# assert r[0] != "/"
final_path = p / as_path
open(final_path, "r")
