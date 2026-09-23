import os
import pathlib

# A name os.listdir yields is one component -- never "", "." or ".." -- so joined below drop/ it
# is a path at drop/*, which the one-level grant covers. drop/sub is skipped: not a file.
DROP = pathlib.Path("drop")
for name in sorted(os.listdir("drop")):
    entry = DROP / name
    if entry.is_file():
        print(entry.read_text(), end="")
