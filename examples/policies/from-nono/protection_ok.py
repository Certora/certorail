# Accepted against protection.toml: one read of a file the lookahead admits, one listing, and
# one write into the only writable subtree.
import pathlib

notes = (pathlib.Path("workspace") / "notes.md").read_text()

for entry in (pathlib.Path("workspace") / "src").iterdir():
    print(entry)

(pathlib.Path("workspace") / "reports" / "audit.md").write_text(notes)
