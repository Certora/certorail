# The contrast to view_read.py: `head` runs under the host view, trusted with the whole
# filesystem, so the file no grant covers is there for it.
r = certora.exec("head", FILES=["private/journal.txt"], cwd=".")
print(f"head private/journal.txt: exit {r.returncode}")
