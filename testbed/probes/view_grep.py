# grep -r under the policy view: "needle" is in five files, and the tool finds the two it may
# read. The others are absent (private/, NO.txt) or listed but unreadable (the catalog entry: an
# error on stderr, not a match).
r = certora.exec("grep", FLAGS=["-r", "-l"], PATTERN="needle", FILES=["src", "notes", "catalog", "private"], cwd=".")
for line in sorted(r.stdout.decode("utf-8", "replace").split()):
    print(line)
