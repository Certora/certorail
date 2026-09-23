import typing

# Folding under the policy view, in cf/ (casefold: see README). The first line is the control:
# head runs under the host view, straight on the filesystem, and reads Stored.txt through a
# folded spelling only if cf/ really folds. Under the policy view a name must be the directory's
# own spelling: a folded one does not exist, and a new name cannot land on a stored one.


def head(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("head", FILES=[path], cwd=".")
    print(f"head (host view) {path}: exit {r.returncode}")


def cat(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("cat", FILES=[path], cwd=".")
    print(f"cat {path}: exit {r.returncode}")


def make(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("mkdir", DIRS=[path], cwd=".")
    print(f"mkdir {path}: exit {r.returncode} {r.stderr.decode('utf-8', 'replace').strip()}".rstrip())


def touch(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("touch", FILES=[path], cwd=".")
    print(f"touch {path}: exit {r.returncode}")


def copy(src: typing.Annotated[str, certora.within(".")], dst: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("cp", SRC=src, DST=dst, cwd=".")
    print(f"cp {src} {dst}: exit {r.returncode}")


def holds(path: typing.Annotated[str, certora.within(".")]) -> None:
    # host view: what the file really holds, whatever the view let through
    r = certora.exec("head", FILES=[path], cwd=".")
    print(f"{path} holds: {r.stdout.decode('utf-8', 'replace').strip()}")


head("cf/STORED.TXT")        # control: the filesystem folds
cat("cf/Stored.txt")         # the stored spelling
cat("cf/STORED.TXT")         # a folded spelling: no such file
copy("src/main.py", "cf/STORED.TXT")   # a write through a folded spelling: refused ...
holds("cf/Stored.txt")                 # ... and the stored file untouched
make("cf/DOCS")              # would land on the stored Docs (the filesystem refuses this one itself)
touch("cf/.GIT/config")      # a folded spelling of a protected directory: no such directory
touch("cf/.git/config")      # the stored spelling: protected
touch("cf/new.txt")          # an ordinary new name: created
