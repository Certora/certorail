import typing

# Listings under the policy view. An entry shows when it is readable, when its directory is, or
# when it is a directory on the way to a grant; private/ is none of these. drop/sub lies within
# drop/*, so listing it is reading a granted directory: its entries show by name, and none opens.


def listing(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("ls", FLAGS=["-A"], FILES=[path], cwd=".")
    names = " ".join(r.stdout.decode("utf-8", "replace").split())
    print(f"ls {path}: {names}")


def cat(path: typing.Annotated[str, certora.within(".")]) -> None:
    print(f"cat {path}: exit {certora.exec('cat', FILES=[path], cwd='.').returncode}")


listing(".")
listing("catalog")
listing("drop/sub")
cat("drop/sub/three.txt")
