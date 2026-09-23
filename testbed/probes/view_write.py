import typing

# Writers under the policy view: write grants are writable, protections and read grants are not,
# and a path under no grant does not exist.


def touch(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("touch", FILES=[path], cwd=".")
    print(f"touch {path}: exit {r.returncode}")


def copy(src: typing.Annotated[str, certora.within(".")], dst: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("cp", SRC=src, DST=dst, cwd=".")
    print(f"cp {src} {dst}: exit {r.returncode}")


touch("out/view-new.txt")           # a write grant: created
touch("out/keep/final.txt")         # a concrete protection
touch("repos/alpha/.git/config")    # a patterned protection
touch("src/new.py")                 # a read grant is never writable
touch("private/new.txt")            # no grant: no such directory
copy("src/main.py", "out/main-copy.py")          # read from one grant, written to another
copy("src/main.py", "repos/alpha/.git/hooks")    # into a protection
