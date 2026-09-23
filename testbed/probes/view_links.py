import typing

# Hard links and renames under the policy view. The policy judges names, and a file with two
# names could be written through either, so a file with several names is never written through
# the view, and a link may be made only to a file that may be written. Files rename freely
# between permitted names; directories do not rename at all. Each line: what was tried, and the
# tool's exit status.


def touch(path: typing.Annotated[str, certora.within(".")]) -> int:
    return certora.exec("touch", FILES=[path], cwd=".").returncode


def link(target: typing.Annotated[str, certora.within(".")], name: typing.Annotated[str, certora.within(".")]) -> int:
    return certora.exec("ln", TARGET=target, LINK=name, cwd=".").returncode


def move(src: typing.Annotated[str, certora.within(".")], dst: typing.Annotated[str, certora.within(".")]) -> int:
    return certora.exec("mv", SRC=src, DST=dst, cwd=".").returncode


def make(path: typing.Annotated[str, certora.within(".")]) -> int:
    return certora.exec("mkdir", DIRS=[path], cwd=".").returncode


print("touch out/hard-a.txt (built with two names):", touch("out/hard-a.txt"))
print("touch out/links-a.txt (one name):", touch("out/links-a.txt"))
print("ln out/links-a.txt out/links-b.txt (a writable target):", link("out/links-a.txt", "out/links-b.txt"))
print("touch out/links-a.txt (now two names):", touch("out/links-a.txt"))
print("ln repos/alpha/.git/config out/config-link (a protected target):", link("repos/alpha/.git/config", "out/config-link"))
touch("out/mv-a.txt")
print("mv out/mv-a.txt out/mv-b.txt (between permitted names):", move("out/mv-a.txt", "out/mv-b.txt"))
print("mv out/mv-b.txt out/keep/mv-c.txt (into a protection):", move("out/mv-b.txt", "out/keep/mv-c.txt"))
make("out/dir-a")
print("mv out/dir-a out/dir-b (a directory):", move("out/dir-a", "out/dir-b"))
