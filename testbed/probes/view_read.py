import typing

# Readers under the policy view. The program may hand cat any path under the root (the hole says
# **), so every call here passes the analysis; what the tool can actually open is the view's to
# decide, and each line prints what happened.


def cat(path: typing.Annotated[str, certora.within(".")]) -> None:
    r = certora.exec("cat", FILES=[path], cwd=".")
    err = r.stderr.decode("utf-8", "replace").strip()
    print(f"cat {path}: exit {r.returncode} {err}".rstrip())


cat("src/main.py")            # a tree grant: its contents
cat("private/journal.txt")    # no grant: it does not exist for the tool
cat("notes/deep/ok.txt")      # the pattern admits it
cat("notes/deep/NO.txt")      # the pattern does not
cat("catalog/item-a.txt")     # a literal directory's entry: listed, never opened
cat("src/link-out")           # the link's target is outside the tool's world
