# Oversteps: the draft goes out as an argument without being scanned.
import pathlib

DRAFTS = pathlib.Path("drafts")


def main() -> None:
    workdir = pathlib.Path(".")
    body = (DRAFTS / "release-note.md").read_text()
    certora.exec("post-note", "publish-text", body, cwd=workdir)


main()
