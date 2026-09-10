# Oversteps, and this is the one a scan of command arguments alone would miss: the text
# never appears in an argument. It is written to a file, and the file is handed over by
# name.
import pathlib

DRAFTS = pathlib.Path("drafts")
OUTBOX = pathlib.Path("outbox")


def main() -> None:
    workdir = pathlib.Path(".")
    body = (DRAFTS / "release-note.md").read_text()
    note = OUTBOX / "release-note.md"
    note.write_text(body)
    note_path = str(note)
    certora.exec("post-note", "publish-file", note_path, cwd=workdir)


main()
