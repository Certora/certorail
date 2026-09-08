# Oversteps: the file is scanned, and then written again. Whatever the scan established is
# about bytes that are no longer there.
import pathlib

DRAFTS = pathlib.Path("drafts")
OUTBOX = pathlib.Path("outbox")


def main() -> None:
    workdir = pathlib.Path(".")
    body = (DRAFTS / "release-note.md").read_text()
    note = OUTBOX / "release-note.md"
    note.write_text(body)
    note_path = str(note)
    certora.check("scan-file", path=note_path, cwd=workdir)
    note.write_text("PROJECT-BLUEBOTTLE ships tomorrow\n")
    certora.exec("post-note", "publish-file", note_path, cwd=workdir)


main()
