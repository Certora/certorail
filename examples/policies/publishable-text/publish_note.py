# Conforming: both routes to the outside are scanned -- the text handed over as an argument,
# and the file handed over by name.
import pathlib

DRAFTS = pathlib.Path("drafts")
OUTBOX = pathlib.Path("outbox")


def main() -> None:
    workdir = pathlib.Path(".")

    # A literal the scan passes needs no check: certorail ran the scanner on this exact
    # text while checking the program.
    certora.exec("post-note", "publish-text", "Release notes follow.", cwd=workdir)

    body = (DRAFTS / "release-note.md").read_text()

    # A pure fact: it is about this exact string, so it survives the calls that follow.
    scanned = certora.check_single("scan-text", body)
    certora.exec("post-note", "publish-text", scanned, cwd=workdir)

    note = OUTBOX / "release-note.md"
    note.write_text(scanned)
    note_path = str(note)
    # An environmental fact: it is about the bytes on disk right now, so it is established
    # after the last write and immediately before the publish.
    certora.check("scan-file", path=note_path, cwd=workdir)
    certora.exec("post-note", "publish-file", note_path, cwd=workdir)


main()
