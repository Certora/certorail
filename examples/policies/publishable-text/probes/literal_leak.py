# Oversteps, and it never runs: the text is a literal, so certorail runs the scanner on it
# during analysis and the program is rejected before it starts.
import pathlib


def main() -> None:
    certora.exec(
        "post-note", "publish-text", "XXX-DO-NOT-SHIP-XXX: internal build", cwd=pathlib.Path("."),
    )


main()
