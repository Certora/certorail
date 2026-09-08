# Accepted against paths.toml: every path is built from literals, so the analysis places each
# site inside a granted location without a single runtime assertion.
import pathlib

settings = pathlib.Path("config") / "settings.json"
text = settings.read_text()

for entry in pathlib.Path("src").iterdir():
    print(entry)

(pathlib.Path("reports") / "summary.md").write_text(text)
