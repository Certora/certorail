# Rejected against paths.toml, twice over.
import pathlib

# `config/**` is granted read, not write. nono would write this as an `allow` (read+write)
# with a `deny` carved out of it; certorail has no deny, so a narrower grant is the whole
# mechanism -- and the write is denied because nothing permits it, not because a rule forbids it.
(pathlib.Path("config") / "settings.json").write_text("{}")

# An absolute location and a root-relative one never relate, so a sandbox-relative grant says
# nothing about /etc.
pathlib.Path("/etc/hosts").read_text()
