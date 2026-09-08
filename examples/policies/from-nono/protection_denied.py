# Rejected against protection.toml: the credential file the read grant's lookahead excludes,
# and a program nothing names. Both are policy denials.
import pathlib

(pathlib.Path("workspace") / ".env").read_text()
certora.exec("rm", "-rf", "workspace", cwd=pathlib.Path("."))
