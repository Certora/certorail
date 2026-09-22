# Rejected against any policy at all, and not by the policy: deletion is outside the subset,
# so this is a violation rather than a denial. nono needs unlink_protection because deletion is
# otherwise available; here there is nothing to protect.
import pathlib

(pathlib.Path("workspace") / "reports" / "audit.md").unlink()
