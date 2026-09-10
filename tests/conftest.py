"""The suite never reads the machine's config directory.

``policyfile`` composes ``$CONFIG/rulesets/base.toml`` into every policy it loads, so a test
that loads a policy without saying which config directory it means would pick up whatever the
developer has installed -- and a real ``base.toml`` would change the shape of every policy under
test. Point every test at an empty config directory for the whole session; tests that need
their own (``RulesetCase`` and friends) override it per test and restore this one after.
"""
import os
import pathlib
import tempfile

_ISOLATED = pathlib.Path(tempfile.mkdtemp(prefix="certorail-test-config-"))
(_ISOLATED / "rulesets").mkdir()
(_ISOLATED / "checkers").mkdir()
os.environ["CERTORAIL_CONFIG_DIR"] = str(_ISOLATED)
