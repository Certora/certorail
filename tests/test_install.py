"""The installer (`certorail policy`), the shipped packs, validator checker-pins, and the
session hook: pack and
policy rotation into a scratch config directory, the closure checks both ways, conflict
refusal, pin extraction/consistency/drift, and the hook's output and silence.

The ``pin`` key is live end to end: the schema accepts it, the loader carries it onto
``policy.Validation``, and the evaluator sites verify it before exec. ``verify_all`` still
reads installed documents raw (tomllib), so the sweep needs no loadable composition."""
import os
import pathlib

import pytest

from certorail import session_hook
from certorail.install import InstallError, install_pack, install_policy, main, suggest_pins
from certorail.integrity import (
    CheckerIntegrityError,
    digest,
    document_pins,
    verify_all,
    verify_pinned,
)
from certorail.policydir import find_policy

MINI = """\
ruleset-version = 1

[atoms]
clean = { }

[[validation]]
name = "clean"
argv = ["${checkers}/is-clean"]
cwd = "."
writes = []
establishes = { cwd = ["clean"] }

[[program]]
name = "true"
cwd = "."
writes = []
"""

CHECKER = "#!/bin/sh\nexit 0\n"

PINNED_TMPL = """\
ruleset-version = 1

[atoms]
ok = {{ }}

[[validation]]
name = "pinned"
argv = ["${{checkers}}/is-clean"]
pin = "{pin}"
cwd = "."
writes = []
establishes = {{ cwd = ["ok"] }}
"""

POLICY_TMPL = """\
policy-version = 1
root = "{root}"

[[apply]]
ruleset = "mini.toml"
"""


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    config = tmp_path / "config"
    monkeypatch.setenv("CERTORAIL_CONFIG_DIR", str(config))
    return config


def make_pack(tmp_path):
    pack = tmp_path / "pack"
    (pack / "checkers").mkdir(parents=True)
    (pack / "mini.toml").write_text(MINI)
    (pack / "mini.md").write_text("program-author note\n")
    (pack / "README.md").write_text("about the pack\n")
    (pack / "checkers" / "is-clean").write_text(CHECKER)
    return pack


def test_pack_install_and_idempotence(cfg, tmp_path):
    pack = make_pack(tmp_path)
    report = install_pack(pack)
    checker = cfg / "checkers" / "is-clean"
    assert checker.is_file() and os.access(checker, os.X_OK)
    assert (cfg / "rulesets" / "mini.toml").read_text() == MINI
    assert (cfg / "rulesets" / "mini.md").is_file()
    # a pack-level README documents the pack, not the trusted tree
    assert not (cfg / "rulesets" / "README.md").exists()
    assert any("README.md" in n for n in report.notes)
    again = install_pack(pack)
    assert not again.installed and len(again.unchanged) == 3


def test_pack_closure_both_ways(cfg, tmp_path):
    pack = make_pack(tmp_path)
    (pack / "checkers" / "stray").write_text(CHECKER)
    with pytest.raises(InstallError) as e:
        install_pack(pack)
    assert "stray" in str(e.value) and "references" in str(e.value)
    (pack / "checkers" / "stray").unlink()
    (pack / "checkers" / "is-clean").unlink()
    with pytest.raises(InstallError) as e:
        install_pack(pack)
    assert "is-clean" in str(e.value)


def test_pack_conflicts_need_replace(cfg, tmp_path):
    pack = make_pack(tmp_path)
    install_pack(pack)
    (pack / "mini.toml").write_text(MINI + "\n# revised\n")
    with pytest.raises(InstallError) as e:
        install_pack(pack)
    assert "--replace" in str(e.value)
    report = install_pack(pack, replace=True)
    assert any(t.endswith("mini.toml") for t in report.installed)
    assert (cfg / "rulesets" / "mini.toml").read_text().endswith("# revised\n")


def test_policy_install_discovery_and_collisions(cfg, tmp_path):
    install_pack(make_pack(tmp_path))
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    root = str(sandbox.resolve())
    src = tmp_path / "dev.toml"
    src.write_text(POLICY_TMPL.format(root=root))
    report = install_policy(src)
    found = find_policy(sandbox)
    assert found is not None and found[0].name == "dev.toml"
    assert any("--describe" in n for n in report.notes)
    # a second file claiming the same root is refused outright
    other = tmp_path / "other.toml"
    other.write_text(POLICY_TMPL.format(root=root))
    with pytest.raises(InstallError) as e:
        install_policy(other)
    assert "dev.toml" in str(e.value)
    # revising the installed file needs --replace
    src.write_text(POLICY_TMPL.format(root=root) + "\n# revised\n")
    with pytest.raises(InstallError):
        install_policy(src)
    install_policy(src, replace=True)
    assert (found[0].read_text()).endswith("# revised\n")


def test_policy_validation_failures(cfg, tmp_path):
    rootless = tmp_path / "rootless.toml"
    rootless.write_text("policy-version = 1\n")
    with pytest.raises(InstallError) as e:
        install_policy(rootless)
    assert "root" in str(e.value)
    broken = tmp_path / "broken.toml"
    broken.write_text('policy-version = 1\nroot = "/nowhere"\n\n[[apply]]\nruleset = "nope.toml"\n')
    with pytest.raises(InstallError) as e:
        install_policy(broken)
    assert "nope.toml" in str(e.value)


def test_document_pins_extraction():
    good = {"validation": [{"name": "x", "argv": ["${checkers}/c"], "pin": "sha256:" + "0" * 64}]}
    (p,) = document_pins(good, "<t>")
    assert p.checker == "c" and p.validation == "x"
    assert document_pins({"validation": [{"name": "y", "argv": ["${checkers}/c"]}]}, "<t>") == []
    with pytest.raises(CheckerIntegrityError):  # malformed digest
        document_pins({"validation": [{"name": "x", "argv": ["${checkers}/c"], "pin": "beef"}]}, "<t>")
    with pytest.raises(CheckerIntegrityError):  # only installed checkers are pinnable
        document_pins({"validation": [{"name": "x", "argv": ["test"], "pin": "sha256:" + "0" * 64}]}, "<t>")


def test_verify_pinned_is_violent(cfg, tmp_path):
    install_pack(make_pack(tmp_path))
    installed = cfg / "checkers" / "is-clean"
    good = digest(CHECKER.encode())
    verify_pinned(installed, good)  # matching: silent
    installed.write_text("#!/bin/sh\nexit 1\n")
    with pytest.raises(CheckerIntegrityError) as e:
        verify_pinned(installed, good)
    assert "no longer mean" in str(e.value)
    with pytest.raises(CheckerIntegrityError):
        verify_pinned(cfg / "checkers" / "absent", good)


def test_verify_all_scans_installed_documents(cfg, tmp_path):
    install_pack(make_pack(tmp_path))  # supplies is-clean; mini's validation is unpinned
    # written raw: the schema does not accept `pin` yet, but verify_all reads documents raw
    pinned = PINNED_TMPL.format(pin=digest(CHECKER.encode()))
    (cfg / "rulesets" / "pinned.toml").write_text(pinned)
    vr = verify_all()
    assert vr.clean
    assert any("mini.toml" in n and "'clean'" in n for n in vr.notes)  # unpinned, noted
    (cfg / "checkers" / "is-clean").write_text("#!/bin/sh\nexit 1\n")
    vr = verify_all()
    assert not vr.clean and any("pinned" in p and "is-clean" in p for p in vr.problems)


def test_pack_pin_inconsistency_refused(cfg, tmp_path):
    pack = make_pack(tmp_path)
    wrong = PINNED_TMPL.format(pin="sha256:" + "0" * 64)
    (pack / "pinned.toml").write_text(wrong)
    with pytest.raises(InstallError) as e:
        install_pack(pack)
    assert "internally inconsistent" in str(e.value)


def test_pin_carries_to_loaded_policy(cfg, tmp_path):
    import tomllib

    from certorail.policyfile import from_data

    pack = make_pack(tmp_path)
    good = digest(CHECKER.encode())
    (pack / "pinned.toml").write_text(PINNED_TMPL.format(pin=good))
    report = install_pack(pack)
    assert any("1 validation pin" in n for n in report.notes)
    sandbox = tmp_path / "sb"
    sandbox.mkdir()
    text = 'policy-version = 1\nroot = "%s"\n\n[[apply]]\nruleset = "pinned.toml"\n' % sandbox.resolve()
    policy = from_data(tomllib.loads(text), "<t>")
    assert any(v.pin == good for v in policy.validations)


def test_cli_pin_and_verify(cfg, tmp_path, capsys):
    pack = make_pack(tmp_path)
    assert main(["pin", str(pack)]) == 0
    out = capsys.readouterr().out
    assert f'"{digest(CHECKER.encode())}"' in out and '"clean"' in out
    install_pack(pack)
    assert main(["verify"]) == 0
    assert "clean" in capsys.readouterr().out
    (cfg / "rulesets" / "pinned.toml").write_text(PINNED_TMPL.format(pin=digest(CHECKER.encode())))
    (cfg / "checkers" / "is-clean").write_text("revised text\n")
    assert main(["verify"]) == 1
    assert "is-clean" in capsys.readouterr().out


def test_edit_lands_only_a_loadable_policy(cfg, tmp_path, capsys):
    """``certorail policy edit``: the editor works on a copy; a broken edit shows its problems
    and offers to edit again or give up; a good edit rotates into place; the root cannot move."""
    from certorail.install import edit_policy

    install_pack(make_pack(tmp_path))
    root = tmp_path / "work"
    root.mkdir()
    src = tmp_path / "policy.toml"
    src.write_text(POLICY_TMPL.format(root=root))
    install_policy(src)
    found = find_policy(root)
    assert found is not None
    target, prefix = found
    original = target.read_bytes()

    def editor_writing(*versions: str):
        queue = list(versions)

        def editor(path: pathlib.Path) -> int:
            path.write_text(queue.pop(0))
            return 0

        return editor

    answers: list[str] = []

    def prompt(question: str) -> str:
        return answers.pop(0)

    # 1. broken, then quit: nothing changes, status 1
    answers[:] = ["q"]
    assert edit_policy(target, prefix, editor=editor_writing("policy-version = 1\nroot = "), prompt=prompt) == 1
    assert target.read_bytes() == original
    out = capsys.readouterr().out
    assert "does not load" in out and "discarded" in out

    # 2. broken, edit again, then good: the second version lands
    good = POLICY_TMPL.format(root=root) + '\n[[program]]\nname = "false"\ncwd = "."\n'
    answers[:] = ["x", "e"]  # a stray answer is re-asked
    assert edit_policy(target, prefix, editor=editor_writing("policy-version = 1\n[[program]]\nname = 3\n", good), prompt=prompt) == 0
    assert target.read_text() == good
    assert "updated" in capsys.readouterr().out
    assert any(p.name == "false" for p in load_policy_file_ok(target))

    # 3. unchanged: nothing to do, status 0
    assert edit_policy(target, prefix, editor=editor_writing(good), prompt=prompt) == 0
    assert "no changes" in capsys.readouterr().out

    # 4. the root may not move: refused with the reason, then quit
    answers[:] = ["q"]
    moved = good.replace(f'root = "{root}"', f'root = "{tmp_path / "elsewhere"}"')
    assert edit_policy(target, prefix, editor=editor_writing(moved), prompt=prompt) == 1
    assert "root changed" in capsys.readouterr().out
    assert target.read_text() == good

    # 5. an editor that fails leaves the file alone
    assert edit_policy(target, prefix, editor=lambda p: 1, prompt=prompt) == 1
    assert target.read_text() == good


def load_policy_file_ok(path: pathlib.Path):
    from certorail.policyfile import load_policy_file

    return load_policy_file(path).programs


def test_edit_target_resolution(cfg, tmp_path):
    from certorail.install import _edit_target

    with pytest.raises(InstallError, match="no ambient policy governs"):
        _edit_target(tmp_path, None)
    install_pack(make_pack(tmp_path))
    root = tmp_path / "work"
    root.mkdir()
    src = tmp_path / "policy.toml"
    src.write_text(POLICY_TMPL.format(root=root))
    install_policy(src)
    target, prefix = _edit_target(root / "deeper" if (root / "deeper").mkdir() is None else root, None)
    assert prefix == root.resolve() and target.name == "policy.toml"
    # a file named directly: its declared root is what it must keep
    direct, declared = _edit_target(None, src)
    assert (direct, declared) == (src, root)
    rootless = tmp_path / "rootless.toml"
    rootless.write_text("policy-version = 1\n")
    assert _edit_target(None, rootless) == (rootless, None)
    with pytest.raises(InstallError, match="no such file"):
        _edit_target(None, tmp_path / "missing.toml")


REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not (REPO / "rulesets" / "git").is_dir(), reason="the shipped packs are not in this tree")
def test_shipped_packs_install(cfg):
    """The repo's git and coreutils packs are installable units: closure exact, seven checkers
    placed executable, and the fixture root policy composes them with evaluator bytes captured."""
    import tomllib

    from certorail.policyfile import from_data

    report = install_pack(REPO / "rulesets" / "git")
    assert len([t for t in report.installed if "/checkers/" in t]) == 7
    assert any(t.endswith("git.md") for t in report.installed)
    install_pack(REPO / "rulesets" / "coreutils")
    # the fixture root policy also runs a root-authored checker of its own, outside any pack
    org = cfg / "checkers" / "org-checkout"
    org.write_text(CHECKER)
    org.chmod(0o755)
    data = tomllib.loads((REPO / "tests" / "fixtures" / "git-policy.toml").read_text(encoding="utf-8"))
    policy = from_data(data, "git-policy.toml")
    assert any(v.evaluator is not None for v in policy.validations)


def test_plugin_ships_the_skill_and_hook():
    """The plugin ships the policy-authoring skill (SKILL.md and reference.md; the program-author
    guide is package data the hook injects, not a skill file), an executable hook script, and
    manifests that parse."""
    import json

    plugin = REPO / "plugins" / "certorail"
    shipped = {p.name for p in (plugin / "skills" / "certorail-policy").iterdir() if p.is_file()}
    assert {"SKILL.md", "reference.md"} <= shipped
    assert os.access(plugin / "hooks" / "session-start.sh", os.X_OK)
    json.loads((plugin / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    hooks = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert "SessionStart" in hooks["hooks"]
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert market["plugins"][0]["source"] == "./plugins/certorail"


def test_the_guide_is_package_data():
    """The program-author guide ships inside the package, where the hook reads it."""
    import importlib.resources

    text = importlib.resources.files("certorail").joinpath("SUBSET_PROMPT.md").read_text(encoding="utf-8")
    assert "## The SafePy Dialect" in text and "## Policy Enforcement" in text
    assert session_hook.guide() == text


def test_verbs_dispatch_under_certorail(cfg, tmp_path, capsys):
    from certorail.host import main as certorail_main

    install_pack(make_pack(tmp_path))
    assert certorail_main(["policy", "verify"]) == 0
    assert "clean" in capsys.readouterr().out
    assert certorail_main(["policy", "list"]) == 0
    assert "rulesets:" in capsys.readouterr().out


def test_session_hook_output_and_silence(cfg, tmp_path, monkeypatch, capsys):
    install_pack(make_pack(tmp_path))
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    src = tmp_path / "dev.toml"
    src.write_text(POLICY_TMPL.format(root=str(sandbox.resolve())))
    install_policy(src)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(sandbox))
    assert session_hook.main() == 0
    out = capsys.readouterr().out
    assert "certorail governs" in out
    assert 'certora.check("clean"' in out
    # the agent gets the program-author guide (the subset, then the policy vocabulary) and is told
    # what to do when denied: edit THIS file, never bypass
    assert "## The SafePy Dialect" in out and "## Policy Enforcement" in out
    assert out.index("## The SafePy Dialect") < out.index('certora.check("clean"')  # guide, then policy
    assert "## When you are denied" in out
    installed_policy = cfg / "policy"
    assert str(installed_policy) in out  # the policy file's path, so the agent edits the right thing
    assert "Do **not** disable certorail" in out
    assert "base ruleset" not in out  # no base.toml installed here: no note about one
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(elsewhere))
    assert session_hook.main() == 0
    assert capsys.readouterr().out == ""
