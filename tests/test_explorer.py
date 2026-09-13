"""Smoke tests for the policy explorer: the atom cross-reference index, and every detail
card rendering against a policy that exercises each shape (flat rule, template holes of all
three kinds, demands, regions, sources, network requires)."""
from rich.console import Console, RenderableType

from certorail.explorer import (
    ExplorerApp,
    atom_card,
    atom_index,
    fs_card,
    hole_card,
    network_card,
    region_card,
    rule_card,
    signature_text,
    source_card,
    validation_card,
)
from certorail.policyfile import from_data

POLICY: dict[str, object] = {
    "policy-version": 1,
    "filesystem": {"read": ["repos/**"], "write": ["repos/**"], "list": ["repos/**"]},
    "regions": {
        "git.config": {"footprint": ".git/config", "about": "what git reads from config"},
        "git.remote": {"network": True, "about": "the remote repository"},
    },
    "atoms": {
        "no-flag": {"matches": "[^-].*"},
        "org-checkout": {"reads": ["git.config"]},
        "gh-api": {"pure": True},
        "approved": {"pure": True},
    },
    "validation": [
        {
            "name": "org-repo",
            "argv": ["test", "-d", ".git"],
            "cwd": "repos/**",
            "effect-free": True,
            "establishes": {"cwd": ["org-checkout"]},
        },
    ],
    "program": [
        {"name": "git", "subcommand": "log", "cwd": "repos/**", "effect-free": True},
        {
            "name": "git",
            "cwd": "repos/**",
            "requires": ["org-checkout"],
            "argv": ["git", "push", "origin", "${BRANCH}", "${FLAGS...}"],
            "holes": {
                "BRANCH": {"atoms": ["no-flag"]},
                "FLAGS": {
                    "kind": "flags",
                    "bare": ["-q"],
                    "--force-with-lease": {"any": True, "requires": {"BRANCH": ["no-flag"]}},
                },
            },
            "writes": ["git.remote"],
        },
        {
            "name": "git",
            "cwd": "repos",
            "argv": ["git", "clone", "--", "${URL}", "${DIR}"],
            "holes": {"URL": {"any": True}, "DIR": {"location": "*"}},
        },
    ],
    "network": [
        {"host": "api.github.com", "methods": ["GET"], "path": "/repos/**", "source": "gh-api"},
    ],
    "source": [{"name": "approved", "location": "platform/approved.json"}],
}


def load():
    return from_data(POLICY, "<test>")


def rendered(card: RenderableType) -> str:
    console = Console(record=True, width=100)
    console.print(card)
    return console.export_text()


def test_atom_index_kinds_and_crossrefs():
    policy = load()
    ix = atom_index(policy)
    assert ix["no-flag"].kind == "defined"
    assert ix["org-checkout"].kind == "environmental"
    assert ix["gh-api"].kind == "source"
    assert ix["approved"].kind == "source"
    assert ix["not-option"].kind == "built-in"
    assert any("git push" in c for c in ix["no-flag"].consumed_by)
    assert any("--force-with-lease" in c for c in ix["no-flag"].consumed_by)
    assert any("org-repo" in e for e in ix["org-checkout"].established_by)
    assert any("git push" in c for c in ix["org-checkout"].consumed_by)
    assert any("api.github.com" in y for y in ix["gh-api"].yielded_by)
    assert any("platform" in y for y in ix["approved"].yielded_by)


def test_every_card_renders():
    policy = load()
    ix = atom_index(policy)
    for kind in ("read", "write", "list"):
        assert "repos" in rendered(fs_card(kind, policy))
    for p in policy.programs:
        text = rendered(rule_card(p, ix, policy))
        assert " ".join(p.leading_words[:2]) in text
        if p.template is not None:
            for name, hole in p.template.holes.items():
                assert name in rendered(hole_card(p, name, hole, ix, policy))
    for v in policy.validations:
        assert str(v.name) in rendered(validation_card(v, ix, policy))
    for r in policy.network:
        assert r.host in rendered(network_card(r, ix, policy))
    for info in ix.values():
        assert str(info.atom) in rendered(atom_card(info, policy))
    for reg in policy.regions:
        assert str(reg.name) in rendered(region_card(reg, policy))
    for s in policy.sources:
        assert str(s.name) in rendered(source_card(s))


def test_hole_cards_carry_the_constraints():
    policy = load()
    ix = atom_index(policy)
    push = next(p for p in policy.programs if p.leading_words[:2] == ("git", "push"))
    t = push.template
    assert t is not None
    cards = {name: rendered(hole_card(push, name, hole, ix, policy)) for name, hole in t.holes.items()}
    assert "no-flag" in cards["BRANCH"] and "dash guard" in cards["BRANCH"]
    assert "--force-with-lease" in cards["FLAGS"] and "requires" in cards["FLAGS"]
    clone = next(p for p in policy.programs if p.leading_words[:2] == ("git", "clone"))
    ct = clone.template
    assert ct is not None
    url = rendered(hole_card(clone, *next(iter(ct.holes.items())), ix, policy))
    assert "anything" in url and "'--' precedes" in url


def test_signatures_and_app_construct():
    policy = load()
    flat = next(p for p in policy.programs if p.template is None)
    assert signature_text(flat).plain == "git log"
    app = ExplorerApp(policy, "<test>", None)
    assert app.ix
