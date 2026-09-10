#!/usr/bin/env python3
"""Install the certorail Claude Code pack, from the manifest beside this file.

    install.py [--pack-dir DIR] [--home DIR] [--claude-dir DIR] [--uninstall] [--dry-run] [--quiet]

Three verbs, and no knowledge of Claude Code beyond what ``pack.toml`` names:

  write_file   copy an artifact to a destination, refusing to clobber anything it did not write
  symlink      point a name at the checkout, so the checkout stays the single copy
  json_merge   deep-merge a patch into a JSON document, APPENDING to its arrays

That third verb is the point of the example. ``~/.claude/settings.json`` belongs to the user and
usually already holds their own hooks, environment and permissions; a merge that replaced arrays
would silently delete every hook they configured for an event this pack also uses. Each merge
records exactly what it appended, so uninstall removes exactly that and nothing else.

Idempotent: a second install re-derives the same plan, finds every step already satisfied, and
writes nothing. Stdlib only, Python 3.12+.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import pathlib
import string
import sys
import tomllib
from typing import Any

RECORD_NAME = "certorail-pack.json"
VARIABLES = ("PACK_DIR", "REPO_DIR", "HOME", "CLAUDE_DIR")


class InstallError(Exception):
    """A step refused to run. Nothing further is attempted."""


# ---------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------


def expand(template: str, env: dict[str, str]) -> str:
    """Substitute ``$NAME`` for the four known variables.

    An unknown ``$NAME`` is an error, not an empty string: a wiring step that quietly wrote to the
    wrong place would be worse than one that refused to run."""
    try:
        return string.Template(template).substitute(env)
    except KeyError as e:
        raise InstallError(f"{template!r}: unknown variable {e.args[0]}; known: {', '.join(VARIABLES)}")
    except ValueError as e:
        raise InstallError(f"{template!r}: {e}")


def load_manifest(pack_dir: pathlib.Path) -> dict:
    path = pack_dir / "pack.toml"
    if not path.is_file():
        raise InstallError(f"no manifest at {path}")
    with path.open("rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------------------
# json_merge
# ---------------------------------------------------------------------------


def json_merge(target: Any, patch: Any, path: list[str], additions: list[dict]) -> Any:
    """Deep-merge *patch* into *target*, appending to *additions* one record per change.

    Objects merge key by key. Arrays APPEND entries not already present by value, rather than
    replacing the array. Scalars take the patch's value, and the previous one is recorded so
    uninstall can put it back.

    A key the document does not have yet is recorded as the empty container plus a record per
    leaf beneath it, never as one record for the whole subtree: ``hooks`` is usually missing on a
    fresh config, and one record for it would make uninstall take away every hook the user
    configured afterwards."""
    if isinstance(target, dict) and isinstance(patch, dict):
        merged = dict(target)
        for key, value in patch.items():
            if key in merged:
                merged[key] = json_merge(merged[key], value, [*path, key], additions)
                continue
            additions.append({"op": "add-key", "path": path, "key": key})
            if isinstance(value, dict):
                merged[key] = json_merge({}, value, [*path, key], additions)
            elif isinstance(value, list):
                merged[key] = json_merge([], value, [*path, key], additions)
            else:
                merged[key] = copy.deepcopy(value)
        return merged
    if isinstance(target, list) and isinstance(patch, list):
        merged = list(target)
        for entry in patch:
            if entry not in merged:
                merged.append(copy.deepcopy(entry))
                additions.append({"op": "append", "path": path, "value": entry})
        return merged
    if target != patch:
        additions.append({"op": "set", "path": path[:-1], "key": path[-1], "previous": target})
        return copy.deepcopy(patch)
    return target


def json_unmerge(document: Any, additions: list[dict]) -> Any:
    """Undo *additions*, newest first. Anything not in the list is left exactly as it is."""
    document = copy.deepcopy(document)
    for addition in reversed(additions):
        container = document
        for step in addition["path"]:
            if not isinstance(container, dict) or step not in container:
                container = None
                break
            container = container[step]
        if container is None:
            continue
        match addition["op"]:
            case "add-key":
                # the key goes only if what it holds is back to what this pack created it as: a
                # container someone has since put their own entries in stays
                if isinstance(container, dict) and addition["key"] in container:
                    held = container[addition["key"]]
                    if not (isinstance(held, (dict, list)) and held):
                        container.pop(addition["key"])
            case "append":
                if isinstance(container, list) and addition["value"] in container:
                    container.remove(addition["value"])
            case "set":
                if isinstance(container, dict):
                    container[addition["key"]] = addition["previous"]
    return document


# ---------------------------------------------------------------------------
# the verbs
# ---------------------------------------------------------------------------


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Installer:
    def __init__(
        self,
        claude_dir: pathlib.Path,
        dry_run: bool,
        quiet: bool,
        previous_records: list[dict],
    ):
        self.claude_dir = claude_dir
        self.dry_run = dry_run
        self.quiet = quiet
        # what the last install of this pack wrote: the only thing that makes an overwrite safe
        self.previous_records = previous_records
        self.records: list[dict] = []
        self.changed = 0

    def say(self, done: str, planned: str, what: str) -> None:
        """Two spellings of the same step: what a real run did, and what a dry run would do."""
        if not self.quiet:
            print(f"would {planned} {what}" if self.dry_run else f"{done} {what}")

    def previous(self, kind: str, key: str, value: str) -> dict | None:
        return next(
            (r for r in self.previous_records if r["type"] == kind and r.get(key) == value), None
        )

    # -- write_file ---------------------------------------------------------

    def write_file(self, source: pathlib.Path, dest: pathlib.Path, mode: str | None) -> None:
        content = source.read_bytes()
        if dest.exists() or dest.is_symlink():
            record = self.previous("write_file", "path", str(dest))
            if record is None:
                raise InstallError(
                    f"write_file: refusing to overwrite {str(dest)!r} -- it exists and this pack "
                    "did not write it. Move it aside, then install again."
                )
            if dest.read_bytes() == content:
                self.records.append({"type": "write_file", "path": str(dest), "sha256": sha256(dest)})
                self.say("unchanged", "leave unchanged", str(dest))
                return
            if sha256(dest) != record["sha256"]:
                raise InstallError(
                    f"write_file: refusing to overwrite {str(dest)!r} -- it has changed since the "
                    "last install (sha256 mismatch). Revert it, or uninstall this pack first."
                )
        digest = hashlib.sha256(content).hexdigest()
        if not self.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            if mode is not None:
                dest.chmod(int(mode, 8))
        self.records.append({"type": "write_file", "path": str(dest), "sha256": digest})
        self.changed += 1
        self.say("wrote", "write", str(dest))

    # -- symlink ------------------------------------------------------------

    def symlink(self, link: pathlib.Path, target: pathlib.Path) -> None:
        if not target.exists():
            raise InstallError(f"symlink: {str(target)!r} does not exist")
        record = {"type": "symlink", "link": str(link), "target": str(target)}
        if link.is_symlink():
            if pathlib.Path(os.readlink(link)) == target:
                self.records.append(record)
                self.say("unchanged", "leave unchanged", str(link))
                return
            if not self.dry_run:
                link.unlink()
        elif link.exists():
            raise InstallError(
                f"symlink: refusing to replace {str(link)!r} -- it is a real file or directory, "
                "not a link this pack made. Move it aside, then install again."
            )
        if not self.dry_run:
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(target)
        self.records.append(record)
        self.changed += 1
        self.say("linked", "link", f"{link} -> {target}")

    # -- json_merge ---------------------------------------------------------

    def json_merge_file(self, file: pathlib.Path, patch: dict) -> None:
        document = json.loads(file.read_text(encoding="utf-8")) if file.is_file() else {}
        additions: list[dict] = []
        merged = json_merge(document, patch, [], additions)
        if not additions:
            # already merged: the earlier install's additions are what uninstall must undo, so
            # they are carried forward rather than replaced by this run's empty list
            earlier = self.previous("json_merge", "file", str(file))
            self.records.append(
                {
                    "type": "json_merge",
                    "file": str(file),
                    "additions": [] if earlier is None else earlier["additions"],
                }
            )
            self.say("unchanged", "leave unchanged", str(file))
            return
        if not self.dry_run:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        self.records.append({"type": "json_merge", "file": str(file), "additions": additions})
        self.changed += 1
        self.say("merged", "merge into", f"{file} ({len(additions)} added)")


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------


def apply(manifest: dict, pack_dir: pathlib.Path, env: dict[str, str], installer: Installer) -> None:
    for step in manifest.get("wiring", []):
        match step.get("type"):
            case "write_file":
                installer.write_file(
                    pack_dir / step["source"],
                    pathlib.Path(expand(step["dest"], env)),
                    step.get("mode"),
                )
            case "symlink":
                installer.symlink(
                    pathlib.Path(expand(step["link"], env)),
                    pathlib.Path(expand(step["target"], env)),
                )
            case "json_merge":
                patch_text = expand((pack_dir / step["patch"]).read_text(encoding="utf-8"), env)
                installer.json_merge_file(
                    pathlib.Path(expand(step["file"], env)), json.loads(patch_text)
                )
            case other:
                raise InstallError(f"unknown wiring type {other!r}")


def uninstall(records: list[dict], installer: Installer) -> None:
    """Replay the records in reverse. Nothing has to be re-derived: the record says what happened,
    so a pack.toml that has moved on since the install cannot strand anything."""
    for record in reversed(records):
        match record["type"]:
            case "write_file":
                path = pathlib.Path(record["path"])
                if not path.exists():
                    continue
                if sha256(path) != record["sha256"]:
                    installer.say("left in place", "leave in place", f"{path} (edited since install)")
                    continue
                if not installer.dry_run:
                    path.unlink()
                installer.changed += 1
                installer.say("removed", "remove", str(path))
            case "symlink":
                link = pathlib.Path(record["link"])
                if link.is_symlink() and os.readlink(link) == record["target"]:
                    if not installer.dry_run:
                        link.unlink()
                    installer.changed += 1
                    installer.say("removed", "remove", str(link))
            case "json_merge":
                file = pathlib.Path(record["file"])
                if not file.is_file() or not record["additions"]:
                    continue
                document = json.loads(file.read_text(encoding="utf-8"))
                restored = json_unmerge(document, record["additions"])
                if not installer.dry_run:
                    file.write_text(json.dumps(restored, indent=2) + "\n", encoding="utf-8")
                installer.changed += 1
                installer.say("unmerged", "unmerge from", str(file))


def write_record(record_file: pathlib.Path, manifest: dict, records: list[dict]) -> None:
    """What this install did, where the next one and the uninstall will look for it."""
    record_file.parent.mkdir(parents=True, exist_ok=True)
    record_file.write_text(
        json.dumps(
            {
                "pack": manifest.get("name", "certorail-claude-code"),
                "pack-version": manifest.get("pack-version", 0),
                "installed-at": datetime.datetime.now(datetime.UTC).isoformat(),
                "records": records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        prog="install.py", description="Install (or remove) the certorail Claude Code pack."
    )
    parser.add_argument("--pack-dir", type=pathlib.Path, default=here, help="this pack (default: the directory holding install.py)")
    parser.add_argument("--home", type=pathlib.Path, default=None, help="the home directory to install into (default: $HOME)")
    parser.add_argument("--claude-dir", type=pathlib.Path, default=None, help="Claude Code's config directory (default: $CLAUDE_HOME, else <home>/.claude)")
    parser.add_argument("--uninstall", action="store_true", help="undo a previous install, from its record")
    parser.add_argument("--dry-run", action="store_true", help="say what would happen; write nothing")
    parser.add_argument("--quiet", action="store_true", help="print only errors")
    ns = parser.parse_args(argv)

    pack_dir = ns.pack_dir.resolve()
    home = (ns.home or pathlib.Path(os.environ.get("HOME", "~")).expanduser()).resolve()
    if ns.claude_dir is not None:
        claude_dir = ns.claude_dir.resolve()
    elif os.environ.get("CLAUDE_HOME"):
        claude_dir = pathlib.Path(os.environ["CLAUDE_HOME"]).resolve()
    else:
        claude_dir = home / ".claude"
    env = {
        "PACK_DIR": str(pack_dir),
        "REPO_DIR": str(pack_dir.parent.parent),
        "HOME": str(home),
        "CLAUDE_DIR": str(claude_dir),
    }

    record_file = claude_dir / RECORD_NAME
    previous_records: list[dict] = []
    if record_file.is_file():
        previous_records = json.loads(record_file.read_text(encoding="utf-8")).get("records", [])

    installer = Installer(claude_dir, ns.dry_run, ns.quiet, previous_records)
    manifest: dict = {}
    try:
        if ns.uninstall:
            uninstall(previous_records, installer)
            if record_file.is_file() and not ns.dry_run:
                record_file.unlink()
                installer.say("removed", "remove", str(record_file))
        else:
            manifest = load_manifest(pack_dir)
            apply(manifest, pack_dir, env, installer)
            # a run that changed nothing and plans nothing new leaves the record alone, so a
            # reinstall does not churn its timestamp
            settled = installer.changed == 0 and installer.records == previous_records
            if not ns.dry_run and not settled:
                write_record(record_file, manifest, installer.records)
    except InstallError as e:
        # the steps that ran before the refusal are already on disk, so they are recorded too:
        # the record is what lets --uninstall take them back out, and what lets the next install
        # recognise its own files instead of refusing to touch them
        if not ns.uninstall and not ns.dry_run and installer.records:
            write_record(record_file, manifest, installer.records)
        print(f"install.py: {e}", file=sys.stderr)
        return 1

    if not ns.quiet:
        verb = "removed" if ns.uninstall else "installed"
        if ns.dry_run:
            print(f"dry run: {installer.changed} step(s) would change, in {claude_dir}")
        else:
            print(f"{verb}: {installer.changed} step(s) changed, into {claude_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
