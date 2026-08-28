# repo_audit.py -- a non-trivial program written entirely in the certorail subset.
#
# What it does:
#   1. Pages through `gh api graphql` to collect repositories matching a search.
#   2. Selects a few by simple metrics (stars, on-disk size).
#   3. Clones the winners into a confined `repos/` directory.
#   4. "Does something": reports which clones look like Foundry (Solidity) projects.
#
# What the current analysis asks of it (and what it costs):
#   * Plain `import`s, full dotted use; a module name never appears as a value.
#     -> `main(sys.argv)` is out (that hands the list itself around); `sys.argv[1:]` is fine.
#   * Every filesystem operation is a *sink* whose path must have a proven location:
#     `open`, `Path.mkdir`, ... The location comes from literals and `/`-joins, so the
#     `repos/{slug}` paths are confined by construction -- *provided* `slug` is a safe
#     component, which is exactly one runtime assertion (in `slugify`).
#   * Relies/guarantees are `typing.Annotated` markers. `slugify` *guarantees* a safe
#     component; `clone_repo`/`is_foundry_project` *rely* on receiving one. The guarantee is
#     established by the assertion, the rely is discharged at the call sites by the guarantee.
#     Plain type annotations are the runtime guard's business, not the analysis'.
#   * Subprocesses go through `certora.exec(program, *args, cwd=...)`: literal program,
#     mandatory `cwd` (a sink), no shell, output piped, and -- the visible cost -- no splatting,
#     so the optional `-f after=<cursor>` needs the command spelled out twice.
#   * No dunders anywhere, so no `if __name__ == "__main__":`; the entry point is a top-level
#     `main()` call.
#
# Runtime assertions needed to get this accepted: one.

import json
import pathlib
import sys
import typing

SEARCH_GQL = """
query($q: String!, $after: String) {
  search(query: $q, type: REPOSITORY, first: 50, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on Repository {
        nameWithOwner
        url
        stargazerCount
        diskUsage
      }
    }
  }
}
"""


def fetch_page(search_expr: str, cursor: str | None) -> dict | None:
    # no splatting: the command is spelled out for each shape it can take
    if cursor is None:
        result = certora.exec(
            "gh", "api", "graphql", "-f", f"query={SEARCH_GQL}", "-f", f"q={search_expr}",
            cwd=pathlib.Path("."),
        )
    else:
        result = certora.exec(
            "gh", "api", "graphql", "-f", f"query={SEARCH_GQL}", "-f", f"q={search_expr}",
            "-f", f"after={cursor}",
            cwd=pathlib.Path("."),
        )
    if result.returncode != 0:
        print(f"gh api failed: {result.stderr.decode().strip()}")
        return None
    return json.loads(result.stdout)


def collect_repos(search_expr: str, page_limit: int) -> list[dict]:
    repos = []
    cursor = None
    pages = 0
    while pages < page_limit:
        payload = fetch_page(search_expr, cursor)
        if payload is None:
            break
        search = payload["data"]["search"]
        for node in search["nodes"]:
            repos.append(node)
        info = search["pageInfo"]
        if not info["hasNextPage"]:
            break
        cursor = info["endCursor"]
        pages += 1
    return repos


def pick_repos(repos: list[dict], min_stars: int, max_disk_kb: int, take: int) -> list[dict]:
    keep = []
    for r in repos:
        disk = r["diskUsage"]
        if disk is None:
            continue
        if r["stargazerCount"] >= min_stars and disk <= max_disk_kb:
            keep.append(r)
    keep = sorted(keep, key=lambda r: r["stargazerCount"], reverse=True)
    return keep[:take]


def slugify(name_with_owner: str) -> typing.Annotated[str, certora.no_slash, certora.not_dot_dot]:
    # `name_with_owner` is untrusted GraphQL data. The guarantee -- a single safe path
    # component -- is what lets `repos/{slug}` be confined downstream, and this assertion is
    # what establishes it (and what makes the analysis accept the `return`).
    slug = name_with_owner.replace("/", "__")
    assert "/" not in slug and slug not in (".", "..")
    return slug


def clone_repo(url: str, slug: typing.Annotated[str, certora.no_slash, certora.not_dot_dot]) -> bool:
    # cloning *into* `repos/` by making it the cwd: the clone target is the bare slug
    result = certora.exec("git", "clone", "--depth", "1", url, slug, cwd=pathlib.Path("repos"))
    return result.returncode == 0


def is_foundry_project(slug: typing.Annotated[str, certora.no_slash, certora.not_dot_dot]) -> bool:
    candidate = f"repos/{slug}/foundry.toml"  # located: repos / <safe component> / foundry.toml
    try:
        with open(candidate, "r") as handle:
            body = handle.read()
    except FileNotFoundError:
        return False
    return "[profile" in body


def main() -> None:
    args = sys.argv[1:]
    if len(args) < 1:
        print("usage: repo_audit <github-search-expr>")
        return
    search_expr = args[0]

    pathlib.Path("repos").mkdir(exist_ok=True)

    repos = collect_repos(search_expr, page_limit=3)
    print(f"fetched {len(repos)} repositories")

    chosen = pick_repos(repos, min_stars=100, max_disk_kb=500000, take=5)
    foundry = []
    for r in chosen:
        slug = slugify(r["nameWithOwner"])
        print(f"cloning {r['nameWithOwner']} ({r['stargazerCount']} stars)")
        if not clone_repo(r["url"], slug):
            print("  clone failed, skipping")
            continue
        if is_foundry_project(slug):
            foundry.append(r["nameWithOwner"])

    print(f"\n{len(foundry)}/{len(chosen)} clones look like Foundry projects:")
    for name in foundry:
        print(f"  {name}")


main()
