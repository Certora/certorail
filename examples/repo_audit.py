# repo_audit.py -- a non-trivial program written entirely in the certorail subset.
#
# What it does:
#   1. Pages through `gh api graphql` to collect repositories matching a search.
#   2. Selects a few by simple metrics (stars, on-disk size).
#   3. Clones the winners into a confined `repos/` directory.
#   4. "Does something": reports which clones look like Foundry (Solidity) projects.
#
# Subset rules exercised (and their consequences):
#   * No `import x as y`, no `from x import y`  -> plain imports, full dotted use.
#   * Modules appear ONLY as attribute receivers -> `json.loads(...)`, never `j = json`.
#   * No dunder access at all -> the `if __name__ == "__main__":` idiom is gone;
#     the entry point is just a top-level `main(sys.argv)` call (see bottom).
#   * No bare `open`; file reads go through the certora_within/matches/open guard.
#   * No subprocess module; every spawn goes through the auditable `certora_exec`.
#
# Assumed contract for the (host-provided) `certora_exec` builtin:
#   certora_exec(argv: list[str]) -> result, where argv[0] is the binary (kept a
#   literal here so the auditor can see exactly what's spawned) and `result` has
#   `.returncode: int`, `.stdout: str`, `.stderr: str`. No shell, ever.

import json
import sys

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


def fetch_page(search_expr, cursor):
    argv = [
        "gh", "api", "graphql",
        "-f", f"query={SEARCH_GQL}",
        "-f", f"q={search_expr}",
    ]
    if cursor is not None:
        argv.append("-f")
        argv.append(f"after={cursor}")
    result = certora_exec(argv)
    if result.returncode != 0:
        print(f"gh api failed: {result.stderr.strip()}")
        return None
    return json.loads(result.stdout)


def collect_repos(search_expr, page_limit):
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


def pick_repos(repos, min_stars, max_disk_kb, take):
    keep = []
    for r in repos:
        disk = r["diskUsage"]
        if disk is None:
            continue
        if r["stargazerCount"] >= min_stars and disk <= max_disk_kb:
            keep.append(r)
    keep = sorted(keep, key=lambda r: r["stargazerCount"], reverse=True)
    return keep[:take]


def slugify(name_with_owner):
    # `__` here is a string literal separator, not an identifier -- fine.
    return name_with_owner.replace("/", "__")


def clone_repo(url, slug):
    # `slug` derives from untrusted GraphQL data, so the clone target is confined
    # to `repos/` before it reaches certora_exec.
    dest = f"repos/{slug}"
    with certora_within(dest, "repos") as safe_dest:
        result = certora_exec(["git", "clone", "--depth", "1", url, safe_dest])
    return result.returncode == 0


def is_foundry_project(slug):
    candidate = f"repos/{slug}/foundry.toml"
    try:
        with (
            certora_within(candidate, "repos") as safe,
            certora_matches(safe, r"\.toml$") as checked,
            open(checked, "r") as handle,
        ):
            body = handle.read()
    except FileNotFoundError:
        return False
    return "[profile" in body


def main(argv):
    if len(argv) < 2:
        print("usage: repo_audit <github-search-expr>")
        return
    search_expr = argv[1]

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


main(sys.argv)
