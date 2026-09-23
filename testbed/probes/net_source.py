# Provenance: the rule governing this request names `source = "testbed-api"`, so what is
# extracted from its response carries that atom, which is all echo's WORD hole accepts. The
# guard supplies not-option (echo has no "--" to protect it).
r = certora.network.get("http://127.0.0.1:8765/pub/branch.json")
name = certora.extract(r, ".name")
assert not name.startswith("-")
print(certora.exec("echo", name, cwd=".").stdout.decode("utf-8"), end="")
