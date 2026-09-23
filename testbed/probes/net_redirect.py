# Credentials on redirects, as curl does it: a hop to the same origin keeps Authorization, a hop
# to another origin -- here only the port differs -- drops it. /headers echoes what arrived.
AUTH = {"Authorization": "Bearer testbed-demo"}
same = certora.network.get("http://127.0.0.1:8765/hop-same", headers=AUTH)
other = certora.network.get("http://127.0.0.1:8765/hop-port", headers=AUTH)
print("same origin keeps it:", "authorization" in same.body.decode("utf-8"))
print("another port drops it:", "authorization" not in other.body.decode("utf-8"))
