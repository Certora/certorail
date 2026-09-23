# A request the first network rule admits: scheme, host, port, method and path.
r = certora.network.get("http://127.0.0.1:8765/pub/hello.txt")
print(r.body.decode("utf-8"), end="")
