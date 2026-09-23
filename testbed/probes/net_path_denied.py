# The host and port are granted, the path is not: /private/note is under neither rule's path.
r = certora.network.get("http://127.0.0.1:8765/private/note")
print(r.body.decode("utf-8"), end="")
