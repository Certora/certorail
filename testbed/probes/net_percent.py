# The path is read as sent. %2e%2e decodes to "..", and the server may read it either way, so a
# path whose escapes spell ".." or "/" has no location at all -- not /pub/**, nor anything else.
r = certora.network.get("http://127.0.0.1:8765/pub/%2e%2e/private/note")
print(r.body.decode("utf-8"), end="")
