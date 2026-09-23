# The analysis sees only the URL the program names, and the rule admits both of these. Where the
# server redirects is for the broker to judge, hop by hop: /private/note is under no rule's path,
# and a path whose escapes spell ".." has no location at all. Each line prints what happened.
try:
    certora.network.get("http://127.0.0.1:8765/hop-private")
    print("hop to /private/note: followed")
except certora.NetworkError as e:
    print(f"hop to /private/note: {e}")
try:
    certora.network.get("http://127.0.0.1:8765/hop-percent")
    print("hop to /pub/%2e%2e/private/note: followed")
except certora.NetworkError as e:
    print(f"hop to /pub/%2e%2e/private/note: {e}")
