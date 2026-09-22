# Rejected against endpoints.toml, five ways: a permitted host and method but a path the atom
# does not cover; a path that reads as covered and resolves elsewhere; a method no rule lists;
# a URL with nothing known about it; and a URL whose host and scheme are proven but whose path
# is not -- the guards prove what they prove, and reading a value as a URL gives up its text.
import sys
import urllib.parse

certora.network.get("https://api.github.com/user")

# The same `/user`, reached by dot segments. Nothing between here and the origin server
# resolves them, so the atom is what has to refuse the text.
certora.network.get("https://api.github.com/repos/example-org/example-repo/issues/../../../../user")

certora.network.delete("https://api.github.com/repos/example-org/example-repo/issues/1")
certora.network.get(sys.argv[1])

guessed = sys.argv[2]
if urllib.parse.urlsplit(guessed).scheme == "https" and urllib.parse.urlsplit(guessed).netloc == "api.github.com":
    certora.network.get(guessed)
