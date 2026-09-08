# Rejected against endpoints.toml, four ways: a permitted host and method but a path the atom
# does not cover; a method no rule lists; a URL with nothing known about it; and a URL whose
# host and scheme are proven but whose path is not -- the guards prove what they prove, and
# reading a value as a URL gives up its text.
import sys
import urllib.parse

certora.network.get("https://api.github.com/user")
certora.network.delete("https://api.github.com/repos/example-org/example-repo/issues/1")
certora.network.get(sys.argv[1])

guessed = sys.argv[2]
if urllib.parse.urlsplit(guessed).scheme == "https" and urllib.parse.urlsplit(guessed).netloc == "api.github.com":
    certora.network.get(guessed)
