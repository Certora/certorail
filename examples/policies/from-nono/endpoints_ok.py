# Accepted against endpoints.toml. The first two URLs are literals, so the analysis reads the
# text and discharges the atom itself. The third is an argument: the urlsplit guards prove the
# scheme and the netloc, and the check establishes the atom the guards cannot.
import sys
import urllib.parse

certora.network.get("https://api.github.com/repos/example-org/example-repo/issues")
certora.network.get("https://api.github.com/repos/example-org/example-repo/issues/1/comments")

url = sys.argv[1]
if urllib.parse.urlsplit(url).scheme == "https" and urllib.parse.urlsplit(url).netloc == "api.github.com":
    certora.check("issues-endpoint-check", url=url)
    certora.network.get(url)
