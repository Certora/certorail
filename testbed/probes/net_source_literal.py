# The same text, named by the program instead of returned by the API: no testbed-api atom.
print(certora.exec("echo", "feature-x", cwd=".").stdout.decode("utf-8"), end="")
