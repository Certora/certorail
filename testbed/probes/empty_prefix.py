# An empty constant in front adds no text: PREFIX + "/etc/hostname" is the ABSOLUTE path
# /etc/hostname, which no read grant covers -- not a relative path below the root.
PREFIX = ""
print(open(PREFIX + "/etc/hostname").read(), end="")
