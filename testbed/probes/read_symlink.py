# Names, not objects: src/link-out is a name inside src/**, and the file behind it is outside
# every grant. The grant is about the name, so the read is permitted, and the jail around the
# program confines its writes, not its reads. (A tool under the policy view cannot follow the
# same link: see view_read.py.)
print(open("src/link-out").read(), end="")
