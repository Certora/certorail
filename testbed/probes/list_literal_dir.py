import os

# `catalog` is granted literally: listing it is reading the directory itself.
for name in sorted(os.listdir("catalog")):
    print(name)
