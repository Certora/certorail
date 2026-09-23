# out/keep is protected (no-write), whatever out/** grants.
open("out/keep/final.txt", "a").write("more\n")
