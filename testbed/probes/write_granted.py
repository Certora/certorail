# A write inside a write grant (out/**).
open("out/new.txt", "w").write("written by the program\n")
print("wrote out/new.txt")
