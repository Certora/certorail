# An absolute write grant, /tmp/certorail-testbed-outside/{abs,alt}/**: a literal head and a
# {a,b} set, which the jail explodes into two writable binds.
open("/tmp/certorail-testbed-outside/abs/hello.txt", "w").write("hello\n")
open("/tmp/certorail-testbed-outside/alt/hello.txt", "w").write("hello\n")
print("wrote abs/hello.txt and alt/hello.txt")
