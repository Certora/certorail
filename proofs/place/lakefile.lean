import Lake
open Lake DSL

package «place»

/-- The placement checker: a jail's mounts certified against its grants, and the proof that a
certified jail holds exactly what the grants mean, over a whole run. -/
@[default_target]
lean_lib Place

/-- The checker as certorail runs it: a plan on stdin, a verdict on stdout. Linked dynamically: the
toolchain's own glibc has no static archive. Its jail (`sandbox/certify.py`) holds the loader and
the libraries it names, and nothing else. -/
@[default_target]
lean_exe «place-check» where
  root := `Main

/-- The checker run on hand-built plans: the ones it must accept, and the ones it must refuse. -/
lean_exe «place-tests» where
  root := `Tests
