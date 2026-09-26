import Lake
open Lake DSL System

package «fuseview-lean»

lean_lib Fuseview

/-- The system calls Lean's IO library does not make (`c/shim.c`). -/
target shim pkg : FilePath := do
  let oFile := pkg.buildDir / "c" / "shim.o"
  let srcJob ← inputTextFile <| pkg.dir / "c" / "shim.c"
  let weakArgs := #["-I", (← getLeanIncludeDir).toString]
  buildO oFile srcJob weakArgs #["-fPIC", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter"] "cc"

-- Linked dynamically: the toolchain's own glibc has no static archive. Its jail
-- (scripts/native_view.py) holds the loader and the libraries it names, and nothing else.
@[default_target]
lean_exe «fuseview-lean» where
  root := `Main
  moreLinkObjs := #[shim]

/-- The filter's cases from tests/test_fuseview.py, a decoded specification, the regex, and the
protocol answered over a small tree, request by request, with no kernel involved. -/
lean_exe «fuseview-tests» where
  root := `Tests
  moreLinkObjs := #[shim]
