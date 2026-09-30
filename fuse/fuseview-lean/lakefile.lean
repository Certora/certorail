import Lake
open Lake DSL System

package «fuseview-lean»

/-- The regex engine a `<...>` component is matched with: formally verified (both its matchers are
proven sound and complete against its semantics), and nothing of its own to fetch. -/
require Regex from git "https://github.com/pandaman64/lean-regex" @ "v4.32.0" / "regex"

/-- The placement checker's model of what grants mean (`Place.Meaning`): the daemon decides every
name by the same `stateFrom`, `covers`, `after` and `movable` the checker's proofs are about. -/
require place from "../../proofs/place"

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
