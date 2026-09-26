import Fuseview.Json
import Fuseview.Filter

/-!
A view daemon's specification (`viewdaemon.ViewSpec.document()`, format 2) as the filter's layers.
A regex that does not compile here refuses the whole specification: a pattern read differently is
a grant or a restriction read differently.
-/
namespace Fuseview

structure Spec where
  /-- the served directory, as the document spells it: where the kernel reports it to be -/
  directory : String
  layers : Array Layer

namespace Spec

def need {α : Type} (what : String) : Option α → Except String α
  | some a => .ok a
  | none => .error what

def path (j : Json) : Except String Path := do
  return splitPath (← need "a path that is not a string" j.str?)

def component (j : Json) : Except String Component := do
  if let some name := j.str? then return .named (Name.ofString name)
  if (j.get? "any").isSome then return .any
  if let some names := (j.get? "one_of").bind Json.arr? then
    return .oneOf (← names.mapM fun n => need "a name that is not a string" (n.str?.map Name.ofString))
  if let some pattern := (j.get? "regex").bind Json.str? then
    match Regex.Regex.compile pattern with
    | .ok re => return .matching re
    | .error e => throw s!"the regex {pattern} does not compile here: {e}"
  throw "a component of no known kind"

def componentList (j : Json) : Except String (Array Component) := do
  (← need "not a list of components" j.arr?).mapM component

def location (j : Json) : Except String Location := do
  if let some cs := j.get? "path" then return .path (← componentList cs)
  let pre ← componentList (← need "a location of no known kind" (j.get? "prefix"))
  match j.get? "leaf" with
  | none => return .splat pre none
  | some l => if l.isNull then return .splat pre none else return .splat pre (some (← component l))

def region (j : Json) : Except String Region := do
  if let some p := j.get? "subtree" then return .subtree (← path p)
  if let some p := j.get? "exactly" then return .exactly (← path p)
  match j.get? "pattern", j.get? "anchor" with
  | some loc, some anchor => return .pattern (← location loc) (← path anchor)
  | _, _ => throw "a region of no known kind"

def says (j : Json) : Except String Says :=
  match (j.get? "grant").bind Json.str?, (j.get? "restrict").bind Json.str? with
  | some "read-only", none => .ok (.grant .readOnly)
  | some "writable", none => .ok (.grant .writable)
  | none, some "no-write" => .ok (.restrict .noWrite)
  | none, some "hidden" => .ok (.restrict .hidden)
  | _, _ => .error "a layer that says nothing known"

def layer (j : Json) : Except String Layer := do
  let r ← region (← need "a layer with no region" (j.get? "region"))
  return { region := r, says := ← says j }

def parse (text : String) : Except String Spec := do
  let body ← Json.parse text
  if (body.get? "format").bind Json.num? != some 2 then throw "not a format-2 view specification"
  let directory ← need "no directory" ((body.get? "directory").bind Json.str?)
  let layers ← (← need "no list of layers" ((body.get? "layers").bind Json.arr?)).mapM layer
  return { directory := directory, layers := layers }

def filter (s : Spec) : Filter := { directory := splitPath s.directory, layers := s.layers }

end Spec
end Fuseview
