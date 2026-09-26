import Lean.Data.Json
import Fuseview.Filter

/-!
A view daemon's specification (`viewdaemon.ViewSpec.document()`, format 2) as the filter's layers,
read with Lean's own JSON. A regex that does not compile here refuses the whole specification: a
pattern read differently is a grant or a restriction read differently.
-/
namespace Fuseview

open Lean (Json)

structure Spec where
  /-- the served directory, as the document spells it: where the kernel reports it to be -/
  directory : String
  layers : Array Layer

namespace Spec

def need {α : Type} (what : String) : Option α → Except String α
  | some a => .ok a
  | none => .error what

-- the document's pieces, as options: an absent key and a value of another kind are alike
def field (j : Json) (key : String) : Option Json := (j.getObjVal? key).toOption
def asStr (j : Json) : Option String := j.getStr?.toOption
def asArr (j : Json) : Option (Array Json) := j.getArr?.toOption
def asInt (j : Json) : Option Int := j.getInt?.toOption

def isNull : Json → Bool
  | .null => true
  | _ => false

def path (j : Json) : Except String Path := do
  return splitPath (← need "a path that is not a string" (asStr j))

def component (j : Json) : Except String Component := do
  if let some name := asStr j then return .named (Name.ofString name)
  if (field j "any").isSome then return .any
  if let some names := (field j "one_of").bind asArr then
    return .oneOf (← names.mapM fun n => need "a name that is not a string" ((asStr n).map Name.ofString))
  if let some pattern := (field j "regex").bind asStr then
    match NamePattern.compile pattern with
    | .ok re => return .matching re
    | .error e => throw s!"the regex {pattern} does not compile here: {e}"
  throw "a component of no known kind"

def componentList (j : Json) : Except String (Array Component) := do
  (← need "not a list of components" (asArr j)).mapM component

def location (j : Json) : Except String Location := do
  if let some cs := field j "path" then return .path (← componentList cs)
  let pre ← componentList (← need "a location of no known kind" (field j "prefix"))
  match field j "leaf" with
  | none => return .splat pre none
  | some l => if isNull l then return .splat pre none else return .splat pre (some (← component l))

def region (j : Json) : Except String Region := do
  if let some p := field j "subtree" then return .subtree (← path p)
  if let some p := field j "exactly" then return .exactly (← path p)
  match field j "pattern", field j "anchor" with
  | some loc, some anchor => return .pattern (← location loc) (← path anchor)
  | _, _ => throw "a region of no known kind"

def says (j : Json) : Except String Says :=
  match (field j "grant").bind asStr, (field j "restrict").bind asStr with
  | some "read-only", none => .ok (.grant .readOnly)
  | some "writable", none => .ok (.grant .writable)
  | none, some "no-write" => .ok (.restrict .noWrite)
  | none, some "hidden" => .ok (.restrict .hidden)
  | _, _ => .error "a layer that says nothing known"

def layer (j : Json) : Except String Layer := do
  let r ← region (← need "a layer with no region" (field j "region"))
  return { region := r, says := ← says j }

def parse (text : String) : Except String Spec := do
  let body ← Json.parse text
  if (field body "format").bind asInt != some 2 then throw "not a format-2 view specification"
  let directory ← need "no directory" ((field body "directory").bind asStr)
  let layers ← (← need "no list of layers" ((field body "layers").bind asArr)).mapM layer
  return { directory := directory, layers := layers }

def filter (s : Spec) : Filter := { directory := splitPath s.directory, layers := s.layers }

end Spec
end Fuseview
