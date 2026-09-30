import Lean.Data.Json
import Place.Plan

/-!
The checker's input (`sandbox/certify.py`, format 1), read with Lean's own JSON. Anything it does
not know refuses the whole document: a plan read differently is a plan certified differently.

Paths are absolute strings, `/` for the root; a view's `rel` is relative, `.` for its directory. No
path may name `.` or `..`: the model's components are names. A mount's source is `"own"`,
`{"alias": PATH}` or `{"view": INDEX, "rel": REL}`.
-/
namespace Place
namespace Decode

open Lean (Json)

def need {α : Type} (what : String) : Option α → Except String α
  | some a => .ok a
  | none => .error what

-- the document's pieces, as options: an absent key and a value of another kind are alike
def field (j : Json) (key : String) : Option Json := (j.getObjVal? key).toOption
def asStr (j : Json) : Option String := j.getStr?.toOption
def asArr (j : Json) : Option (Array Json) := j.getArr?.toOption
def asNat (j : Json) : Option Nat := j.getNat?.toOption

def components (s : String) : Except String Path := do
  let names := (s.splitOn "/").filter (· ≠ "")
  if names.any (fun n => n == "." || n == "..") then throw s!"{s}: names . or .."
  return names

def path (j : Json) : Except String Path := do
  let s ← need "a path that is not a string" (asStr j)
  unless s.startsWith "/" do throw s!"{s}: not an absolute path"
  components s

def rel (j : Json) : Except String Path := do
  let s ← need "a relative path that is not a string" (asStr j)
  if s == "." then return []
  if s.startsWith "/" then throw s!"{s}: not a relative path"
  components s

def list {α : Type} (what : String) (f : Json → Except String α) (j : Json) : Except String (List α) := do
  (← need s!"not a list of {what}" (asArr j)).toList.mapM f

def pair {α β : Type} (f : Json → Except String α) (g : Json → Except String β) (j : Json) :
    Except String (α × β) := do
  match (← need "not a pair" (asArr j)).toList with
  | [a, b] => return (← f a, ← g b)
  | _ => throw "not a pair"

def region (j : Json) : Except String Region := do
  if let some p := field j "subtree" then return .subtree (← path p)
  if let some p := field j "exactly" then return .exactly (← path p)
  if let some key := (field j "pattern").bind asStr then
    return .pattern key (← list "tops" path (← need "a pattern with no tops" (field j "tops")))
  throw "a region of no known kind"

def says (j : Json) : Except String Says :=
  match (field j "grant").bind asStr, (field j "restrict").bind asStr with
  | some "read-only", none => .ok (.grant .readOnly)
  | some "writable", none => .ok (.grant .writable)
  | none, some "no-write" => .ok (.restrict .noWrite)
  | none, some "hidden" => .ok (.restrict .hidden)
  | _, _ => .error "a layer that says nothing known"

def layer (j : Json) : Except String Layer := do
  return { region := ← region (← need "a layer with no region" (field j "region")), says := ← says j }

def state (j : Json) : Except String State :=
  match asStr j with
  | some "absent" => .ok .absent
  | some "read-only" => .ok .readOnly
  | some "writable" => .ok .writable
  | some "hidden" => .ok .hidden
  | _ => .error "a state of no known kind"

def source (j : Json) : Except String Source := do
  match asStr j with
  | some "own" => return .own
  | some _ => throw "a source of no known kind"
  | none =>
    if let some t := field j "alias" then return .alias (← path t)
    let v ← need "a source of no known kind" ((field j "view").bind asNat)
    return .view v (← rel (← need "a view source with no rel" (field j "rel")))

def mount (j : Json) : Except String Mount := do
  return {
    path := ← path (← need "a mount with no path" (field j "path"))
    state := ← state (← need "a mount with no state" (field j "state"))
    source := ← source (← need "a mount with no source" (field j "source")) }

def view (j : Json) : Except String View := do
  return {
    dir := ← path (← need "a view with no directory" (field j "directory"))
    layers := ← list "layers" layer (← need "a view with no layers" (field j "layers")) }

def base (j : Json) : Except String Base :=
  match asStr j with
  | some "empty" => .ok .empty
  | some "host-read-only" => .ok (.host false)
  | some "host-writable" => .ok (.host true)
  | _ => .error "a base of no known kind"

def lifetime (j : Json) : Except String Lifetime :=
  match asStr j with
  | some "exec" => .ok .exec
  | some "run" => .ok .run
  | _ => .error "a lifetime of no known kind"

def kind (j : Json) : Except String Kind :=
  match asStr j with
  | some "file" => .ok .file
  | some "directory" => .ok .directory
  | some "symlink" => .ok .symlink
  | some "missing" => .ok .missing
  | _ => .error "a kind of no known kind"

def stability (j : Json) : Except String Stability := do
  let paths (key : String) : Except String (List Path) := do
    list "paths" path (← need s!"a stability with no {key}" (field j key))
  return {
    names := ← paths "names", childrenOf := ← paths "children-of", kept := ← paths "kept",
    subtrees := ← paths "subtrees" }

def facts (j : Json) : Except String Facts := do
  return {
    kinds := ← list "kinds" (pair path kind) (← need "facts with no kinds" (field j "kinds"))
    resolutions := ← list "resolutions" (pair path path)
      (← need "facts with no resolutions" (field j "resolutions")) }

end Decode

open Decode in
def Plan.decode (body : Lean.Json) : Except String Plan := do
  let get (key : String) : Except String Lean.Json := need s!"a plan with no {key}" (field body key)
  return {
    base := ← Decode.base (← get "base")
    layers := ← list "layers" layer (← get "layers")
    views := ← list "views" view (← get "views")
    mounts := ← list "mounts" mount (← get "mounts")
    lifetime := ← Decode.lifetime (← get "lifetime")
    stability := ← Decode.stability (← get "stability")
    facts := ← Decode.facts (← get "facts") }

open Decode in
/-- A document: `{"format": 1, "plans": [...]}`, one run's plans, certified together. -/
def decodePlans (text : String) : Except String (List Plan) := do
  let body ← Lean.Json.parse text
  if (field body "format").bind asNat != some 1 then throw "not a format-1 document"
  list "plans" Plan.decode (← need "a document with no plans" (field body "plans"))

end Place
