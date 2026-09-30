import Place.Decode
import Place.Explain

/-!
`place-check`: a run's plans on stdin (`Place.Decode`), their verdicts on stdout, one line of JSON
-- `{"verdicts": [...]}`, each `{"certified": true}` or `{"certified": false, "reasons": [...]}`,
in the plans' order, or `{"error": ...}` for a document that is not one -- and an exit status to
match: 0 every plan certified, 1 some refused, 2 not a document. Reads nothing else and writes
nothing else.
-/
open Place Lean

partial def readAll (s : IO.FS.Stream) (acc : ByteArray := .empty) : IO ByteArray := do
  let chunk ← s.read 65536
  if chunk.isEmpty then return acc else readAll s (acc ++ chunk)

def say (j : Json) : IO Unit := IO.println j.compress

def verdict (pl : Plan) : Json :=
  if pl.check then Json.mkObj [("certified", true)]
  else Json.mkObj [("certified", false), ("reasons", Json.arr (pl.reasons.map Json.str).toArray)]

def main (_ : List String) : IO UInt32 := do
  let bytes ← readAll (← IO.getStdin)
  let some text := String.fromUTF8? bytes
    | say (Json.mkObj [("error", "the document is not UTF-8")]); return 2
  match decodePlans text with
  | .error e => say (Json.mkObj [("error", e)]); return 2
  | .ok plans =>
    say (Json.mkObj [("verdicts", Json.arr (plans.map verdict).toArray)])
    return if plans.all Plan.check then 0 else 1
