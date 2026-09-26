import Regex
import Fuseview.Bytes

/-!
A `<...>` component's regex, as a policy spells it -- Python's `re` syntax, fullmatched against one
name -- matched by lean-regex (`Regex`), whose matchers are proven sound and complete against its
semantics.

The syntax is Python's, so it is parsed here, for the part of it a name pattern uses: literals and
escapes, `.`, sets with ranges and negation, `\d \w \s` and their negations, groups (plain,
`(?:...)`, `(?P<name>...)`), alternation, `* + ? {m} {m,} {,n} {m,n}` (lazy or not: the language is
the same), `^ $ \A \Z`. Anything else -- lookarounds, backreferences, flags, atomic groups, `\b`,
possessive repeats -- does not parse, and a specification holding it is refused: a pattern read
differently would be a grant or a hide read differently. What parses is printed again in
lean-regex's syntax, with nothing left to its reading: every character spelled `\u{…}`, Python's
`.` as `[^\n]`, each repeat with explicit bounds, the whole anchored at both ends of the input.

Where the two engines' meanings part, a name has no answer (`none`), and the filter fails closed:
- lean-regex's `\d \w \s` are ASCII, and its `\s` leaves out the vertical tab; Python's are Unicode.
  A pattern holding one (or a negation) has no answer on a name with a character outside printable
  ASCII.
- Python's `$` also matches just before a final newline. No pattern has an answer on a name holding
  a newline.
A name that is not UTF-8 has none either.
-/
namespace Fuseview

structure NamePattern where
  compiled : Regex
  /-- does it hold `\d \w \s` or a negation, which mean more than ASCII in Python? -/
  classes : Bool

namespace NamePattern

inductive Item where
  | ch (c : Char)
  | range (lo hi : Char)
  | digit (neg : Bool)
  | word (neg : Bool)
  | space (neg : Bool)
  deriving Inhabited

inductive Node where
  | ch (c : Char)
  | any
  | set (neg : Bool) (items : Array Item)
  | seq (ns : Array Node)
  | alt (ns : Array Node)
  | rep (n : Node) (lo : Nat) (hi : Option Nat)
  | atStart
  | atEnd      -- `$`: the end, or just before a final newline
  | atEndAbs   -- `\Z`: the end
  deriving Inhabited

-- parsing Python's syntax ---------------------------------------------------------------------------

structure P where
  cs : Array Char
  classes : Bool := false

abbrev ParseM := StateT P (Except String)

def peekAt (cs : Array Char) (i : Nat) : Option Char := if i < cs.size then some cs[i]! else none

def isHex (c : Char) : Bool := c.isDigit || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')

def hexVal (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat
  else if 'a' ≤ c && c ≤ 'f' then c.toNat - 'a'.toNat + 10
  else c.toNat - 'A'.toNat + 10

/-- *n* hex digits at *i*, as a character. -/
def hexChar (cs : Array Char) (i n : Nat) : Except String Char := do
  if i + n > cs.size then throw "a short hex escape"
  let mut v := 0
  for k in List.range n do
    let c := cs[i + k]!
    if !isHex c then throw "a bad hex escape"
    v := v * 16 + hexVal c
  if v > 0x10FFFF || (0xD800 ≤ v && v < 0xE000) then throw "an escape that is no character"
  return Char.ofNat v

/-- An escape's meaning -- a character or a class -- at *i* (past the backslash), and the index
past it. *inSet*: inside `[...]`, where `\b` is a backspace. -/
def escape (cs : Array Char) (i : Nat) (inSet : Bool) : Except String (Item × Nat) := do
  let some c := peekAt cs i | throw "a pattern ending in a backslash"
  match c with
  | 'd' => return (.digit false, i + 1)
  | 'D' => return (.digit true, i + 1)
  | 'w' => return (.word false, i + 1)
  | 'W' => return (.word true, i + 1)
  | 's' => return (.space false, i + 1)
  | 'S' => return (.space true, i + 1)
  | 'n' => return (.ch '\n', i + 1)
  | 't' => return (.ch '\t', i + 1)
  | 'r' => return (.ch '\r', i + 1)
  | 'f' => return (.ch (Char.ofNat 12), i + 1)
  | 'v' => return (.ch (Char.ofNat 11), i + 1)
  | 'a' => return (.ch (Char.ofNat 7), i + 1)
  | 'b' => if inSet then return (.ch (Char.ofNat 8), i + 1) else throw "\\b is not supported"
  | 'x' => return (.ch (← hexChar cs (i + 1) 2), i + 3)
  | 'u' => return (.ch (← hexChar cs (i + 1) 4), i + 5)
  | 'U' => return (.ch (← hexChar cs (i + 1) 8), i + 9)
  | c =>
    if c.isAlphanum then throw s!"the escape \\{c} is not supported"
    else return (.ch c, i + 1)

def itemIsClass : Item → Bool
  | .digit _ | .word _ | .space _ => true
  | _ => false

/-- The set whose body starts at *i* (past `[`), and the index past its `]`. -/
partial def setBody (cs : Array Char) (i : Nat) (items : Array Item) (first : Bool) : Except String (Array Item × Nat) := do
  let some c := peekAt cs i | throw "an unterminated set"
  if c == ']' && !first then return (items, i + 1)
  let (item, j) ← if c == '\\' then escape cs (i + 1) true else pure (.ch c, i + 1)
  -- a range, unless the '-' is the set's last character
  match item, peekAt cs j, peekAt cs (j + 1) with
  | .ch lo, some '-', some d =>
    if d == ']' then setBody cs j (items.push item) false
    else
      let (hiItem, k) ← if d == '\\' then escape cs (j + 2) true else pure (.ch d, j + 2)
      match hiItem with
      | .ch hi =>
        if hi < lo then throw "a bad range"
        setBody cs k (items.push (.range lo hi)) false
      | _ => throw "a range to a class"
  | _, _, _ => setBody cs j (items.push item) false

/-- `{m}`, `{m,}`, `{,n}`, `{m,n}` at *i* (on the `{`): the bounds and the index past `}`; none if
it is not a quantifier, and the `{` is a literal. -/
partial def bound (cs : Array Char) (i : Nat) : Option (Nat × Option Nat × Nat) := do
  let rec num (j : Nat) (n : Nat) (any : Bool) : Nat × Nat × Bool :=
    match peekAt cs j with
    | some c => if c.isDigit then num (j + 1) (n * 10 + (c.toNat - '0'.toNat)) true else (n, j, any)
    | none => (n, j, any)
  let (lo, j, loAny) := num (i + 1) 0 false
  match peekAt cs j with
  | some '}' => if loAny then some (lo, some lo, j + 1) else none
  | some ',' =>
    let (hi, k, hiAny) := num (j + 1) 0 false
    if peekAt cs k != some '}' then none
    else if !loAny && !hiAny then none
    else some ((if loAny then lo else 0), (if hiAny then some hi else none), k + 1)
  | _ => none

partial def groupName (cs : Array Char) (k : Nat) : Option Nat :=
  match peekAt cs k with
  | some '>' => some (k + 1)
  | some _ => groupName cs (k + 1)
  | none => none

/-- Where a group's body starts, *i* being on its `(`. -/
def groupStart (cs : Array Char) (i : Nat) : Except String Nat := do
  if peekAt cs (i + 1) != some '?' then return i + 1
  match peekAt cs (i + 2) with
  | some ':' => return i + 3
  | some 'P' =>
    if peekAt cs (i + 3) != some '<' then throw "backreferences are not supported"
    match groupName cs (i + 4) with
    | some k => return k
    | none => throw "an unterminated group name"
  | _ => throw "lookarounds, flags and other (?...) groups are not supported"

mutual
  /-- Alternatives separated by `|`, up to a `)` or the end. -/
  partial def alts (i : Nat) : ParseM (Node × Nat) := do
    let (first, j) ← sequence i #[]
    let mut branches := #[first]
    let mut j := j
    while peekAt (← get).cs j == some '|' do
      let (b, k) ← sequence (j + 1) #[]
      branches := branches.push b
      j := k
    return (if branches.size == 1 then branches[0]! else .alt branches, j)

  partial def sequence (i : Nat) (acc : Array Node) : ParseM (Node × Nat) := do
    let cs := (← get).cs
    match peekAt cs i with
    | none | some '|' | some ')' => return (.seq acc, i)
    | some _ =>
      let (atom, j) ← atomAt i
      let (node, k) ← quantified atom j
      sequence k (acc.push node)

  partial def quantified (atom : Node) (i : Nat) : ParseM (Node × Nat) := do
    let cs := (← get).cs
    let mut node := atom
    let mut j := i
    match peekAt cs i with
    | some '*' =>
      node := .rep atom 0 none
      j := i + 1
    | some '+' =>
      node := .rep atom 1 none
      j := i + 1
    | some '?' =>
      node := .rep atom 0 (some 1)
      j := i + 1
    | some '{' =>
      if let some (lo, hi, k) := bound cs i then
        if hi.any (· < lo) then throw "a repeat whose bounds are reversed"
        node := .rep atom lo hi
        j := k
    | _ => pure ()
    if j == i then return (node, j)
    match peekAt cs j with
    | some '?' => return (node, j + 1)  -- lazy: the same language
    | some '+' => throw "possessive repeats are not supported"
    | some '*' | some '{' => throw "a repeat of a repeat"
    | _ => return (node, j)

  partial def atomAt (i : Nat) : ParseM (Node × Nat) := do
    let cs := (← get).cs
    let some c := peekAt cs i | throw "a pattern ending early"
    match c with
    | '.' => return (.any, i + 1)
    | '^' => return (.atStart, i + 1)
    | '$' => return (.atEnd, i + 1)
    | '*' | '+' | '?' => throw "nothing to repeat"
    | '[' =>
      let (neg, j) := if peekAt cs (i + 1) == some '^' then (true, i + 2) else (false, i + 1)
      let (items, k) ← setBody cs j #[] true
      if items.any itemIsClass then modify fun p => { p with classes := true }
      return (.set neg items, k)
    | '(' =>
      let j ← groupStart cs i
      let (inner, k) ← alts j
      if peekAt cs k != some ')' then throw "an unterminated group"
      return (inner, k + 1)
    | ')' => throw "an unbalanced parenthesis"
    | '\\' =>
      match peekAt cs (i + 1) with
      | some 'A' => return (.atStart, i + 2)
      | some 'Z' => return (.atEndAbs, i + 2)
      | some d =>
        if d.isDigit then throw "backreferences and octal escapes are not supported"
        let (item, j) ← escape cs (i + 1) false
        match item with
        | .ch ch => return (.ch ch, j)
        | cls =>
          modify fun p => { p with classes := true }
          return (.set false #[cls], j)
      | none => throw "a pattern ending in a backslash"
    | c => return (.ch c, i + 1)
end

-- printing lean-regex's syntax ----------------------------------------------------------------------

/-- *c*, spelled so lean-regex reads it as itself and nothing else. -/
def lit (c : Char) : String :=
  if c.isAlphanum then c.toString else "\\u{" ++ String.ofList (Nat.toDigits 16 c.toNat) ++ "}"

def renderItem : Item → String
  | .ch c => lit c
  | .range lo hi => lit lo ++ "-" ++ lit hi
  | .digit neg => if neg then "\\D" else "\\d"
  | .word neg => if neg then "\\W" else "\\w"
  | .space neg => if neg then "\\S" else "\\s"

def bounds (lo : Nat) : Option Nat → String
  | none => "{" ++ toString lo ++ ",}"
  | some hi => "{" ++ toString lo ++ "," ++ toString hi ++ "}"

/-- *n* in lean-regex's syntax, each piece self-delimiting, so concatenation needs no care. -/
partial def render : Node → String
  | .ch c => lit c
  | .any => "[^\\u{a}]"  -- Python's `.`: anything but a newline
  | .set neg items => "[" ++ (if neg then "^" else "") ++ String.join (items.toList.map renderItem) ++ "]"
  | .seq ns => if ns.isEmpty then "(?:\\u{0}){0,0}" else String.join (ns.toList.map render)
  | .alt ns => "(?:" ++ "|".intercalate (ns.toList.map render) ++ ")"
  | .rep n lo hi => "(?:" ++ render n ++ ")" ++ bounds lo hi
  | .atStart => "^"
  | .atEnd | .atEndAbs => "$"  -- the end of the input (a name with a newline never gets here)

-- the pattern ---------------------------------------------------------------------------------------

/-- *pattern*, as Python's `re` would read it, compiled to be fullmatched. -/
def compile (pattern : String) : Except String NamePattern := do
  let cs := pattern.toList.toArray
  let ((node, i), parsed) ← (alts 0).run { cs := cs }
  if i != cs.size then throw "an unbalanced parenthesis"
  match Regex.parse ("^(?:" ++ render node ++ ")$") with
  | .ok re => return { compiled := re, classes := parsed.classes }
  | .error _ => throw "lean-regex does not read it"

/-- Does the whole of *name* match? None: the two engines might answer differently (see above). -/
def fullmatch (p : NamePattern) (name : Name) : Option Bool := do
  let text ← String.fromUTF8? name.bytes
  if text.any (· == '\n') then failure
  if p.classes && text.any (fun c => c.toNat < 32 || c.toNat ≥ 127) then failure
  return p.compiled.test text

end NamePattern
end Fuseview
