import Fuseview.Bytes

/-!
A regex as a policy's `<...>` component spells it, fullmatched against one name as `re.fullmatch`
would: Python's syntax, for the part of it a name pattern uses -- literals and escapes, `.`, sets
with ranges and negation, `\d \w \s` and their negations, groups (plain, `(?:...)`,
`(?P<name>...)`), alternation, `* + ? {m} {m,} {,n} {m,n}` (lazy or not: the language is the
same), `^ $ \A \Z`. Anything else -- lookarounds, backreferences, flags, atomic groups, `\b` --
does not compile, and a specification holding it is refused: a pattern read differently would be a
grant or a hide read differently.

`\d \w \s` are ASCII here and Unicode in Python, so on a name with a non-ASCII character a pattern
holding one has no answer (`none`), and the filter fails closed. So has a name that is not UTF-8.

Matching is a Pike VM over the compiled program: every thread advances in step, so a match costs
the name's length times the program's, whatever the pattern.
-/
namespace Fuseview.Regex

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

inductive Inst where
  | ch (c : Char)
  | any
  | set (neg : Bool) (items : Array Item)
  | split (x y : Nat)
  | jmp (x : Nat)
  | atStart
  | atEnd
  | atEndAbs
  | done
  deriving Inhabited

structure Regex where
  prog : Array Inst
  /-- does it hold `\d \w \s` or a negation, whose meaning differs from Python's past ASCII? -/
  unicodeClasses : Bool
  deriving Inhabited

-- parsing ------------------------------------------------------------------------------------------

structure P where
  cs : Array Char
  unicode : Bool := false

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
      if items.any itemIsClass then modify fun p => { p with unicode := true }
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
          modify fun p => { p with unicode := true }
          return (.set false #[cls], j)
      | none => throw "a pattern ending in a backslash"
    | c => return (.ch c, i + 1)
end

-- compiling ----------------------------------------------------------------------------------------

abbrev CompileM := StateT (Array Inst) (Except String)

def emit (i : Inst) : CompileM Nat := modifyGet fun prog => (prog.size, prog.push i)
def here : CompileM Nat := return (← get).size
def patch (at_ : Nat) (i : Inst) : CompileM Unit := modify fun prog => prog.set! at_ i

def limit : Nat := 20000

mutual
  partial def emitNode : Node → CompileM Unit
    | .ch c => discard <| emit (.ch c)
    | .any => discard <| emit .any
    | .set neg items => discard <| emit (.set neg items)
    | .atStart => discard <| emit .atStart
    | .atEnd => discard <| emit .atEnd
    | .atEndAbs => discard <| emit .atEndAbs
    | .seq ns => ns.forM emitNode
    | .alt ns => emitAlt ns 0
    | .rep n lo hi => do
      for _ in List.range lo do
        emitNode n
        if (← here) > limit then throw "a pattern too large"
      match hi with
      | none =>
        let sp ← emit (.split 0 0)
        emitNode n
        discard <| emit (.jmp sp)
        patch sp (.split (sp + 1) (← here))
      | some h =>
        let mut splits := #[]
        for _ in List.range (h - lo) do
          splits := splits.push (← emit (.split 0 0))
          emitNode n
          if (← here) > limit then throw "a pattern too large"
        let e ← here
        for sp in splits do
          patch sp (.split (sp + 1) e)

  partial def emitAlt (ns : Array Node) (k : Nat) : CompileM Unit := do
    if k + 1 ≥ ns.size then
      if k < ns.size then emitNode ns[k]!
      return
    let sp ← emit (.split 0 0)
    emitNode ns[k]!
    let j ← emit (.jmp 0)
    patch sp (.split (sp + 1) (← here))
    emitAlt ns (k + 1)
    patch j (.jmp (← here))
end

def Regex.compile (pattern : String) : Except String Regex := do
  let cs := pattern.toList.toArray
  let ((node, i), parsed) ← (alts 0).run { cs := cs }
  if i != cs.size then throw "an unbalanced parenthesis"
  let ((), prog) ← (do emitNode node; discard <| emit .done).run #[]
  if prog.size > limit then throw "a pattern too large"
  return { prog := prog, unicodeClasses := parsed.unicode }

-- matching -----------------------------------------------------------------------------------------

def Item.accepts (c : Char) : Item → Bool
  | .ch d => c == d
  | .range lo hi => lo ≤ c && c ≤ hi
  | .digit neg => c.isDigit != neg
  | .word neg => (c.isAlphanum || c == '_') != neg
  | .space neg =>
    (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == Char.ofNat 11 || c == Char.ofNat 12) != neg

/-- Every instruction reachable from *pc* without consuming a character, at *pos*: the consuming
ones (and `done`) added to *list*, each once. -/
partial def closure (prog : Array Inst) (s : Array Char) (pos pc : Nat) (seen : Array Bool) (list : Array Nat) :
    Array Bool × Array Nat :=
  if seen[pc]! then (seen, list) else
  let seen := seen.set! pc true
  match prog[pc]! with
  | .jmp x => closure prog s pos x seen list
  | .split x y =>
    let (seen, list) := closure prog s pos x seen list
    closure prog s pos y seen list
  | .atStart => if pos == 0 then closure prog s pos (pc + 1) seen list else (seen, list)
  | .atEnd =>
    if pos == s.size || (pos + 1 == s.size && s[pos]! == '\n') then closure prog s pos (pc + 1) seen list
    else (seen, list)
  | .atEndAbs => if pos == s.size then closure prog s pos (pc + 1) seen list else (seen, list)
  | _ => (seen, list.push pc)

def steps (prog : Array Inst) (s : Array Char) (c : Char) (pos : Nat) (current : Array Nat) : Array Nat := Id.run do
  let mut seen := Array.replicate prog.size false
  let mut next := #[]
  for pc in current do
    let advances := match prog[pc]! with
      | .ch d => c == d
      | .any => c != '\n'
      | .set neg items => items.any (·.accepts c) != neg
      | _ => false
    if advances then
      let r := closure prog s (pos + 1) (pc + 1) seen next
      seen := r.1
      next := r.2
  return next

partial def runFrom (prog : Array Inst) (s : Array Char) (pos : Nat) (current : Array Nat) : Bool :=
  if current.isEmpty then false
  else if pos == s.size then current.any fun pc => match prog[pc]! with | .done => true | _ => false
  else runFrom prog s (pos + 1) (steps prog s s[pos]! pos current)

/-- Does the whole of *name* match? None: this cannot say as Python would (see above). -/
def Regex.fullmatch (r : Regex) (name : Name) : Option Bool := do
  let text ← String.fromUTF8? name.bytes
  let s := text.toList.toArray
  if r.unicodeClasses && s.any (·.toNat ≥ 128) then failure
  let (_, start) := closure r.prog s 0 0 (Array.replicate r.prog.size false) #[]
  return runFrom r.prog s 0 start

end Fuseview.Regex
