import Fuseview.Bytes

/-!
Just enough JSON for a view's specification (`viewdaemon.ViewSpec.document()`): objects, arrays,
strings with every escape, integers, `true`, `false`, `null`. Anything else is an error, and so is
a string that is not Unicode (a lone surrogate): a specification this cannot read is refused.
-/
namespace Fuseview

inductive Json where
  | null
  | bool (b : Bool)
  | num (n : Int)
  | str (s : String)
  | arr (xs : Array Json)
  | obj (kvs : Array (String × Json))
  deriving Inhabited

namespace Json

def get? (j : Json) (key : String) : Option Json :=
  match j with
  | .obj kvs => kvs.findSome? fun (k, v) => if k == key then some v else none
  | _ => none

def str? : Json → Option String
  | .str s => some s
  | _ => none

def arr? : Json → Option (Array Json)
  | .arr xs => some xs
  | _ => none

def num? : Json → Option Int
  | .num n => some n
  | _ => none

def isNull : Json → Bool
  | .null => true
  | _ => false

partial def ws (s : ByteArray) (i : Nat) : Nat :=
  if i < s.size then
    let c := s[i]!.toNat
    if c == 32 || c == 10 || c == 13 || c == 9 then ws s (i + 1) else i
  else i

def hexDigit (c : UInt8) : Option UInt32 :=
  let n := c.toNat
  if 48 ≤ n && n ≤ 57 then some (n - 48).toUInt32
  else if 97 ≤ n && n ≤ 102 then some (n - 87).toUInt32
  else if 65 ≤ n && n ≤ 70 then some (n - 55).toUInt32
  else none

def hex4 (s : ByteArray) (i : Nat) : Option UInt32 := do
  guard (i + 4 ≤ s.size)
  let a ← hexDigit s[i]!
  let b ← hexDigit s[i + 1]!
  let c ← hexDigit s[i + 2]!
  let d ← hexDigit s[i + 3]!
  return (a <<< 12) ||| (b <<< 8) ||| (c <<< 4) ||| d

/-- A continuation byte: six bits of *c*, from bit *shift*. -/
def cont (c : UInt32) (shift : UInt32) : UInt8 := ((0x80 : UInt32) ||| ((c >>> shift) &&& 0x3F)).toUInt8

def lead (mark : UInt32) (c : UInt32) (shift : UInt32) : UInt8 := (mark ||| (c >>> shift)).toUInt8

def pushUtf8 (b : ByteArray) (c : UInt32) : ByteArray :=
  if c < 0x80 then b.push c.toUInt8
  else if c < 0x800 then (b.push (lead 0xC0 c 6)).push (cont c 0)
  else if c < 0x10000 then ((b.push (lead 0xE0 c 12)).push (cont c 6)).push (cont c 0)
  else (((b.push (lead 0xF0 c 18)).push (cont c 12)).push (cont c 6)).push (cont c 0)

/-- The string whose body starts at *i* (past its opening quote), and the index past its end. -/
partial def string (s : ByteArray) (i : Nat) (acc : ByteArray) : Except String (String × Nat) :=
  if i ≥ s.size then .error "an unterminated string" else
  let c := s[i]!
  if c.toNat == 34 then
    match String.fromUTF8? acc with
    | some t => .ok (t, i + 1)
    | none => .error "a string that is not UTF-8"
  else if c.toNat != 92 then string s (i + 1) (acc.push c)
  else if i + 1 ≥ s.size then .error "an unterminated escape"
  else match s[i + 1]!.toNat with
    | 34 => string s (i + 2) (acc.push 34)
    | 92 => string s (i + 2) (acc.push 92)
    | 47 => string s (i + 2) (acc.push 47)
    | 98 => string s (i + 2) (acc.push 8)
    | 102 => string s (i + 2) (acc.push 12)
    | 110 => string s (i + 2) (acc.push 10)
    | 114 => string s (i + 2) (acc.push 13)
    | 116 => string s (i + 2) (acc.push 9)
    | 117 =>
      match hex4 s (i + 2) with
      | none => .error "a bad \\u escape"
      | some u =>
        if 0xDC00 ≤ u && u < 0xE000 then .error "a lone low surrogate"
        else if 0xD800 ≤ u && u < 0xDC00 then
          -- a high surrogate: its low half must follow
          if i + 12 > s.size || s[i + 6]!.toNat != 92 || s[i + 7]!.toNat != 117 then .error "a lone high surrogate"
          else match hex4 s (i + 8) with
            | some lo =>
              if 0xDC00 ≤ lo && lo < 0xE000 then
                string s (i + 12) (pushUtf8 acc ((0x10000 : UInt32) + ((u - 0xD800) <<< 10) + (lo - 0xDC00)))
              else .error "a lone high surrogate"
            | none => .error "a bad \\u escape"
        else string s (i + 6) (pushUtf8 acc u)
    | _ => .error "an unknown escape"

partial def digits (s : ByteArray) (i : Nat) (n : Nat) : Nat × Nat :=
  if i < s.size && 48 ≤ s[i]!.toNat && s[i]!.toNat ≤ 57 then digits s (i + 1) (n * 10 + (s[i]!.toNat - 48))
  else (n, i)

def literal (s : ByteArray) (i : Nat) (word : String) : Bool :=
  bytesEq (s.extract i (i + word.utf8ByteSize)) word.toUTF8

def byteAt (s : ByteArray) (i : Nat) : Nat := if i < s.size then s[i]!.toNat else 0

mutual
  partial def value (s : ByteArray) (i : Nat) : Except String (Json × Nat) := do
    let i := ws s i
    if i ≥ s.size then throw "the document ends early"
    let c := byteAt s i
    if c == 123 then return ← members s (ws s (i + 1)) #[]
    if c == 91 then return ← elements s (ws s (i + 1)) #[]
    if c == 34 then
      let (t, j) ← string s (i + 1) .empty
      return (.str t, j)
    if c == 45 then
      let (n, j) := digits s (i + 1) 0
      if j == i + 1 then throw "a bad number"
      return (.num (-(n : Int)), j)
    if 48 ≤ c && c ≤ 57 then
      let (n, j) := digits s i 0
      let d := byteAt s j
      if d == 46 || d == 101 || d == 69 then throw "a number that is not an integer"
      return (.num n, j)
    if literal s i "true" then return (.bool true, i + 4)
    if literal s i "false" then return (.bool false, i + 5)
    if literal s i "null" then return (.null, i + 4)
    throw s!"an unexpected byte at {i}"

  partial def elements (s : ByteArray) (i : Nat) (acc : Array Json) : Except String (Json × Nat) := do
    if byteAt s i == 93 && acc.isEmpty then return (.arr acc, i + 1)
    let (v, j) ← value s i
    let j := ws s j
    if byteAt s j == 44 then return ← elements s (ws s (j + 1)) (acc.push v)
    if byteAt s j == 93 then return (.arr (acc.push v), j + 1)
    throw s!"a bad array at {j}"

  partial def members (s : ByteArray) (i : Nat) (acc : Array (String × Json)) : Except String (Json × Nat) := do
    if byteAt s i == 125 && acc.isEmpty then return (.obj acc, i + 1)
    if byteAt s i != 34 then throw s!"a bad key at {i}"
    let (k, j) ← string s (i + 1) .empty
    let j := ws s j
    if byteAt s j != 58 then throw s!"a missing colon at {j}"
    let (v, j) ← value s (j + 1)
    let j := ws s j
    if byteAt s j == 44 then return ← members s (ws s (j + 1)) (acc.push (k, v))
    if byteAt s j == 125 then return (.obj (acc.push (k, v)), j + 1)
    throw s!"a bad object at {j}"
end

def parse (text : String) : Except String Json := do
  let s := text.toUTF8
  let (v, i) ← value s 0
  if ws s i != s.size then .error "text after the document" else .ok v

end Json
end Fuseview
