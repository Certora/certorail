/-!
# `git-rev`, verified

A Lean 4 port of `rulesets/checkers/git-rev`: the argument is a revision, range or object
spelling for a READING git command. Establishes `git.rev` and `not-option`.

The Boolean functions below are the spec — each mirrors one clause of the Python checker
and is named for it. The theorems at the bottom are the tin:

* `check_no_option`    — an admitted string never begins with `-`
* `check_no_forbidden` — an admitted string carries no space, control, glob or escape character
* `check_nonempty`     — the empty string is refused

A revision that is exactly one bare `@{...}` form (`@{u}`, `@{upstream}`, `@{push}`,
`@{-N}`) is admitted, per the docstring; a concatenation of forms is not. (The Python
refused the bare forms until 2026-09-11: stripping left an empty body.)
-/

namespace GitRev

/-- `[A-Za-z0-9]` — the Python's regex classes are ASCII, so this is too. -/
def isAlnum (c : Char) : Bool :=
  ('A' ≤ c && c ≤ 'Z') || ('a' ≤ c && c ≤ 'z') || ('0' ≤ c && c ≤ '9')

def isDigit (c : Char) : Bool := '0' ≤ c && c ≤ '9'

/-- C0 control characters and DEL. -/
def isCtl (c : Char) : Bool := c.toNat < 0x20 || c.toNat == 0x7F

/-- Glob and escape metacharacters, refused outright. -/
def isGlob (c : Char) : Bool := c == '*' || c == '?' || c == '[' || c == '\\'

/-- Whitespace, control, glob. (The Python uses `str.isspace`, which also covers Unicode
spaces; those fail `bodyOk`'s ASCII classes here instead — the verdict is the same.) -/
def isForbidden (c : Char) : Bool := c == ' ' || isCtl c || isGlob c

/-- First character of the stripped body: `[A-Za-z0-9_@]`. -/
def firstOk (c : Char) : Bool := isAlnum c || c == '_' || c == '@'

/-- Every later character: `[A-Za-z0-9_./^~:-]`. -/
def restOk (c : Char) : Bool :=
  isAlnum c || c == '_' || c == '.' || c == '/' || c == '^' ||
    c == '~' || c == ':' || c == '-'

/-- After `[0-9]*` comes `}`: the number of characters consumed, including the `}`. -/
def bracePos : List Char → Option Nat
  | '}' :: _ => some 1
  | c :: rest => if isDigit c then (bracePos rest).map (· + 1) else none
  | [] => none

/-- The characters after an `@{`: if they begin with a form body the Python's `_AT` admits —
`u}`, `upstream}`, `push}` or `-?[0-9]+}` — the length of that body including the `}`. -/
def atBody : List Char → Option Nat
  | 'u' :: 'p' :: 's' :: 't' :: 'r' :: 'e' :: 'a' :: 'm' :: '}' :: _ => some 9
  | 'u' :: '}' :: _ => some 2
  | 'p' :: 'u' :: 's' :: 'h' :: '}' :: _ => some 5
  | '-' :: c :: rest => if isDigit c then (bracePos rest).map (· + 2) else none
  | c :: rest => if isDigit c then (bracePos rest).map (· + 1) else none
  | [] => none

/-- `_AT.sub("", rev)`: delete every admitted `@{...}` form, scanning left to right.
`atBody` reports how many characters a match occupies, so every recursive call is on a
strictly shorter list and termination needs no facts about `atBody` at all. -/
def stripAt (cs : List Char) : List Char :=
  match cs with
  | [] => []
  | '@' :: '{' :: rest =>
    match atBody rest with
    | some n => stripAt (rest.drop n)
    | none => '@' :: stripAt ('{' :: rest)
  | c :: rest => c :: stripAt rest
termination_by cs.length
decreasing_by all_goals first
  | (simp [List.length_drop]; omega)
  | (simp; omega)
  | simp
  | omega

/-- `_AT.fullmatch`: the whole revision is exactly one admitted `@{...}` form. -/
def bareForm : List Char → Bool
  | '@' :: '{' :: rest =>
    match atBody rest with
    | some n => (rest.drop n).isEmpty
    | none => false
  | _ => false

/-- `"@{" in stripped`. -/
def hasAtBrace : List Char → Bool
  | '@' :: '{' :: _ => true
  | _ :: rest => hasAtBrace rest
  | [] => false

/-- `_BODY.fullmatch`: `[A-Za-z0-9_@][A-Za-z0-9_./^~:-]*`. The empty list does not match. -/
def bodyOk : List Char → Bool
  | [] => false
  | c :: rest => firstOk c && rest.all restOk

def leadingDash : List Char → Bool
  | '-' :: _ => true
  | _ => false

/-- The checker, clause for clause the Python's `main`. A bare form passes the three
scans trivially — nonempty, starts `@`, no forbidden characters — so hoisting them out
of the disjunction changes no verdict and keeps the theorems one projection each. -/
def check (s : String) : Bool :=
  !s.toList.isEmpty
    && !leadingDash s.toList
    && s.toList.all (fun c => !isForbidden c)
    && (bareForm s.toList
        || (!hasAtBrace (stripAt s.toList) && bodyOk (stripAt s.toList)))

/-! ## The tin -/

/-- The `not-option` atom, kernel-checked: an admitted revision never begins with `-`. -/
theorem check_no_option {s : String} (h : check s = true) :
    leadingDash s.toList = false := by
  cases hb : leadingDash s.toList with
  | false => rfl
  | true => simp [check, hb] at h

/-- An admitted revision is never empty. -/
theorem check_nonempty {s : String} (h : check s = true) : s.toList ≠ [] := by
  intro he
  simp [check, he] at h

/-- An admitted revision carries no space, control character, glob metacharacter
or backslash — anywhere, not only at the head. -/
theorem check_no_forbidden {s : String} (h : check s = true) :
    ∀ c ∈ s.toList, isForbidden c = false := by
  intro c hc
  cases hb : isForbidden c with
  | false => rfl
  | true =>
    unfold check at h
    simp only [Bool.and_eq_true, List.all_eq_true] at h
    have hx := h.1.2 c hc   -- && is left-associative: (((nonempty ∧ nodash) ∧ all) ∧ tail)
    simp [hb] at hx

/-! ## Vectors (checked at build time) -/

-- admitted
#guard check "HEAD"
#guard check "@"
#guard check "main"
#guard check "feature/foo-bar"
#guard check "HEAD~3"
#guard check "HEAD^2"
#guard check "a..b"
#guard check "a...b"
#guard check "main:src/policy.py"
#guard check "HEAD@{u}"
#guard check "main@{upstream}"
#guard check "master@{-1}"
#guard check "x@{push}y"          -- forms strip anywhere, as in the Python

-- refused
#guard !check ""
#guard !check "-rf"
#guard !check "--force"
#guard !check "a b"
#guard !check "a\tb"
#guard !check "a*b"
#guard !check "a?"
#guard !check "a[0]"
#guard !check "a\\b"
#guard !check "@{yesterday}"
#guard !check "x@{yesterday}"
#guard !check "a@b"               -- '@' is admitted only as the first character

-- bare forms: exactly one whole @{...} form stands alone
#guard check "@{u}"
#guard check "@{upstream}"
#guard check "@{push}"
#guard check "@{-1}"
#guard !check "@{u}@{u}"          -- a concatenation of forms is not a revision
#guard !check "@{-}"              -- the number form needs digits

end GitRev

/-! ## The unverified shim: argv in, exit code out. -/

def refuse (msg : String) : IO UInt32 := do
  (← IO.getStderr).putStrLn s!"git-rev: {msg}"
  pure 1

def main (args : List String) : IO UInt32 :=
  match args with
  -- a leading "--" (end-of-options; `lake exe` forwards it) is accepted and ignored:
  -- a bare "--" still lands in the second alternative and is refused as an option
  | ["--", rev] | [rev] =>
    if GitRev.check rev then pure 0
    else refuse s!"{repr rev} is not an admissible revision for a reading command"
  | _ => refuse "expected exactly one argument"
