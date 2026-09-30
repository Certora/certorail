import Place.Meaning
import Fuseview.Bytes
import Fuseview.NamePattern

/-!
What a pattern denotes: a location's components matched one by one against a path's names,
relative to the directory the pattern is anchored at (`analysis.location_le`, with a real path on
the other side). Everything here is total, so that it can be reasoned about: the placement
checker's theorems hold for any matcher that keeps within its patterns' literal prefixes
(`Place.WellFormed`), and `Pattern.denotesAt_top` shows this one does.

`none` is a question with no answer -- a regex that cannot say (see `NamePattern`) -- and every
answer the filter builds on one is the closed one.

The checker spells paths as strings (`Place.Path`); a name is bytes. `Name.encode` spells a valid
UTF-8 name as itself and any other as `/` -- which no name holds -- and its bytes in hex, and
`Name.decode` reads either back. A string neither came from (`canonical` false) matches no pattern.
-/
namespace Fuseview

inductive Component where
  | named (n : Name)
  | any
  | oneOf (ns : Array Name)
  /-- the whole name must match -/
  | matching (re : NamePattern)
  deriving Inhabited

inductive Location where
  /-- exactly these components -/
  | path (cs : Array Component)
  /-- `pre/**` (no leaf): the prefix and everything below it; `pre/**/leaf`: anything strictly
  below it whose last component is the leaf -/
  | splat (pre : Array Component) (leaf : Option Component)
  deriving Inhabited

/-- An absolute path, as its components. -/
abbrev Path := Array Name

/-- A pattern, anchored: the root for a relative location, `/` for an absolute one. -/
structure Pattern where
  loc : Location
  anchor : Path
  deriving Inhabited

def accepts (c : Component) (name : Name) : Option Bool :=
  match c with
  | .named n => some (n == name)
  | .any => some true
  | .oneOf ns => some (ns.toList.any (· == name))
  | .matching re => re.fullmatch name

/-- Components against names, one to one, as many of each. -/
def acceptsAll : List Component → List Name → Option Bool
  | [], [] => some true
  | c :: cs, n :: ns =>
    match accepts c n with
    | some true => acceptsAll cs ns
    | other => other
  | _, _ => some false

/-- The components against the first names, one per component. -/
def acceptsPrefix (cs : List Component) (ns : List Name) : Option Bool :=
  if ns.length < cs.length then some false else acceptsAll cs (ns.take cs.length)

/-- Does *loc* denote the path *rel* spells, relative to its anchor? -/
def denotes (loc : Location) (rel : List Name) : Option Bool :=
  match loc with
  | .path cs => acceptsAll cs.toList rel
  | .splat pre leaf =>
    match acceptsPrefix pre.toList rel with
    | some true =>
      if rel.length == pre.size then some leaf.isNone  -- the prefix itself: only the reflexive form
      else match leaf with
        | none => some true
        | some l =>
          match rel.getLast? with
          | some n => accepts l n
          | none => some false
    | other => other

/-- Does *loc* denote some path strictly below *rel*? -/
def namesBelow (loc : Location) (rel : List Name) : Option Bool :=
  match loc with
  | .path cs => if cs.size ≤ rel.length then some false else acceptsAll (cs.toList.take rel.length) rel
  | .splat pre _ =>
    let k := min pre.size rel.length
    acceptsAll (pre.toList.take k) (rel.take k)

/-- Does *loc* denote *rel* and everything below it? `pre/**` (no leaf) that denotes it; nothing
else is known to. -/
def coversWholly (loc : Location) (rel : List Name) : Option Bool :=
  match loc with
  | .splat _ none => denotes loc rel
  | _ => some false

/-- The literal prefixes a component list spells: its leading run of names and sets, exploded
(`locations.enumerable_prefixes`). -/
def literalRun : List Component → List (List Name)
  | .named n :: cs => (literalRun cs).map (n :: ·)
  | .oneOf ns :: cs => ns.toList.flatMap fun n => (literalRun cs).map (n :: ·)
  | _ => [[]]

def Location.tops : Location → List (List Name)
  | .path cs => literalRun cs.toList
  | .splat pre _ => literalRun pre.toList

-- -- names as the checker spells them -----------------------------------------------------------------

def hexDigit (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)

def Name.encode (n : Name) : String :=
  match String.fromUTF8? n.bytes with
  | some s => s
  | none => "/" ++ String.ofList (n.bytes.toList.flatMap fun b => [hexDigit (b.toNat / 16), hexDigit (b.toNat % 16)])

def unhex : List Char → List UInt8
  | a :: b :: rest => (NamePattern.hexVal a * 16 + NamePattern.hexVal b).toUInt8 :: unhex rest
  | _ => []

def Name.decode (s : String) : Name :=
  if s.startsWith "/" then ⟨⟨(unhex (s.toList.drop 1)).toArray⟩⟩ else ⟨s.toUTF8⟩

/-- Did the string come from a name? -/
def canonical (s : String) : Bool := Name.encode (Name.decode s) == s

def toPlace (p : Path) : Place.Path := p.toList.map Name.encode

/-- *names* less the prefix *pre*, when it is one. -/
def dropPrefix : List Name → List Name → Option (List Name)
  | [], ns => some ns
  | a :: as, n :: ns => if a == n then dropPrefix as ns else none
  | _ :: _, [] => none

def isPrefixN (pre full : List Name) : Bool := (dropPrefix pre full).isSome

/-- Is *pre* the path *full*, or a directory above it? -/
def isPrefix (pre full : Path) : Bool := isPrefixN pre.toList full.toList

namespace Pattern

/-- Does the pattern denote *names*, an absolute path? -/
def denotesNames (pat : Pattern) (names : List Name) : Option Bool :=
  match dropPrefix pat.anchor.toList names with
  | some rel => denotes pat.loc rel
  | none => some false

/-- Might the pattern name something strictly below *names*? At or above where it is anchored,
yes. -/
def belowNames (pat : Pattern) (names : List Name) : Option Bool :=
  if isPrefixN names pat.anchor.toList then some true
  else match dropPrefix pat.anchor.toList names with
    | some rel => namesBelow pat.loc rel
    | none => some false

def whollyNames (pat : Pattern) (names : List Name) : Option Bool :=
  match dropPrefix pat.anchor.toList names with
  | some rel => coversWholly pat.loc rel
  | none => some false

/-- The pattern on a path as the checker spells it: a string that came from no name matches
nothing. -/
def denotesAt (pat : Pattern) (q : Place.Path) : Option Bool :=
  if q.all canonical then pat.denotesNames (q.map Name.decode) else some false

def belowAt (pat : Pattern) (q : Place.Path) : Option Bool :=
  if q.all canonical then pat.belowNames (q.map Name.decode) else some false

def whollyAt (pat : Pattern) (q : Place.Path) : Option Bool :=
  if q.all canonical then pat.whollyNames (q.map Name.decode) else some false

/-- The literal directories the pattern lies under, as the checker spells them. -/
def tops (pat : Pattern) : List Place.Path :=
  pat.loc.tops.map fun t => (pat.anchor.toList ++ t).map Name.encode

end Pattern

-- -- the matcher keeps within its tops --------------------------------------------------------------

theorem acceptsAll_top : ∀ {cs : List Component} {ns : List Name},
    acceptsAll cs ns = some true → ∃ t ∈ literalRun cs, t <+: ns
  | [], ns, _ => ⟨[], by simp [literalRun], List.nil_prefix⟩
  | _ :: _, [], h => by simp [acceptsAll] at h
  | c :: cs, n :: ns, h => by
    simp only [acceptsAll] at h
    cases hc : accepts c n with
    | none => rw [hc] at h; cases h
    | some b =>
      cases b with
      | false => rw [hc] at h; cases h
      | true =>
        rw [hc] at h
        simp only at h
        obtain ⟨t, ht, s, hs⟩ := acceptsAll_top h
        cases c with
        | named m =>
          simp only [accepts, Option.some.injEq] at hc
          have hm : m = n := Name.eq_of_beq hc
          subst hm
          exact ⟨m :: t, List.mem_map.2 ⟨t, ht, rfl⟩, s, by rw [List.cons_append, hs]⟩
        | oneOf ms =>
          simp only [accepts, Option.some.injEq, List.any_eq_true] at hc
          obtain ⟨m, hm, hmn⟩ := hc
          have := Name.eq_of_beq hmn
          subst this
          exact ⟨m :: t, List.mem_flatMap.2 ⟨m, hm, List.mem_map.2 ⟨t, ht, rfl⟩⟩, s, by rw [List.cons_append, hs]⟩
        | any => exact ⟨[], by simp [literalRun], List.nil_prefix⟩
        | matching re => exact ⟨[], by simp [literalRun], List.nil_prefix⟩

theorem acceptsPrefix_top {cs : List Component} {ns : List Name} (h : acceptsPrefix cs ns = some true) :
    ∃ t ∈ literalRun cs, t <+: ns := by
  unfold acceptsPrefix at h
  split at h
  · cases h
  · obtain ⟨t, ht, hpre⟩ := acceptsAll_top h
    exact ⟨t, ht, hpre.trans (List.take_prefix _ _)⟩

theorem denotes_top {loc : Location} {rel : List Name} (h : denotes loc rel = some true) :
    ∃ t ∈ loc.tops, t <+: rel := by
  cases loc with
  | path cs => exact acceptsAll_top h
  | splat pre leaf =>
    simp only [denotes] at h
    cases hp : acceptsPrefix pre.toList rel with
    | none => rw [hp] at h; cases h
    | some b =>
      cases b with
      | false => rw [hp] at h; cases h
      | true => exact acceptsPrefix_top hp

theorem dropPrefix_spec : ∀ {pre ns rel : List Name}, dropPrefix pre ns = some rel → ns = pre ++ rel
  | [], ns, rel, h => by simp only [dropPrefix, Option.some.injEq] at h; simp [h]
  | a :: as, n :: ns, rel, h => by
    simp only [dropPrefix] at h
    split at h
    · rename_i hb
      have := Name.eq_of_beq hb
      subst this
      rw [List.cons_append, dropPrefix_spec h]
    · cases h
  | _ :: _, [], _, h => by simp [dropPrefix] at h

theorem encode_decode_of_canonical {q : Place.Path} (h : q.all canonical = true) :
    (q.map Name.decode).map Name.encode = q := by
  rw [List.map_map]
  conv => rhs; rw [← List.map_id q]
  apply List.map_congr_left
  intro s hs
  have := List.all_eq_true.1 h s hs
  exact beq_iff_eq.1 this

/-- The matcher keeps within its tops: a path a pattern denotes lies under one of its literal
prefixes -- what the placement checker's proofs need of it (`Place.WellFormed`). -/
theorem Pattern.denotesAt_top {pat : Pattern} {q : Place.Path} (h : pat.denotesAt q = some true) :
    ∃ t ∈ pat.tops, Place.prefixOf t q = true := by
  unfold Pattern.denotesAt at h
  split at h
  · rename_i hcan
    unfold Pattern.denotesNames at h
    cases hd : dropPrefix pat.anchor.toList (q.map Name.decode) with
    | none => rw [hd] at h; cases h
    | some rel =>
      rw [hd] at h
      obtain ⟨t, ht, s, hs⟩ := denotes_top h
      refine ⟨(pat.anchor.toList ++ t).map Name.encode, List.mem_map.2 ⟨t, ht, rfl⟩, ?_⟩
      apply Place.prefixOf_iff.2
      refine ⟨s.map Name.encode, ?_⟩
      rw [← List.map_append, List.append_assoc, hs, ← dropPrefix_spec hd, encode_decode_of_canonical hcan]
  · cases h

end Fuseview
