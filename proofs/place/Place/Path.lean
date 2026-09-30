/-!
Paths as the jail compiler holds them: components from `/`, and `[]` is `/` itself.
`prefixOf t p` says *t* is *p* or one of its ancestors, which is `within(p, t)` in `place.py`.
Everything here is about that one relation.
-/
namespace Place

abbrev Path := List String

/-- Is *t* a prefix of *p*: *p* itself, or a directory above it? -/
def prefixOf : Path → Path → Bool
  | [], _ => true
  | _ :: _, [] => false
  | a :: t, b :: p => a == b && prefixOf t p

theorem prefixOf_iff : ∀ {t p : Path}, prefixOf t p = true ↔ ∃ s, p = t ++ s
  | [], p => by simp [prefixOf]
  | _ :: _, [] => by simp [prefixOf]
  | a :: t, b :: p => by
    simp only [prefixOf, Bool.and_eq_true, beq_iff_eq, prefixOf_iff, List.cons_append, List.cons.injEq]
    constructor
    · rintro ⟨rfl, s, rfl⟩
      exact ⟨s, rfl, rfl⟩
    · rintro ⟨s, rfl, rfl⟩
      exact ⟨rfl, s, rfl⟩

theorem prefixOf_refl (p : Path) : prefixOf p p = true := prefixOf_iff.2 ⟨[], by simp⟩

theorem prefixOf_nil (p : Path) : prefixOf [] p = true := prefixOf_iff.2 ⟨p, by simp⟩

theorem prefixOf_append (t s : Path) : prefixOf t (t ++ s) = true := prefixOf_iff.2 ⟨s, rfl⟩

theorem prefixOf_trans {a b c : Path} (h₁ : prefixOf a b = true) (h₂ : prefixOf b c = true) :
    prefixOf a c = true := by
  obtain ⟨s, rfl⟩ := prefixOf_iff.1 h₁
  obtain ⟨u, rfl⟩ := prefixOf_iff.1 h₂
  exact prefixOf_iff.2 ⟨s ++ u, by simp⟩

theorem length_le_of_prefixOf {t p : Path} (h : prefixOf t p = true) : t.length ≤ p.length := by
  obtain ⟨s, rfl⟩ := prefixOf_iff.1 h
  simp

/-- Two prefixes of one path are one a prefix of the other. -/
theorem prefixOf_total : ∀ {a b p : Path}, prefixOf a p = true → prefixOf b p = true →
    prefixOf a b = true ∨ prefixOf b a = true
  | [], _, _, _, _ => Or.inl (prefixOf_nil _)
  | _ :: _, [], _, _, _ => Or.inr (prefixOf_nil _)
  | _ :: _, _ :: _, [], ha, _ => by simp [prefixOf] at ha
  | x :: a, y :: b, z :: p, ha, hb => by
    simp only [prefixOf, Bool.and_eq_true, beq_iff_eq] at ha hb ⊢
    obtain ⟨rfl, ha⟩ := ha
    obtain ⟨rfl, hb⟩ := hb
    simpa using prefixOf_total ha hb

theorem eq_of_prefixOf_of_length_le {a b : Path} (h : prefixOf a b = true) (hl : b.length ≤ a.length) :
    a = b := by
  obtain ⟨s, rfl⟩ := prefixOf_iff.1 h
  have : s = [] := by
    simp at hl
    exact List.eq_nil_of_length_eq_zero (by omega)
  simp [this]

/-- Of two prefixes of one path, the shorter is a prefix of the longer. -/
theorem prefixOf_of_length_le {a b p : Path} (ha : prefixOf a p = true) (hb : prefixOf b p = true)
    (hl : a.length ≤ b.length) : prefixOf a b = true := by
  rcases prefixOf_total ha hb with h | h
  · exact h
  · rw [eq_of_prefixOf_of_length_le h hl]
    exact prefixOf_refl a

/-- A name that is none of *b*'s components cannot make *b* reach past *q*. -/
theorem prefixOf_of_prefixOf_snoc {b q : Path} {f : String} (hf : f ∉ b)
    (h : prefixOf b (q ++ [f]) = true) : prefixOf b q = true := by
  obtain ⟨s, hs⟩ := prefixOf_iff.1 h
  rcases List.eq_nil_or_concat s with rfl | ⟨s', x, rfl⟩
  · simp at hs
    exact absurd (hs ▸ List.mem_append_right q (List.mem_singleton_self f)) hf
  · simp only [List.concat_eq_append, ← List.append_assoc] at hs
    obtain ⟨hq, -⟩ := List.append_inj' hs (by simp)
    exact prefixOf_iff.2 ⟨s', hq⟩

/-- Every prefix of *p*, shortest first. -/
def prefixes : Path → List Path
  | [] => [[]]
  | a :: p => [] :: (prefixes p).map (a :: ·)

theorem mem_prefixes : ∀ {q p : Path}, q ∈ prefixes p ↔ prefixOf q p = true
  | q, [] => by cases q <;> simp [prefixes, prefixOf]
  | [], _ :: _ => by simp [prefixes, prefixOf]
  | b :: q, a :: p => by
    simp only [prefixes, List.mem_cons, List.mem_map, prefixOf, Bool.and_eq_true, beq_iff_eq,
      reduceCtorEq, false_or, List.cons.injEq]
    constructor
    · rintro ⟨q', hq', rfl, rfl⟩
      exact ⟨rfl, mem_prefixes.1 hq'⟩
    · rintro ⟨rfl, h⟩
      exact ⟨q, mem_prefixes.2 h, rfl, rfl⟩

/-- The element of *l* with the greatest *f*, the first of equals; none only for an empty list. -/
def argmax {α : Type} (f : α → Nat) : List α → Option α
  | [] => none
  | a :: l => match argmax f l with
    | none => some a
    | some b => if f b ≤ f a then some a else some b

theorem argmax_mem {α : Type} {f : α → Nat} : ∀ {l : List α} {a : α}, argmax f l = some a → a ∈ l
  | [], _, h => by simp [argmax] at h
  | x :: l, a, h => by
    simp only [argmax] at h
    split at h
    · cases h; exact List.mem_cons_self
    · rename_i b hb
      split at h
      · cases h; exact List.mem_cons_self
      · cases h; exact List.mem_cons_of_mem _ (argmax_mem hb)

theorem argmax_eq_none {α : Type} {f : α → Nat} : ∀ {l : List α}, argmax f l = none → l = []
  | [], _ => rfl
  | _ :: _, h => by
    simp only [argmax] at h
    split at h
    · cases h
    · split at h <;> cases h

theorem argmax_max {α : Type} {f : α → Nat} : ∀ {l : List α} {a : α}, argmax f l = some a →
    ∀ b ∈ l, f b ≤ f a
  | [], _, h => by simp [argmax] at h
  | x :: l, a, h => by
    simp only [argmax] at h
    intro b hb
    split at h
    · rename_i hn
      cases h
      rcases List.mem_cons.1 hb with rfl | hb
      · exact Nat.le_refl _
      · rw [argmax_eq_none hn] at hb
        simp at hb
    · rename_i c hc
      have hmax := argmax_max hc
      split at h
      · rename_i hle
        cases h
        rcases List.mem_cons.1 hb with rfl | hb
        · exact Nat.le_refl _
        · exact Nat.le_trans (hmax b hb) hle
      · rename_i hlt
        cases h
        rcases List.mem_cons.1 hb with rfl | hb
        · omega
        · exact hmax b hb

theorem argmax_isSome {α : Type} {f : α → Nat} : ∀ {l : List α} {b : α}, b ∈ l → ∃ a, argmax f l = some a
  | [], _, h => by simp at h
  | x :: l, _, _ => by
    simp only [argmax]
    split
    · exact ⟨x, rfl⟩
    · split
      · exact ⟨x, rfl⟩
      · rename_i c _ _
        exact ⟨c, rfl⟩

end Place
