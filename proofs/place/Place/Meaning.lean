import Place.Path

/-!
What a jail's grants mean (`sandbox/grants.py`, `state_at`): an ordered list of layers, each over
a region, each saying what the paths it covers are, the last word winning.

A pattern is held by its *key* (the location it spells) and its *tops*, the literal directories
every path it matches lies within (`place._tops`). How it matches is a `Matcher`, which nothing
here evaluates: the checker never runs a regex. What is proved holds for every matcher that
keeps within the tops it is given (`WellFormed`), so it holds for the one the view runs.
-/
namespace Place

inductive Region where
  | subtree (p : Path)
  | exactly (p : Path)
  | pattern (key : String) (tops : List Path)
  deriving DecidableEq, Repr

inductive Access where
  | readOnly
  | writable
  deriving DecidableEq, Repr

inductive Narrowing where
  | noWrite
  | hidden
  deriving DecidableEq, Repr

/-- What a layer says of the paths it covers: a grant its access, a restriction its narrowing. -/
inductive Says where
  | grant (a : Access)
  | restrict (n : Narrowing)
  deriving DecidableEq, Repr

inductive State where
  | absent
  | readOnly
  | writable
  | hidden
  deriving DecidableEq, Repr

structure Layer where
  region : Region
  says : Says
  deriving DecidableEq, Repr

/-- What a pattern matches, by its key. -/
abbrev Matcher := String → Path → Bool

def Says.isRestriction : Says → Bool
  | .restrict _ => true
  | .grant _ => false

/-- The literal directories a region lies under: its path, or a pattern's tops. -/
def Region.tops : Region → List Path
  | .subtree p => [p]
  | .exactly p => [p]
  | .pattern _ ts => ts

/-- Does *r* cover *p*? With *below* -- a restriction's, which narrows everything below what it
names -- also whatever lies below what it covers. -/
def Region.covers (M : Matcher) : Region → Bool → Path → Bool
  | .subtree t, _, p => prefixOf t p
  | .exactly t, below, p => if below then prefixOf t p else t == p
  | .pattern k _, below, p => if below then (prefixes p).any (M k) else M k p

def Layer.covers (M : Matcher) (l : Layer) (p : Path) : Bool :=
  l.region.covers M l.says.isRestriction p

/-- *s*, once a layer saying *w* covers the path: a grant sets its access; no-write turns writable
into read-only; hidden turns anything present into hidden. Neither restriction makes an absent
path appear. -/
def after : State → Says → State
  | _, .grant .writable => .writable
  | _, .grant .readOnly => .readOnly
  | .writable, .restrict .noWrite => .readOnly
  | s, .restrict .noWrite => s
  | .absent, .restrict .hidden => .absent
  | _, .restrict .hidden => .hidden

/-- *p*'s state from *s*, by the layers in order. -/
def stateFrom (M : Matcher) (s : State) : List Layer → Path → State
  | [], _ => s
  | l :: ls, p => stateFrom M (if l.covers M p then after s l.says else s) ls p

/-- The matcher keeps within the tops it is given: whatever a pattern of *layers* matches lies
within one of its tops. -/
def WellFormed (M : Matcher) (layers : List Layer) : Prop :=
  ∀ l ∈ layers, ∀ k ts, l.region = .pattern k ts → ∀ q, M k q = true → ∃ t ∈ ts, prefixOf t q = true

theorem WellFormed.tail {M : Matcher} {l : Layer} {ls : List Layer} (h : WellFormed M (l :: ls)) :
    WellFormed M ls :=
  fun l' hl' => h l' (List.mem_cons_of_mem _ hl')

/-- A layer covers only what lies within one of its tops. -/
theorem top_of_covers {M : Matcher} {l : Layer} {p : Path}
    (hwf : ∀ k ts, l.region = .pattern k ts → ∀ q, M k q = true → ∃ t ∈ ts, prefixOf t q = true)
    (h : l.covers M p = true) : ∃ t ∈ l.region.tops, prefixOf t p = true := by
  unfold Layer.covers at h
  cases hr : l.region with
  | subtree t =>
    rw [hr] at h
    exact ⟨t, by simp [Region.tops], h⟩
  | exactly t =>
    rw [hr] at h
    refine ⟨t, by simp [Region.tops], ?_⟩
    simp only [Region.covers] at h
    split at h
    · exact h
    · rw [beq_iff_eq.1 h]
      exact prefixOf_refl p
  | pattern k ts =>
    rw [hr] at h
    simp only [Region.covers] at h
    have wf := hwf k ts hr
    split at h
    · obtain ⟨q, hq, hm⟩ := List.any_eq_true.1 h
      obtain ⟨t, ht, htq⟩ := wf q hm
      exact ⟨t, ht, prefixOf_trans htq (mem_prefixes.1 hq)⟩
    · exact wf p h

-- -- the rename rule, shared with the view daemon ------------------------------------------------

/-- What a matcher knows of its patterns beyond a match: does one cover a path and everything
below it, and might one name something strictly below a path? The checker knows nothing
(`blind`, erring toward moving); the daemon knows its patterns. -/
structure Reach where
  wholly : String → Path → Bool
  below : String → Path → Bool

def blind : Reach := ⟨fun _ _ => true, fun _ _ => false⟩

/-- Does *r* cover *a* and everything below it? -/
def Region.wholly (R : Reach) : Region → Path → Bool
  | .subtree t, a => prefixOf t a
  | .exactly _, _ => false
  | .pattern k _, a => R.wholly k a

/-- Does *l* cover *a*, or reach below it? -/
def Layer.reaches (M : Matcher) (R : Reach) (l : Layer) (a : Path) : Bool :=
  l.covers M a || match l.region with
    | .subtree t => prefixOf a t
    | .exactly t => prefixOf a t
    | .pattern k _ => R.below k a

/-- The view daemon's rule for moving a directory from *a* to *b* (`Fuseview.Filter.mayMoveDir`):
some writable grant covers both ends wholly, and no layer after it covers or reaches below either
-- every path below either end is then writable, by that grant, with nothing else having a say.
The one definition the daemon runs and the checker reasons with. -/
def movable (M : Matcher) (R : Reach) : List Layer → Path → Path → Bool
  | [], _, _ => false
  | l :: ls, a, b =>
    (l.says == .grant .writable && l.region.wholly R a && l.region.wholly R b
      && ls.all fun l' => !l'.reaches M R a && !l'.reaches M R b)
    || movable M R ls a b

/-- Might the daemon move the directory *a* at all? Its rule at one end. -/
def dirRule (M : Matcher) (R : Reach) (layers : List Layer) (a : Path) : Bool := movable M R layers a a

/-- No pattern covers anything: the meaning the checker can evaluate, which is the meaning
wherever the views keep patterns away (`Check.lean`, obligation 3). -/
def noPatterns : Matcher := fun _ _ => false

theorem Region.wholly_blind {R : Reach} {r : Region} {a : Path} (h : r.wholly R a = true) :
    r.wholly blind a = true := by
  cases r with
  | subtree t => exact h
  | exactly t => simp [Region.wholly] at h
  | pattern k ts => simp [Region.wholly, blind]

/-- Blind, a layer reaches no more than it does knowing its patterns. -/
theorem Layer.reaches_of_blind {M : Matcher} {R : Reach} {l : Layer} {a : Path}
    (h : l.reaches noPatterns blind a = true) : l.reaches M R a = true := by
  unfold Layer.reaches at h ⊢
  cases hr : l.region with
  | subtree t => simpa [Layer.covers, hr, Region.covers] using h
  | exactly t => simpa [Layer.covers, hr, Region.covers] using h
  | pattern k ts => simp [Layer.covers, hr, Region.covers, noPatterns, blind] at h

theorem Layer.reaches_blind_false {M : Matcher} {R : Reach} {l : Layer} {a : Path}
    (h : l.reaches M R a = false) : l.reaches noPatterns blind a = false := by
  cases hx : l.reaches noPatterns blind a with
  | false => rfl
  | true => rw [Layer.reaches_of_blind (M := M) (R := R) hx] at h; cases h

/-- Whatever a daemon knowing its patterns (*M*, *R*) may move, the blind rule may move too, at
either end. So a directory the blind rule holds still is one the daemon never moves: what the
placement checker relies on for a bind back on a view (`Plan.footing`), and what makes its
assumption about the kernel (`Run.Kernel.mounts`) one about this daemon (`Fuseview.Filter.mayMoveDir_blind`). -/
theorem movable_blind {M : Matcher} {R : Reach} : ∀ {ls : List Layer} {a b : Path},
    movable M R ls a b = true → dirRule noPatterns blind ls a = true ∧ dirRule noPatterns blind ls b = true
  | [], _, _, h => by simp [movable] at h
  | l :: ls, a, b, h => by
    simp only [movable, Bool.or_eq_true] at h
    unfold dirRule
    simp only [movable, Bool.or_eq_true]
    rcases h with h | h
    · simp only [Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true'] at h
      obtain ⟨⟨⟨hw, hwa⟩, hwb⟩, hall⟩ := h
      constructor
      · left
        simp only [Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true']
        exact ⟨⟨⟨hw, Region.wholly_blind hwa⟩, Region.wholly_blind hwa⟩,
          fun l' hl' => ⟨Layer.reaches_blind_false (hall l' hl').1, Layer.reaches_blind_false (hall l' hl').1⟩⟩
      · left
        simp only [Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true']
        exact ⟨⟨⟨hw, Region.wholly_blind hwb⟩, Region.wholly_blind hwb⟩,
          fun l' hl' => ⟨Layer.reaches_blind_false (hall l' hl').2, Layer.reaches_blind_false (hall l' hl').2⟩⟩
    · have ih := movable_blind h
      unfold dirRule at ih
      exact ⟨Or.inr ih.1, Or.inr ih.2⟩

/-- Might *r* decide anything at or below the directory *d*? (`place._overlaps`) -/
def overlaps (r : Region) (d : Path) : Bool :=
  r.tops.any fun t => prefixOf t d || prefixOf d t

/-- Below *d*, the layers that overlap it decide exactly what all of them do: what a view of *d*
holds is all it needs. -/
theorem stateFrom_filter_overlaps {M : Matcher} {d p : Path} (hdp : prefixOf d p = true) :
    ∀ {layers : List Layer} (s : State), WellFormed M layers →
      stateFrom M s (layers.filter fun l => overlaps l.region d) p = stateFrom M s layers p
  | [], _, _ => rfl
  | l :: ls, s, hwf => by
    have ih := stateFrom_filter_overlaps (M := M) hdp (layers := ls)
    by_cases ho : overlaps l.region d = true
    · simp only [List.filter_cons, ho, if_true, stateFrom]
      exact ih _ hwf.tail
    · have hn : l.covers M p = false := by
        cases hc : l.covers M p
        · rfl
        · obtain ⟨t, ht, htp⟩ := top_of_covers (hwf l List.mem_cons_self) hc
          exfalso
          apply ho
          apply List.any_eq_true.2
          refine ⟨t, ht, ?_⟩
          rcases prefixOf_total htp hdp with h | h <;> simp [h]
      simp only [List.filter_cons, ho, stateFrom, hn]
      simpa using ih s hwf.tail

/-- A writable state is the start's, or a writable grant's. -/
theorem writable_of_stateFrom {M : Matcher} {p : Path} :
    ∀ {layers : List Layer} {s : State}, stateFrom M s layers p = .writable →
      s = .writable ∨ ∃ l ∈ layers, l.says = .grant .writable
  | [], _, h => Or.inl h
  | l :: ls, s, h => by
    simp only [stateFrom] at h
    rcases writable_of_stateFrom h with h' | ⟨l', hl', hs⟩
    · split at h'
      · cases hsays : l.says with
        | grant a =>
          cases a with
          | writable => exact Or.inr ⟨l, List.mem_cons_self, hsays⟩
          | readOnly => rw [hsays] at h'; simp [after] at h'
        | restrict n =>
          rw [hsays] at h'
          cases n <;> cases s <;> simp [after] at h'
      · exact Or.inl h'
    · exact Or.inr ⟨l', List.mem_cons_of_mem _ hl', hs⟩

/-- A writable state is the start's, or a writable grant's that covers the path. -/
theorem writable_covers {M : Matcher} {p : Path} :
    ∀ {layers : List Layer} {s : State}, stateFrom M s layers p = .writable →
      s = .writable ∨ ∃ l ∈ layers, l.says = .grant .writable ∧ l.covers M p = true
  | [], _, h => Or.inl h
  | l :: ls, s, h => by
    simp only [stateFrom] at h
    rcases writable_covers h with h' | ⟨l', hl', hs, hc⟩
    · cases hcov : l.covers M p with
      | false => rw [hcov] at h'; simp at h'; exact Or.inl h'
      | true =>
        rw [hcov] at h'
        simp only [if_true] at h'
        cases hsays : l.says with
        | grant a =>
          cases a with
          | writable => exact Or.inr ⟨l, List.mem_cons_self, hsays, hcov⟩
          | readOnly => rw [hsays] at h'; simp [after] at h'
        | restrict n =>
          rw [hsays] at h'
          cases n <;> cases s <;> simp [after] at h'
    · exact Or.inr ⟨l', List.mem_cons_of_mem _ hl', hs, hc⟩

/-- Where no grant covers *p*, nothing makes it appear: from absent, it stays absent. -/
theorem absent_of_no_grant {M : Matcher} {p : Path} :
    ∀ {layers : List Layer}, (∀ l ∈ layers, l.says.isRestriction = false → l.covers M p = false) →
      stateFrom M .absent layers p = .absent
  | [], _ => rfl
  | l :: ls, h => by
    simp only [stateFrom]
    have hrest : stateFrom M .absent ls p = .absent :=
      absent_of_no_grant fun l' hl' => h l' (List.mem_cons_of_mem _ hl')
    split
    · rename_i hc
      cases hs : l.says with
      | grant a =>
        have := h l List.mem_cons_self (by simp [Says.isRestriction, hs])
        rw [this] at hc
        cases hc
      | restrict n =>
        cases n <;> simpa [after] using hrest
    · exact hrest

/-- Layers that cover two paths alike, under two matchers, decide them alike. -/
theorem stateFrom_congr {M M' : Matcher} {p r : Path} :
    ∀ {layers : List Layer} (s : State), (∀ l ∈ layers, l.covers M p = l.covers M' r) →
      stateFrom M s layers p = stateFrom M' s layers r
  | [], _, _ => rfl
  | l :: ls, s, h => by
    simp only [stateFrom]
    rw [h l List.mem_cons_self]
    exact stateFrom_congr _ fun l' hl' => h l' (List.mem_cons_of_mem _ hl')

end Place
