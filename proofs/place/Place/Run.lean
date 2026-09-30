import Place.Plan

/-!
The jail over a run: the host changes while it lives, and a certified plan keeps showing, at every
path and every moment, no more than what its grants mean of what is there then.

**The host.** At each step the host is what each path names (`Fs`): an object, or nothing, no link
followed (a link is an object with nothing below it). Between steps one operation happens -- a
rename, a removal, a creation -- by the jail or by something outside it. Writing a file changes
what the object holds, not what names it, and is no step.

**Mounts live and die** (`Plan.live`). Everything here about what a replacement does to a mount is
MEASURED (`scripts/probe_bind_semantics.py`, 2026-09-29, kernel 6.8), and the model takes
exactly the rows:
- a mount on the jail's own empty root (footing `root`) stays where it is; a bind there keeps
  showing the object it captured, wherever the host now names it (row 3, `proj` pinned);
- a mount on a host name goes with its directory when the directory is renamed away, and
  detaches when the name is removed or renamed over, in the host world and the policy world
  alike (rows 1a, 1b, 2, 3) -- so the checker allows one on a host name only as a view at a name
  nothing replaces (footing `fixedView`: the model has it live while the host still names its
  directory as it did, and `Trust.fixed` is what makes that so, `view_live`), or as a bind back
  on a view (footing `onView`), whose `live` is `scripts/probe_view_bindback.py` (MEASURED
  2026-09-29): a bind back detaches
  once the host no longer names, at its path, the object it was made over -- the view's daemon
  answers stale for the old name, the kernel drops the dentry and its mounts, and the view decides
  the name. At once for a file; for a directory, when the kernel next revalidates the entry, at
  most the daemon's directory entry cache (1 s) later. Until then the bind back is pinned to the
  moved object, and a write through it lands wherever the host now names that object: the one
  staleness the model rounds to zero, bounded by that cache;
- the jail sees a change at once (the `[after 1s]` rows), the bind back's cache aside.

**The kernel, as assumed** (`Kernel`): the trace applies each step's operation; nothing lies
below what is not there, or below a file, and an object holds what lies below its name; and the
jail itself changes only entries its mounts make writable (`EROFS`, `EACCES`, the daemon's
`writableName`), and never a live mount's own name or a directory above it (`EBUSY` at a
mountpoint; the daemon's `mayMoveDir`, which refuses every directory footing `onView` requires held
-- proved, `movable_blind` and `Fuseview.Filter.mayMoveDir_blind`; the read-only tmpfs root). **What is trusted** (`Trust`): nothing touches a name the stability model calls fixed;
nothing outside the jail touches one it calls stable. **What was read** (`FactsHold`): the facts
were true when the jail was made -- the link step asks them again at each spawn.

Not modelled: the link step's additions (the spawn's executable, its scratch directory), mounts
the host makes after the jail starts, and bubblewrap's rendering of mounts as flags.
-/
namespace Place

abbrev Node := Nat

/-- The host at one moment, by name. -/
abbrev Fs := Path → Option Node

inductive Op where
  | rename (src dst : Path)
  | remove (p : Path)
  | create (p : Path) (n : Node)
  deriving Repr

def Op.apply : Op → Fs → Fs
  | .rename src dst, fs => fun q =>
    if prefixOf dst q then fs (src ++ q.drop dst.length) else if prefixOf src q then none else fs q
  | .remove p, fs => fun q => if prefixOf p q then none else fs q
  | .create p n, fs => fun q =>
    if q = p ∧ fs p = none ∧ (p = [] ∨ fs p.dropLast ≠ none) then some n else fs q

/-- Might *op* change what *q* names? Only by acting on *q* or a directory above it. -/
def Op.touches : Op → Path → Bool
  | .rename src dst, q => prefixOf src q || prefixOf dst q
  | .remove p, q => prefixOf p q
  | .create p _, q => p == q

/-- The entries an operation changes. -/
def Op.targets : Op → List Path
  | .rename src dst => [src, dst]
  | .remove p => [p]
  | .create p _ => [p]

theorem Op.touches_witness {op : Op} {q : Path} (h : op.touches q = true) :
    ∃ x ∈ op.targets, prefixOf x q = true := by
  cases op with
  | rename src dst =>
    simp only [touches, Bool.or_eq_true] at h
    rcases h with h | h
    · exact ⟨src, by simp [targets], h⟩
    · exact ⟨dst, by simp [targets], h⟩
  | remove p => exact ⟨p, by simp [targets], by simpa [touches] using h⟩
  | create p n =>
    simp only [touches, beq_iff_eq] at h
    exact ⟨p, by simp [targets], h ▸ prefixOf_refl p⟩

theorem Op.targets_touch {op : Op} {x : Path} (h : x ∈ op.targets) : op.touches x = true := by
  cases op with
  | rename src dst =>
    simp only [targets, List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl <;> simp [touches, prefixOf_refl]
  | remove p =>
    simp only [targets, List.mem_singleton] at h
    subst h; simp [touches, prefixOf_refl]
  | create p n =>
    simp only [targets, List.mem_singleton] at h
    subst h; simp [touches]

theorem Op.apply_untouched {op : Op} {fs : Fs} {q : Path} (h : op.touches q = false) :
    op.apply fs q = fs q := by
  cases op with
  | rename src dst =>
    simp only [touches, Bool.or_eq_false_iff] at h
    simp [apply, h.1, h.2]
  | remove p =>
    simp only [touches] at h
    simp [apply, h]
  | create p n =>
    simp only [touches] at h
    simp only [apply]
    split
    · rename_i hc
      rw [hc.1] at h
      simp at h
    · rfl

inductive Actor where
  | jail
  | outside
  deriving DecidableEq, Repr

structure Step where
  actor : Actor
  op : Op

structure World where
  /-- the host at each step -/
  fs : Nat → Fs
  /-- what happens after each step -/
  step : Nat → Step
  /-- what a bind was made from: what its path resolved to, every link followed; nothing, where
  it resolved to nothing -/
  capture : Path → Option Node
  /-- what lies below an object, at a step -/
  below : Nat → Node → Path → Option Node
  /-- is the object a file? -/
  file : Node → Bool

/-- Nothing before step *i* touched *q*. -/
def untouched (w : World) (i : Nat) (q : Path) : Prop := ∀ k < i, (w.step k).op.touches q = false

/-- Is something there, in that state: readable, or writable too? -/
def State.present : State → Bool
  | .readOnly => true
  | .writable => true
  | _ => false

/-- Is *m* still there at step *i*? On the empty root, always: bubblewrap's tmpfs (MEASURED). On a
host name -- a view at a fixed name, a bind back on a view -- while the host still names, at its
path, the object it was mounted on: a mount on a host name goes with its directory and detaches
when the name is replaced (MEASURED), a view no less than a bind. That a fixed view stays is
then a theorem of the trust (`view_live`), not a definition. -/
def Plan.live (pl : Plan) (w : World) (i : Nat) (m : Mount) : Bool :=
  match pl.footing m with
  | some .onView => (w.fs 0 m.path).isSome && w.fs i m.path == w.fs 0 m.path
  | some .fixedView => w.fs i m.path == w.fs 0 m.path
  | _ => true

def Plan.liveMounts (pl : Plan) (w : World) (i : Nat) : List Mount := pl.made.filter (pl.live w i)

/-- The jail at step *i*: the plan's jail with the mounts still there. -/
def Plan.jailAt (pl : Plan) (w : World) (i : Nat) : Jail := { pl.jail with mounts := pl.liveMounts w i }

/-- The object the jail shows at *p* at step *i*: by name through the host's base; through a view,
by name too, but only where the view decides the path present -- at an absent or hidden name a
view shows nothing (what the daemon is CLAIMED to do, `Fuseview.View`: `ENOENT`, `EACCES`; not
proved of it); what a bind captured, through a bind; nothing through the empty base. -/
def Plan.content (M : Matcher) (pl : Plan) (w : World) (i : Nat) (p : Path) : Option Node :=
  match nearest (pl.liveMounts w i) p with
  | none =>
    match pl.base with
    | .empty => none
    | .host _ => w.fs i p
  | some m =>
    match m.source with
    | .own => (w.capture m.path).bind fun o => w.below i o (p.drop m.path.length)
    | .alias _ => (w.capture m.path).bind fun o => w.below i o (p.drop m.path.length)
    | .view _ _ => if ((pl.jailAt w i).built M p).present then w.fs i p else none

/-- The host name whose object the jail should show at *p*: *p*, or through an alias where it
leads. -/
def Plan.named (pl : Plan) (w : World) (i : Nat) (p : Path) : Path :=
  match nearest (pl.liveMounts w i) p with
  | some m =>
    match m.source with
    | .alias t => t ++ p.drop m.path.length
    | _ => p
  | none => p

structure Kernel (M : Matcher) (pl : Plan) (w : World) : Prop where
  trace : ∀ i, w.fs (i + 1) = (w.step i).op.apply (w.fs i)
  closed : ∀ i q s, w.fs i q = none → w.fs i (q ++ s) = none
  below : ∀ i q o s, w.fs i q = some o → w.below i o s = w.fs i (q ++ s)
  /-- nothing lies below a file -/
  leaf : ∀ i o s, w.file o = true → s ≠ [] → w.below i o s = none
  /-- the jail changes an entry only where its mounts make it writable -/
  writes : ∀ i, (w.step i).actor = .jail → ∀ x ∈ (w.step i).op.targets, (pl.jailAt w i).built M x = .writable
  /-- the jail never touches a live mount's own name or a directory above it -/
  mounts : ∀ i, (w.step i).actor = .jail → ∀ m ∈ pl.liveMounts w i, (w.step i).op.touches m.path = false

structure Trust (pl : Plan) (w : World) : Prop where
  fixed : ∀ i q, pl.stability.fixed q = true → (w.step i).op.touches q = false
  stable : ∀ i q, pl.stability.holds q = true → (w.step i).actor = .outside →
    (w.step i).op.touches q = false

/-- The recorded facts were true when the jail was made: where a path resolves to something there,
reached without a link, bubblewrap bound that; what is missing named nothing; what is a file is. -/
structure FactsHold (pl : Plan) (w : World) : Prop where
  resolved : ∀ q t, (q, t) ∈ pl.facts.resolutions → pl.facts.present t = true →
    ∃ o, w.fs 0 t = some o ∧ w.capture q = some o
  missing : ∀ q, pl.facts.kind? q = some .missing → w.fs 0 q = none
  file : ∀ q o, pl.facts.kind? q = some .file → w.fs 0 q = some o → w.file o = true

/-- The host has moved on from the name a bind on the empty root was made from: the bind shows
the object it captured, wherever that is now. Only for one exec; never wider than the grants. -/
def Stale (pl : Plan) (w : World) (i : Nat) (p : Path) (seen : Option Node) : Prop :=
  pl.lifetime = .exec ∧ ∃ m ∈ pl.liveMounts w i, nearest (pl.liveMounts w i) p = some m
    ∧ pl.footing m = some .root ∧ m.source.isBind = true ∧ w.fs i m.leads ≠ w.fs 0 m.leads
    ∧ ∃ o, w.capture m.path = some o ∧ seen = w.below i o (p.drop m.path.length)

/-- At step *i* the jail shows what the grants mean: the same state, and the object the host has at
*named* where that state is present, nothing where it is not; or nothing, on the empty root where
the grants may not write; or nothing, below a bind of a file; or a stale bind (`Stale`). -/
def Shows (pl : Plan) (w : World) (i : Nat) (p : Path) (built meaning : State) (seen : Option Node)
    (named : Path) : Prop :=
  (built = meaning ∧ (meaning.present = true → seen = w.fs i named) ∧ (meaning.present = false → seen = none))
    ∨ (seen = none ∧ built = .absent ∧ meaning ≠ .writable)
    ∨ (seen = none ∧ pl.jail.belowLeaf p = true)
    ∨ (built = meaning ∧ Stale pl w i p seen)

-- -- the mounts, made and live ----------------------------------------------------------------------

theorem mem_made {pl : Plan} {m : Mount} (hm : m ∈ pl.made) : m ∈ pl.mounts ∧ pl.skipped m = false := by
  simp only [Plan.made, List.mem_filter, Bool.not_eq_true'] at hm
  exact hm

theorem sits_parts {pl : Plan} (hsits : pl.sits = true) :
    pl.mounts.all pl.sitsOn = true ∧ pl.mounts.all pl.aliasAlone = true ∧ ordered pl.mounts = true := by
  simp only [Plan.sits, Bool.and_eq_true] at hsits
  exact ⟨hsits.1.1, hsits.1.2, hsits.2⟩

/-- With the mounts ancestors first and none at or below an earlier one, no two share a path. -/
theorem ordered_paths : ∀ {ms : List Mount}, ordered ms = true →
    ∀ m ∈ ms, ∀ m' ∈ ms, m.path = m'.path → m = m'
  | [], _, _, h, _, _, _ => absurd h (List.not_mem_nil)
  | m₀ :: ms, ho, m, hm, m', hm', heq => by
    simp only [ordered, Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true'] at ho
    obtain ⟨hnone, hrest⟩ := ho
    simp only [List.mem_cons] at hm hm'
    rcases hm with rfl | hm <;> rcases hm' with rfl | hm'
    · rfl
    · have := hnone m' hm'; rw [← heq, prefixOf_refl] at this; cases this
    · have := hnone m hm; rw [heq, prefixOf_refl] at this; cases this
    · exact ordered_paths hrest m hm m' hm' heq

theorem live_mem {pl : Plan} {w : World} {i : Nat} {m : Mount} (h : m ∈ pl.liveMounts w i) :
    m ∈ pl.made ∧ pl.live w i m = true := List.mem_filter.1 h

theorem footing_some_of {pl : Plan} (hf : pl.footed = true) {m : Mount} (hm : m ∈ pl.mounts)
    (hnl : pl.skippedBelowLeaf m = false) : ∃ f, pl.footing m = some f := by
  have := List.all_eq_true.1 hf m hm
  rw [hnl] at this
  cases h : pl.footing m with
  | none => rw [h] at this; cases this
  | some f => exact ⟨f, rfl⟩

theorem footing_some {pl : Plan} (hf : pl.footed = true) {m : Mount} (hm : m ∈ pl.made) :
    ∃ f, pl.footing m = some f :=
  footing_some_of hf (mem_made hm).1 (by simp [Plan.skippedBelowLeaf, (mem_made hm).2])

theorem fs_stays {M : Matcher} {pl : Plan} {w : World} (hk : Kernel M pl w) {q : Path} :
    ∀ {i : Nat}, untouched w i q → w.fs i q = w.fs 0 q
  | 0, _ => rfl
  | i + 1, h => by
    rw [hk.trace i, Op.apply_untouched (h i (Nat.lt_succ_self i))]
    exact fs_stays hk fun k hk' => h k (Nat.lt_succ_of_lt hk')

/-- No step touches a fixed name. -/
theorem fixed_untouched {pl : Plan} {w : World} (ht : Trust pl w) {q : Path}
    (hq : pl.stability.fixed q = true) (i : Nat) : untouched w i q :=
  fun k _ => ht.fixed k q hq

/-- A mount footed at a fixed name is a view, at a fixed name. -/
theorem fixedView_spec {pl : Plan} {m : Mount} (h : pl.footing m = some .fixedView) :
    m.isView = true ∧ pl.stability.fixed m.path = true := by
  unfold Plan.footing at h
  split at h
  · split at h
    · cases h
    · split at h
      · rename_i hv
        simp only [Bool.and_eq_true] at hv
        exact hv
      · cases h
  · rename_i P hP
    cases hs : P.source <;> simp only [hs] at h
    all_goals try cases h
    split at h
    · split at h <;> cases h
    · cases h

/-- A view is always live. On the empty root by definition (the tmpfs). At a fixed name because no
step touches a fixed name or a directory above it (`Trust.fixed`), so the host names there what
it did when the jail was made -- the one place the trust in the stability model does its work. Its
footing is never `onView`. -/
theorem view_live {M : Matcher} {pl : Plan} {w : World} (hk : Kernel M pl w) (ht : Trust pl w)
    {i : Nat} {m : Mount} (hv : m.isView = true) : pl.live w i m = true := by
  unfold Plan.live
  cases hf : pl.footing m with
  | none => rfl
  | some f =>
    cases f with
    | root => rfl
    | fixedView =>
      have hstay := fs_stays hk (fixed_untouched ht (fixedView_spec hf).2 i)
      show (w.fs i m.path == w.fs 0 m.path) = true
      rw [hstay]
      simp
    | onView =>
      exfalso
      unfold Plan.footing at hf
      split at hf
      · split at hf <;> simp_all
      · rename_i p hp
        cases hs : p.source <;> simp only [hs] at hf
        all_goals try cases hf
        split at hf
        · split at hf
          · rename_i hcond
            simp only [Bool.and_eq_true, beq_iff_eq] at hcond
            simp only [Mount.isView] at hv
            rw [hcond.1] at hv
            cases hv
          · cases hf
        · cases hf

/-- A mount bound back on a view: the view is its parent mount, and it is the host's own path. -/
theorem parent_of_onView {pl : Plan} {m : Mount} (h : pl.footing m = some .onView) :
    ∃ v, parentMount pl.made m.path = some v ∧ v.isView = true ∧ m.source = .own := by
  unfold Plan.footing at h
  split at h
  · split at h <;> simp_all
  · rename_i v hv
    cases hs : v.source <;> simp only [hs] at h
    all_goals try cases h
    split at h
    · split at h
      · rename_i hcond
        simp only [Bool.and_eq_true, beq_iff_eq] at hcond
        exact ⟨v, hv, by simp [Mount.isView, hs], hcond.1⟩
      · cases h
    · cases h

theorem parentMount_spec {ms : List Mount} {p : Path} {v : Mount} (h : parentMount ms p = some v) :
    v ∈ ms ∧ prefixOf v.path p = true ∧ v.path.length < p.length := by
  obtain ⟨hmem, hpre⟩ := nearest_spec h
  simp only [List.mem_filter, decide_eq_true_eq] at hmem
  exact ⟨hmem.1, hpre, hmem.2⟩

theorem parentMount_longest {ms : List Mount} {p : Path} {v u : Mount} (h : parentMount ms p = some v)
    (hu : u ∈ ms) (hup : prefixOf u.path p = true) (hlt : u.path.length < p.length) :
    u.path.length ≤ v.path.length :=
  nearest_longest h (List.mem_filter.2 ⟨hu, by simpa using hlt⟩) hup

theorem root_of_none {pl : Plan} {m : Mount} (hf : ∃ f, pl.footing m = some f)
    (hnone : parentMount pl.made m.path = none) :
    (pl.base = .empty ∧ pl.footing m = some .root)
      ∨ (m.isView = true ∧ pl.stability.fixed m.path = true ∧ pl.footing m = some .fixedView) := by
  obtain ⟨f, hf'⟩ := hf
  have hdef : pl.footing m = (if pl.base == .empty then some .root
      else if m.isView && pl.stability.fixed m.path then some .fixedView else none) := by
    unfold Plan.footing
    rw [hnone]
  by_cases hb : pl.base = .empty
  · left
    exact ⟨hb, by rw [hdef]; simp [hb]⟩
  · right
    have hb' : (pl.base == .empty) = false := by simpa using hb
    rw [hdef, hb'] at hf'
    simp only [Bool.false_eq_true, if_false] at hf'
    split at hf'
    · rename_i hv
      simp only [Bool.and_eq_true] at hv
      exact ⟨hv.1, hv.2, by rw [hdef, hb']; simp [hv.1, hv.2]⟩
    · cases hf'

-- -- what the jail sees at step i ------------------------------------------------------------------

/-- The nearest live mount: the nearest made one, when it is live; else the view it was footed
on, which is live. -/
theorem nearest_live {M : Matcher} {pl : Plan} {w : World} {i : Nat} {p : Path} (hsits : pl.sits = true)
    (hk : Kernel M pl w) (ht : Trust pl w) :
    (nearest (pl.liveMounts w i) p = none ∧ nearest pl.made p = none)
    ∨ (∃ m, nearest pl.made p = some m ∧ pl.live w i m = true ∧ nearest (pl.liveMounts w i) p = some m)
    ∨ (∃ m v, nearest pl.made p = some m ∧ pl.live w i m = false ∧ nearest (pl.liveMounts w i) p = some v
        ∧ v.isView = true ∧ prefixOf v.path p = true) := by
  obtain ⟨_, _, hord⟩ := sits_parts hsits
  have distinct : ∀ m ∈ pl.made, ∀ m' ∈ pl.made, m.path = m'.path → m = m' :=
    fun m hm m' hm' h => ordered_paths hord m (mem_made hm).1 m' (mem_made hm').1 h
  cases hn : nearest pl.made p with
  | none =>
    left
    refine ⟨?_, rfl⟩
    cases hl : nearest (pl.liveMounts w i) p with
    | none => rfl
    | some m =>
      exfalso
      obtain ⟨hm, hmp⟩ := nearest_spec hl
      obtain ⟨m', hm'⟩ := nearest_exists (live_mem hm).1 hmp
      rw [hn] at hm'
      cases hm'
  | some m =>
    obtain ⟨hmm, hmp⟩ := nearest_spec hn
    -- every mount above p lies at or above m
    have above : ∀ m' ∈ pl.made, prefixOf m'.path p = true → prefixOf m'.path m.path = true := by
      intro m' hm' hm'p
      have hlen := nearest_longest hn hm' hm'p
      rcases prefixOf_total hm'p hmp with h | h
      · exact h
      · rw [eq_of_prefixOf_of_length_le h hlen]; exact prefixOf_refl _
    cases hlive : pl.live w i m with
    | true =>
      right; left
      refine ⟨m, rfl, hlive, ?_⟩
      have hml : m ∈ pl.liveMounts w i := List.mem_filter.2 ⟨hmm, hlive⟩
      obtain ⟨m', hm'⟩ := nearest_exists hml hmp
      obtain ⟨hm'l, hm'p⟩ := nearest_spec hm'
      have h1 := nearest_longest hm' hml hmp
      have h2 := nearest_longest hn (live_mem hm'l).1 hm'p
      have heq : m'.path = m.path := by
        rcases prefixOf_total hm'p hmp with h | h
        · exact eq_of_prefixOf_of_length_le h h1
        · exact (eq_of_prefixOf_of_length_le h h2).symm
      rw [hm', distinct m' (live_mem hm'l).1 m hmm heq]
    | false =>
      right; right
      -- m is dead: bound back on a view v, which is live and the nearest live mount (a view is
      -- never dead, `view_live`; a mount on the empty root neither)
      have hfoot : pl.footing m = some .onView := by
        cases hf : pl.footing m with
        | none => simp [Plan.live, hf] at hlive
        | some f =>
          cases f with
          | root => simp [Plan.live, hf] at hlive
          | fixedView =>
            exfalso
            rw [view_live hk ht (fixedView_spec hf).1] at hlive
            cases hlive
          | onView => rfl
      obtain ⟨v, hvpar, hvview, _⟩ := parent_of_onView hfoot
      obtain ⟨hvm, hvp, hvlen⟩ := parentMount_spec hvpar
      have hvl : v ∈ pl.liveMounts w i := List.mem_filter.2 ⟨hvm, view_live hk ht hvview⟩
      have hvpp : prefixOf v.path p = true := prefixOf_trans hvp hmp
      refine ⟨m, v, rfl, hlive, ?_, hvview, hvpp⟩
      obtain ⟨u, hu⟩ := nearest_exists hvl hvpp
      obtain ⟨hul, hup⟩ := nearest_spec hu
      have hu1 := nearest_longest hu hvl hvpp
      -- u lies above p, so at or above m; not m itself (dead), so strictly above m, so a
      -- candidate for m's parent, so no longer than v
      have hum := above u (live_mem hul).1 hup
      have hune : u ≠ m := fun h => by
        rw [h] at hul
        have := (live_mem hul).2
        rw [hlive] at this
        cases this
      have hult : u.path.length < m.path.length := by
        rcases Nat.lt_or_ge u.path.length m.path.length with h | h
        · exact h
        · exfalso
          exact hune (distinct u (live_mem hul).1 m hmm (eq_of_prefixOf_of_length_le hum h))
      have hu2 : u.path.length ≤ v.path.length :=
        parentMount_longest hvpar (live_mem hul).1 hum hult
      have heq : u.path = v.path := by
        rcases prefixOf_total hup hvpp with h | h
        · exact eq_of_prefixOf_of_length_le h hu1
        · exact (eq_of_prefixOf_of_length_le h hu2).symm
      rw [hu, distinct u (live_mem hul).1 v hvm heq]

theorem viewsHold_jailAt {pl : Plan} {w : World} {i : Nat} (h : viewsHold pl.jail = true) :
    viewsHold (pl.jailAt w i) = true :=
  List.all_eq_true.2 fun m hm => List.all_eq_true.1 h m (live_mem hm).1

/-- A skipped bind left to no view sits on the empty root: the plan's base is empty. -/
theorem missing_base_empty {pl : Plan} (hsits : pl.sits = true) (hfooted : pl.footed = true)
    {e : Path × Path} (he : e ∈ pl.jail.missing) : pl.base = .empty := by
  obtain ⟨_, _, hord⟩ := sits_parts hsits
  simp only [Plan.jail, List.mem_map, List.mem_filter, Bool.and_eq_true, Bool.not_eq_true'] at he
  obtain ⟨m, ⟨hm, ⟨hsk, hnv⟩, hnleaf⟩, _⟩ := he
  have hnotmade : m ∉ pl.made := fun h => by
    have := (mem_made h).2
    rw [hsk] at this
    cases this
  have hfoot : ∃ f, pl.footing m = some f :=
    footing_some_of hfooted hm (by simp [Plan.skippedBelowLeaf, hnleaf])
  cases hpar : parentMount pl.made m.path with
  | none =>
    rcases root_of_none hfoot hpar with ⟨hb, _⟩ | ⟨hv, _, _⟩
    · exact hb
    · exfalso
      unfold Plan.skipped at hsk
      unfold Mount.isView at hv
      cases hs : m.source <;> simp_all
  | some P =>
    exfalso
    obtain ⟨f, hf⟩ := hfoot
    unfold Plan.footing at hf
    rw [hpar] at hf
    cases hs : P.source <;> simp only [hs] at hf
    all_goals try cases hf
    obtain ⟨hPm, hPp, hPlt⟩ := parentMount_spec hpar
    obtain ⟨Q, hQ⟩ := nearest_exists hPm hPp
    obtain ⟨hQm, hQp⟩ := nearest_spec hQ
    have hQne : Q.path ≠ m.path := fun h =>
      hnotmade (ordered_paths hord Q (mem_made hQm).1 m hm h ▸ hQm)
    have hQlt : Q.path.length < m.path.length := by
      rcases Nat.lt_or_ge Q.path.length m.path.length with h | h
      · exact h
      · exact absurd (eq_of_prefixOf_of_length_le hQp h) hQne
    have h1 := parentMount_longest hpar hQm hQp hQlt
    have h2 := nearest_longest hQ hPm hPp
    have heq : Q.path = P.path := by
      rcases prefixOf_total hQp hPp with h | h
      · exact eq_of_prefixOf_of_length_le h h2
      · exact (eq_of_prefixOf_of_length_le h h1).symm
    have hQP : Q = P := ordered_paths hord Q (mem_made hQm).1 P (mem_made hPm).1 heq
    rw [hQ, hQP] at hnv
    simp [isViewAt, Mount.isView, hs] at hnv

/-- Below a bind of a file, that bind is the nearest mount. -/
theorem leaf_nearest {pl : Plan} (hsits : pl.sits = true) {p : Path} (hb : pl.jail.belowLeaf p = true) :
    ∃ l ∈ pl.made, nearest pl.made p = some l ∧ l.source.isBind = true
      ∧ pl.facts.kind? l.leads = some .file ∧ l.path ≠ p ∧ prefixOf l.path p = true := by
  obtain ⟨_, _, hord⟩ := sits_parts hsits
  unfold Jail.belowLeaf at hb
  obtain ⟨e, he, hep⟩ := List.any_eq_true.1 hb
  simp only [Plan.jail, Plan.leafMounts, List.mem_map, List.mem_filter, Bool.and_eq_true, beq_iff_eq] at he
  obtain ⟨l, ⟨hl, ⟨hbind, hfile⟩, halone⟩, rfl⟩ := he
  simp only [Bool.and_eq_true, bne_iff_ne, ne_eq] at hep
  obtain ⟨hlp, hne⟩ := hep
  obtain ⟨Q, hQ⟩ := nearest_exists hl hlp
  obtain ⟨hQm, hQp⟩ := nearest_spec hQ
  have hlen := nearest_longest hQ hl hlp
  have hQl : Q = l := by
    rcases prefixOf_total hQp hlp with h | h
    · exact ordered_paths hord Q (mem_made hQm).1 l (mem_made hl).1 (eq_of_prefixOf_of_length_le h hlen)
    · have := List.all_eq_true.1 halone Q hQm
      simp only [Bool.or_eq_true, beq_iff_eq, Bool.not_eq_true'] at this
      rcases this with h' | h'
      · exact h'
      · rw [h] at h'; cases h'
  exact ⟨l, hl, hQl ▸ hQ, hbind, hfile, hne, hlp⟩

/-- What a bind was made from: the object its path resolved to, still there at step 0. -/
theorem bind_capture {pl : Plan} {w : World} {m : Mount} (hsits : pl.sits = true) (hf : FactsHold pl w)
    (hm : m ∈ pl.made) (hb : m.source.isBind = true) :
    ∃ o, w.fs 0 m.leads = some o ∧ w.capture m.path = some o := by
  obtain ⟨hsitsOn, _, _⟩ := sits_parts hsits
  obtain ⟨hmm, hns⟩ := mem_made hm
  have hsit := List.all_eq_true.1 hsitsOn m hmm
  cases hs : m.source with
  | own =>
    simp only [Plan.sitsOn, hs, Plan.bindsFrom, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true] at hsit
    simp only [Plan.skipped, hs, beq_eq_false_iff_ne, ne_eq] at hns
    have hpres : pl.facts.present m.path = true := by
      rcases hsit with h | ⟨h, _⟩
      · exact absurd h hns
      · exact h
    have hres : (m.path, m.path) ∈ pl.facts.resolutions := by
      have h := hpres
      simp only [Facts.present, Facts.plain, Bool.and_eq_true, List.contains_iff_mem] at h
      exact h.1
    have hleads : m.leads = m.path := by simp [Mount.leads, Mount.target?, hs]
    rw [hleads]
    exact hf.resolved m.path m.path hres hpres
  | alias t =>
    simp only [Plan.sitsOn, hs, Bool.and_eq_true, List.contains_iff_mem] at hsit
    simp only [Plan.skipped, hs, beq_eq_false_iff_ne, ne_eq] at hns
    have hpres : pl.facts.present t = true := by
      have h := hsit.2
      simp only [Plan.bindsFrom, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true] at h
      rcases h with h | ⟨h, _⟩
      · exact absurd h hns
      · exact h
    have hleads : m.leads = t := by simp [Mount.leads, Mount.target?, hs]
    rw [hleads]
    exact hf.resolved m.path t hsit.1 hpres
  | view v rel => simp [Source.isBind, hs] at hb

/-- A bind bubblewrap made is read-only or writable: a skipped one is not made, and the facts say
what a made one is bound from. -/
theorem made_bind_present {pl : Plan} {m : Mount} (hsits : pl.sits = true) (hm : m ∈ pl.made)
    (hb : m.source.isBind = true) : m.state.present = true := by
  obtain ⟨hsitsOn, _, _⟩ := sits_parts hsits
  obtain ⟨hmm, hns⟩ := mem_made hm
  have hsit := List.all_eq_true.1 hsitsOn m hmm
  cases hs : m.source with
  | own =>
    simp only [Plan.sitsOn, hs, Plan.bindsFrom, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true] at hsit
    simp only [Plan.skipped, hs, beq_eq_false_iff_ne, ne_eq] at hns
    rcases hsit with h | ⟨_, h⟩
    · exact absurd h hns
    · rcases h with h | h <;> simp [h, State.present]
  | alias t =>
    simp only [Plan.sitsOn, hs, Bool.and_eq_true, List.contains_iff_mem] at hsit
    simp only [Plan.skipped, hs, beq_eq_false_iff_ne, ne_eq] at hns
    have h := hsit.2
    simp only [Plan.bindsFrom, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true] at h
    rcases h with h | ⟨_, h⟩
    · exact absurd h hns
    · rcases h with h | h <;> simp [h, State.present]
  | view v rel => simp [Source.isBind, hs] at hb

/-- The state at step *i*: what the static check certified, since only a bind back on a view can
be gone, and then the view decides -- as the grants do. -/
theorem state_at {M : Matcher} {pl : Plan} {w : World} {i : Nat} (hwf : WellFormed M pl.layers)
    (hj : pl.jail.check = true) (hsits : pl.sits = true) (hk : Kernel M pl w) (ht : Trust pl w) (p : Path) :
    Agree ((pl.jailAt w i).built M p) (pl.jail.meaning M p) (pl.jail.nothingAt p) (pl.jail.belowLeaf p) := by
  have hstatic := sound (j := pl.jail) hwf hj p
  have hviews : viewsHold pl.jail = true := by
    simp only [Jail.check, Bool.and_eq_true] at hj
    exact hj.1.1.2
  rcases nearest_live (i := i) (p := p) hsits hk ht with ⟨hl, hn⟩ | ⟨m, hn, _, hl⟩ | ⟨m, v, hn, _, hl, hv, _⟩
  · have : (pl.jailAt w i).built M p = pl.jail.built M p := by
      unfold Jail.built
      rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl, show pl.jail.mounts = pl.made from rfl, hn]
      rfl
    rw [this]
    exact hstatic
  · have : (pl.jailAt w i).built M p = pl.jail.built M p := by
      unfold Jail.built
      rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl, show pl.jail.mounts = pl.made from rfl, hn]
      rfl
    rw [this]
    exact hstatic
  · left
    have hva : isViewAt (nearest (pl.jailAt w i).mounts p) = true := by
      rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl]
      simpa [isViewAt] using hv
    exact sound_view (j := pl.jailAt w i) hwf (viewsHold_jailAt hviews) hva

theorem base_of_root {pl : Plan} {m : Mount} (h : pl.footing m = some .root) : pl.base = .empty := by
  unfold Plan.footing at h
  split at h
  · split at h
    · rename_i hb
      exact beq_iff_eq.1 hb
    · split at h <;> cases h
  · rename_i P hP
    cases hs : P.source <;> simp only [hs] at h
    all_goals try cases h
    split at h
    · split at h <;> cases h
    · cases h

/-- For a whole run, the name a bind on the empty root leads to keeps naming what it did: nothing
outside touches it (trusted), and the jail cannot, no grant making it or a directory above it
writable. -/
theorem root_leads_stays {M : Matcher} {pl : Plan} {w : World} (hwf : WellFormed M pl.layers)
    (hj : pl.jail.check = true) (hsits : pl.sits = true)
    (hk : Kernel M pl w) (ht : Trust pl w) {m : Mount} (hm : m ∈ pl.made)
    (hroot : pl.footing m = some .root)
    (hstable : pl.stability.holds m.leads = true)
    (hnowrite : (prefixes m.leads).all
      (fun a => a == m.path || (!pl.grantsWriteAbove a && !pl.jail.belowLeaf a)) = true)
    (i : Nat) : w.fs i m.leads = w.fs 0 m.leads := by
  apply fs_stays hk
  intro k _
  cases hact : (w.step k).actor with
  | outside => exact ht.stable k m.leads hstable hact
  | jail =>
    cases htouch : (w.step k).op.touches m.leads with
    | false => rfl
    | true =>
      exfalso
      obtain ⟨x, hx, hxl⟩ := Op.touches_witness htouch
      have hw := hk.writes k hact x hx
      have hbase := base_of_root hroot
      have hx' := List.all_eq_true.1 hnowrite x (mem_prefixes.2 hxl)
      simp only [Bool.or_eq_true, Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at hx'
      rcases hx' with hxm | ⟨hnog, hnoleaf⟩
      · -- the bind's own mountpoint: the kernel refuses to move it
        have hlive : m ∈ pl.liveMounts w k := List.mem_filter.2 ⟨hm, by simp [Plan.live, hroot]⟩
        have := hk.mounts k hact m hlive
        rw [← hxm, Op.targets_touch hx] at this
        cases this
      rcases state_at (i := k) hwf hj hsits hk ht x with heq | ⟨hnothing, _⟩ | hleaf
      · -- the grants make x writable: a writable grant covers it, so one of its tops lies above x
        rw [hw] at heq
        unfold Jail.meaning at heq
        rcases writable_covers heq.symm with h | ⟨l, hl, hsays, hcov⟩
        · rw [show pl.jail.base = pl.base from rfl, hbase] at h
          cases h
        · obtain ⟨t, ht', htx⟩ := top_of_covers (hwf l hl) hcov
          have : pl.grantsWriteAbove x = true := by
            apply List.any_eq_true.2
            refine ⟨l, hl, ?_⟩
            rw [hsays]
            simp only [beq_self_eq_true, Bool.true_and, List.any_eq_true]
            exact ⟨t, ht', htx⟩
          rw [this] at hnog
          cases hnog
      · -- on the empty root with no mount above: absent, not writable
        unfold Jail.nothingAt at hnothing
        simp only [Bool.and_eq_true, Option.isNone_iff_eq_none] at hnothing
        have hnone : nearest (pl.liveMounts w k) x = none := by
          cases h : nearest (pl.liveMounts w k) x with
          | none => rfl
          | some u =>
            obtain ⟨hu, hux⟩ := nearest_spec h
            obtain ⟨u', hu'⟩ := nearest_exists (live_mem hu).1 hux
            rw [show pl.made = pl.jail.mounts from rfl, hnothing.2] at hu'
            cases hu'
        unfold Jail.built at hw
        rw [show (pl.jailAt w k).mounts = pl.liveMounts w k from rfl, hnone] at hw
        simp only [show (pl.jailAt w k).base = pl.base from rfl, hbase, Base.state] at hw
        cases hw
      · rw [hleaf] at hnoleaf
        cases hnoleaf

theorem nothingAt_none {pl : Plan} {p : Path} (h : pl.jail.nothingAt p = true) : nearest pl.made p = none := by
  unfold Jail.nothingAt at h
  simp only [Bool.and_eq_true, Option.isNone_iff_eq_none] at h
  exact h.2

/-- A live bind nearest *p* shows what the grants mean there. -/
theorem bind_shows {M : Matcher} {pl : Plan} {w : World} {i : Nat} {p : Path} {m : Mount}
    (hwf : WellFormed M pl.layers) (hj : pl.jail.check = true) (hsits : pl.sits = true)
    (hfooted : pl.footed = true) (hroot : pl.rootBindsStable = true)
    (hk : Kernel M pl w) (ht : Trust pl w) (hf : FactsHold pl w)
    (hn : nearest pl.made p = some m) (hl : nearest (pl.liveMounts w i) p = some m)
    (hb : m.source.isBind = true)
    (hseen : pl.content M w i p = (w.capture m.path).bind fun o => w.below i o (p.drop m.path.length))
    (hnamed : pl.named w i p = m.leads ++ p.drop m.path.length) :
    Shows pl w i p ((pl.jailAt w i).built M p) (pl.jail.meaning M p) (pl.content M w i p) (pl.named w i p) := by
  obtain ⟨hmm, hmp⟩ := nearest_spec hn
  obtain ⟨hml, _⟩ := nearest_spec hl
  have hlive := (live_mem hml).2
  obtain ⟨o, h0, hcap⟩ := bind_capture hsits hf hmm hb
  obtain ⟨s, hps⟩ := (prefixOf_iff).1 hmp
  have hdrop : p.drop m.path.length = s := by rw [hps, List.drop_left]
  rw [hcap, Option.bind_some, hdrop] at hseen
  rw [hdrop] at hnamed
  have hstate := state_at (i := i) hwf hj hsits hk ht p
  -- below a file, nothing shows
  have leaf_none : pl.jail.belowLeaf p = true → pl.content M w i p = none := by
    intro hleaf
    obtain ⟨l, _, hnl, _, hlfile, hlne, _⟩ := leaf_nearest hsits hleaf
    rw [hn] at hnl
    cases hnl
    have hfo := hf.file m.leads o hlfile h0
    have hs : s ≠ [] := fun h => hlne (by rw [hps, h, List.append_nil])
    rw [hseen]
    exact hk.leaf i o s hfo hs
  -- where the name still names the object, the bind shows the host by name
  have by_name : w.fs i m.leads = some o →
      Shows pl w i p ((pl.jailAt w i).built M p) (pl.jail.meaning M p) (pl.content M w i p) (pl.named w i p) := by
    intro hi
    have hbelow := hk.below i m.leads o s hi
    rcases hstate with heq | ⟨hnothing, _⟩ | hleaf
    · left
      -- the bind's own state, which is present: a made bind is read-only or writable
      have hbuilt : (pl.jailAt w i).built M p = m.state := by
        unfold Jail.built
        rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl]
        dsimp only
        cases hs : m.source with
        | own => rfl
        | alias t => rfl
        | view v rel => simp [Source.isBind, hs] at hb
      refine ⟨heq, fun _ => by rw [hseen, hbelow, hnamed], fun hnp => ?_⟩
      rw [← heq, hbuilt, made_bind_present hsits hmm hb] at hnp
      cases hnp
    · exfalso; rw [nothingAt_none hnothing] at hn; cases hn
    · right; right; left
      exact ⟨leaf_none hleaf, hleaf⟩
  obtain ⟨f, hfoot⟩ := footing_some hfooted hmm
  cases f with
  | fixedView =>
    exfalso
    unfold Plan.footing at hfoot
    split at hfoot
    · split at hfoot
      · cases hfoot
      · split at hfoot
        · rename_i hv
          simp only [Bool.and_eq_true, Mount.isView] at hv
          cases hs' : m.source <;> simp_all [Source.isBind]
        · cases hfoot
    · rename_i P hP
      cases hs' : P.source <;> simp only [hs'] at hfoot
      all_goals try cases hfoot
      split at hfoot
      · split at hfoot <;> cases hfoot
      · cases hfoot
  | onView =>
    -- bound back on a view, and live: the host still names the object at its path
    obtain ⟨_, _, hown⟩ := parent_of_onView hfoot
    have hleads : m.leads = m.path := by simp [Mount.leads, Mount.target?, hown]
    unfold Plan.live at hlive
    rw [hfoot] at hlive
    simp only [Bool.and_eq_true, beq_iff_eq] at hlive
    apply by_name
    rw [hleads, hlive.2, ← hleads]
    exact h0
  | root =>
    by_cases hsame : w.fs i m.leads = w.fs 0 m.leads
    · exact by_name (hsame.trans h0)
    · -- the host moved on from the name the bind was made from
      cases hlt : pl.lifetime with
      | run =>
        exfalso
        apply hsame
        simp only [Plan.rootBindsStable, hlt, Bool.or_eq_true] at hroot
        rcases hroot with h | h
        · cases h
        · have := List.all_eq_true.1 h m hmm
          simp only [hfoot, hb, Bool.and_self, Bool.not_true, Bool.false_or, Bool.and_eq_true, beq_self_eq_true] at this
          exact root_leads_stays hwf hj hsits hk ht hmm hfoot this.1 this.2 i
      | exec =>
        rcases hstate with heq | ⟨hnothing, _⟩ | hleaf
        · right; right; right
          refine ⟨heq, hlt, m, hml, hl, hfoot, hb, hsame, o, hcap, ?_⟩
          rw [hseen, hdrop]
        · exfalso; rw [nothingAt_none hnothing] at hn; cases hn
        · right; right; left
          exact ⟨leaf_none hleaf, hleaf⟩

/-- **Soundness over a run.** A plan the checker certifies, run on a kernel that behaves as
assumed and under the stability model, shows at every step and every path what its grants mean of
what is there then (`Shows`): the same state, and the object the host has at that name where the
state is present, nothing where it is not; nothing where the grants may not write; nothing below a
file; or, for one exec, a bind on the empty root the host has moved on from -- for every matcher
that keeps within its patterns' tops. -/
theorem run_sound {M : Matcher} {pl : Plan} {w : World} (hwf : WellFormed M pl.layers)
    (hc : pl.check = true) (hk : Kernel M pl w) (ht : Trust pl w) (hf : FactsHold pl w)
    (i : Nat) (p : Path) :
    Shows pl w i p ((pl.jailAt w i).built M p) (pl.jail.meaning M p) (pl.content M w i p) (pl.named w i p) := by
  simp only [Plan.check, Bool.and_eq_true] at hc
  obtain ⟨⟨⟨hj, hsits⟩, hfooted⟩, hroot⟩ := hc
  have hstate := state_at (i := i) hwf hj hsits hk ht p
  rcases nearest_live (i := i) (p := p) hsits hk ht with ⟨hl, hn⟩ | ⟨m, hn, _, hl⟩ | ⟨m, v, hn, _, hl, hv, _⟩
  · -- no mount at or above p: the base
    have hnamed : pl.named w i p = p := by unfold Plan.named; rw [hl]
    have hbuilt : (pl.jailAt w i).built M p = pl.base.state := by
      unfold Jail.built
      rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl]
      rfl
    rw [hnamed]
    cases hb : pl.base with
    | empty =>
      have hseen : pl.content M w i p = none := by unfold Plan.content; rw [hl]; dsimp only; rw [hb]
      rcases hstate with heq | ⟨_, hmw⟩ | hleaf
      · left
        refine ⟨heq, fun hpres => ?_, fun _ => hseen⟩
        rw [← heq, hbuilt, hb] at hpres
        simp [Base.state, State.present] at hpres
      · right; left
        exact ⟨hseen, by rw [hbuilt, hb]; rfl, hmw⟩
      · right; right; left
        exact ⟨hseen, hleaf⟩
    | host wr =>
      have hseen : pl.content M w i p = w.fs i p := by unfold Plan.content; rw [hl]; dsimp only; rw [hb]
      rcases hstate with heq | ⟨hnothing, _⟩ | hleaf
      · left
        refine ⟨heq, fun _ => hseen, fun hnp => ?_⟩
        rw [← heq, hbuilt, hb] at hnp
        cases wr <;> simp [Base.state, State.present] at hnp
      · exfalso
        unfold Jail.nothingAt at hnothing
        simp only [Bool.and_eq_true, List.any_eq_true] at hnothing
        obtain ⟨⟨e, he, _⟩, _⟩ := hnothing
        have := missing_base_empty hsits hfooted he
        rw [hb] at this
        cases this
      · exfalso
        obtain ⟨l, _, hnl, _⟩ := leaf_nearest hsits hleaf
        rw [hn] at hnl
        cases hnl
  · -- the nearest mount is live
    obtain ⟨hmm, hmp⟩ := nearest_spec hn
    cases hs : m.source with
    | view v rel =>
      -- the view shows the host by name where it decides the path present, nothing otherwise
      have hseen : pl.content M w i p = if ((pl.jailAt w i).built M p).present then w.fs i p else none := by
        unfold Plan.content; rw [hl]; dsimp only; rw [hs]
      have hnamed : pl.named w i p = p := by unfold Plan.named; rw [hl]; dsimp only; rw [hs]
      rw [hnamed]
      rcases hstate with heq | ⟨hnothing, _⟩ | hleaf
      · left
        rw [heq] at hseen
        exact ⟨heq, fun hp => by simp [hseen, hp], fun hnp => by simp [hseen, hnp]⟩
      · exfalso; rw [nothingAt_none hnothing] at hn; cases hn
      · exfalso
        obtain ⟨l, _, hnl, hlb, _⟩ := leaf_nearest hsits hleaf
        rw [hn] at hnl
        cases hnl
        simp [Source.isBind, hs] at hlb
    | own =>
      apply bind_shows hwf hj hsits hfooted hroot hk ht hf hn hl (by simp [Source.isBind, hs])
      · unfold Plan.content; rw [hl]; dsimp only; rw [hs]
      · unfold Plan.named; rw [hl]; dsimp only; rw [hs]
        simp only [Mount.leads, Mount.target?, hs, Option.getD_none]
        obtain ⟨s, hps⟩ := (prefixOf_iff).1 hmp
        rw [hps, List.drop_left]
    | alias t =>
      apply bind_shows hwf hj hsits hfooted hroot hk ht hf hn hl (by simp [Source.isBind, hs])
      · unfold Plan.content; rw [hl]; dsimp only; rw [hs]
      · unfold Plan.named; rw [hl]; dsimp only; rw [hs]
        simp [Mount.leads, Mount.target?, hs]
  · -- the nearest mount is a bind back the host has taken from under: its view decides
    have hsv : ∃ v' rel, v.source = .view v' rel := by
      unfold Mount.isView at hv
      cases hsv : v.source <;> simp_all
    obtain ⟨v', rel, hsv⟩ := hsv
    have hseen : pl.content M w i p = if ((pl.jailAt w i).built M p).present then w.fs i p else none := by
      unfold Plan.content; rw [hl]; dsimp only; rw [hsv]
    have hnamed : pl.named w i p = p := by unfold Plan.named; rw [hl]; dsimp only; rw [hsv]
    have hviews : viewsHold pl.jail = true := by
      simp only [Jail.check, Bool.and_eq_true] at hj
      exact hj.1.1.2
    have hva : isViewAt (nearest (pl.jailAt w i).mounts p) = true := by
      rw [show (pl.jailAt w i).mounts = pl.liveMounts w i from rfl, hl]
      simpa [isViewAt] using hv
    have hsound : (pl.jailAt w i).built M p = pl.jail.meaning M p :=
      sound_view (j := pl.jailAt w i) hwf (viewsHold_jailAt hviews) hva
    left
    rw [hnamed]
    rw [hsound] at hseen
    exact ⟨hsound, fun hp => by simp [hseen, hp], fun hnp => by simp [hseen, hnp]⟩

end Place
