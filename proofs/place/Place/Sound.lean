import Place.Check

/-!
The checker is sound: a jail it certifies builds, at every path, what its grants mean -- for every
matcher that keeps within its patterns' tops, so for whatever the view's daemon runs.

The proof splits on the mount nearest the path. Under a view, the view decides by exactly the
layers that can decide there (`viewLayers_agree`), and the mount's state takes nothing from it.
Anywhere else, no pattern covers the path (obligation 3), and the path has a representative with
the same breakpoints at or above it and the same mount nearest it, where the checker compared the
two directly.
-/
namespace Place

theorem nearest_spec {ms : List Mount} {p : Path} {m : Mount} (h : nearest ms p = some m) :
    m ∈ ms ∧ prefixOf m.path p = true :=
  List.mem_filter.1 (argmax_mem h)

theorem nearest_longest {ms : List Mount} {p : Path} {m m' : Mount} (h : nearest ms p = some m)
    (hm' : m' ∈ ms) (hp : prefixOf m'.path p = true) : m'.path.length ≤ m.path.length :=
  argmax_max h m' (List.mem_filter.2 ⟨hm', hp⟩)

theorem nearest_exists {ms : List Mount} {p : Path} {m' : Mount} (hm' : m' ∈ ms)
    (hp : prefixOf m'.path p = true) : ∃ m, nearest ms p = some m :=
  argmax_isSome (List.mem_filter.2 ⟨hm', hp⟩)

theorem nearest_congr {ms : List Mount} {p r : Path}
    (h : ∀ m ∈ ms, prefixOf m.path p = prefixOf m.path r) : nearest ms p = nearest ms r := by
  unfold nearest
  rw [List.filter_congr h]

theorem subtree_mem_breakpoints {j : Jail} {l : Layer} {t : Path} (hl : l ∈ j.layers)
    (hr : l.region = .subtree t) : t ∈ breakpoints j :=
  List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _
    (List.mem_filterMap.2 ⟨l, hl, by simp [hr]⟩)))

theorem exactly_mem_breakpoints {j : Jail} {l : Layer} {t : Path} (hl : l ∈ j.layers)
    (hr : l.region = .exactly t) : t ∈ breakpoints j :=
  List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _
    (List.mem_filterMap.2 ⟨l, hl, by simp [hr]⟩)))

theorem mount_mem_breakpoints {j : Jail} {m : Mount} (hm : m ∈ j.mounts) : m.path ∈ breakpoints j :=
  List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ (List.mem_map.2 ⟨m, hm, rfl⟩)))

theorem missing_mem_breakpoints {j : Jail} {e : Path × Path} (he : e ∈ j.missing) :
    e.1 ∈ breakpoints j :=
  List.mem_append_left _ (List.mem_append_right _ (List.mem_map.2 ⟨e, he, rfl⟩))

theorem leaf_mem_breakpoints {j : Jail} {e : Path × Path} (he : e ∈ j.leaves) :
    e.1 ∈ breakpoints j :=
  List.mem_append_right _ (List.mem_map.2 ⟨e, he, rfl⟩)

theorem mem_tree {j : Jail} {b : Path} (hb : b ∈ breakpoints j) : b ∈ tree j :=
  List.mem_cons_of_mem _ (List.mem_flatMap.2 ⟨b, hb, mem_prefixes.2 (prefixOf_refl b)⟩)

/-- Where no view is nearest, a pattern covers only as a restriction at a bare top. -/
theorem pattern_free {M : Matcher} {j : Jail} {p : Path} (hwf : WellFormed M j.layers)
    (hpv : patternsViewed j = true) (hnv : isViewAt (nearest j.mounts p) = false)
    {l : Layer} (hl : l ∈ j.layers) {k : String} {ts : List Path} (hr : l.region = .pattern k ts)
    (hc : l.covers M p = true) :
    l.says.isRestriction = true ∧ ∃ t, prefixOf t p = true ∧ j.bare t = true := by
  obtain ⟨t, ht, htp⟩ := top_of_covers (hwf l hl) hc
  rw [hr] at ht
  simp only [Region.tops] at ht
  have h : (viewedTop j t || (l.says.isRestriction && j.bare t)) = true := by
    have := List.all_eq_true.1 hpv l hl
    rw [hr] at this
    exact List.all_eq_true.1 this t ht
  simp only [Bool.or_eq_true, Bool.and_eq_true] at h
  rcases h with hvt | ⟨hrest, hbare⟩
  · exfalso
    simp only [viewedTop, Bool.and_eq_true, List.all_eq_true, List.any_eq_true] at hvt
    obtain ⟨hbelow, m₀, hm₀, ⟨_, hm₀t⟩, habove⟩ := hvt
    obtain ⟨m, hm⟩ := nearest_exists hm₀ (prefixOf_trans hm₀t htp)
    obtain ⟨hmms, hmp⟩ := nearest_spec hm
    have hlen := nearest_longest hm hm₀ (prefixOf_trans hm₀t htp)
    rw [hm] at hnv
    simp only [isViewAt] at hnv
    rcases prefixOf_total htp hmp with htm | hmt
    · have := hbelow m hmms
      simp [htm, hnv] at this
    · have := habove m hmms
      simp [hmt, hnv] at this
      omega
  · exact ⟨hrest, t, htp, hbare⟩

/-- A path's representative: itself where it is a prefix of some breakpoint, else its longest
prefix that is, with the fresh name after it. -/
def rep (j : Jail) (p : Path) : Path :=
  match argmax List.length ((prefixes p).filter fun q => decide (q ∈ tree j)) with
  | some q => if q = p then p else q ++ [fresh]
  | none => p

theorem rep_cases (j : Jail) (p : Path) : ∃ q, q ∈ tree j ∧ prefixOf q p = true ∧
    (∀ q' ∈ tree j, prefixOf q' p = true → q'.length ≤ q.length) ∧
    rep j p = (if q = p then p else q ++ [fresh]) := by
  have hnil : [] ∈ (prefixes p).filter fun q => decide (q ∈ tree j) :=
    List.mem_filter.2 ⟨mem_prefixes.2 (prefixOf_nil p), by simp [tree]⟩
  obtain ⟨q, hq⟩ := argmax_isSome (f := List.length) hnil
  have hqm := List.mem_filter.1 (argmax_mem hq)
  refine ⟨q, of_decide_eq_true hqm.2, mem_prefixes.1 hqm.1, ?_, ?_⟩
  · intro q' hq' hq'p
    exact argmax_max hq q' (List.mem_filter.2 ⟨mem_prefixes.2 hq'p, decide_eq_true hq'⟩)
  · simp only [rep, hq]

theorem rep_mem (j : Jail) (p : Path) : rep j p ∈ representatives j := by
  obtain ⟨q, hqt, hqp, _, hrep⟩ := rep_cases j p
  rw [hrep]
  split
  · rename_i h
    subst h
    exact List.mem_append_left _ hqt
  · exact List.mem_append_right _ (List.mem_map.2 ⟨q, hqt, rfl⟩)

/-- A representative lies at or below the same breakpoints as its path, and is one exactly when
its path is. -/
theorem rep_signature {j : Jail} {p b : Path} (hf : freshIsFresh j = true) (hb : b ∈ breakpoints j) :
    prefixOf b p = prefixOf b (rep j p) ∧ (b = p ↔ b = rep j p) := by
  obtain ⟨q, hqt, hqp, hmax, hrep⟩ := rep_cases j p
  rw [hrep]
  split
  · exact ⟨rfl, Iff.rfl⟩
  · rename_i hne
    have hfb : fresh ∉ b := of_decide_eq_true (List.all_eq_true.1 hf b hb)
    refine ⟨?_, ?_⟩
    · apply Bool.eq_iff_iff.2
      constructor
      · intro hbp
        have hbq : prefixOf b q = true :=
          prefixOf_of_length_le hbp hqp (hmax b (mem_tree hb) hbp)
        exact prefixOf_trans hbq (prefixOf_append q [fresh])
      · intro h
        exact prefixOf_trans (prefixOf_of_prefixOf_snoc hfb h) hqp
    · apply iff_of_false
      · intro h
        subst h
        exact hne (eq_of_prefixOf_of_length_le hqp (hmax b (mem_tree hb) (prefixOf_refl b)))
      · intro h
        exact hfb (h ▸ List.mem_append_right q (List.mem_singleton_self fresh))

theorem sound_view {M : Matcher} {j : Jail} {p : Path} (hwf : WellFormed M j.layers)
    (hviews : viewsHold j = true) (hv : isViewAt (nearest j.mounts p) = true) :
    j.built M p = j.meaning M p := by
  cases hn : nearest j.mounts p with
  | none => rw [hn] at hv; simp [isViewAt] at hv
  | some m =>
    rw [hn] at hv
    obtain ⟨hmms, hmp⟩ := nearest_spec hn
    have hvh := List.all_eq_true.1 hviews m hmms
    unfold Jail.built
    rw [hn]
    dsimp only
    simp only [isViewAt, Mount.isView] at hv
    cases hs : m.source with
    | own => simp [hs] at hv
    | alias t => simp [hs] at hv
    | view v rel =>
      dsimp only
      simp only [viewHolds, hs] at hvh
      cases hview : j.views[v]? with
      | none => simp [hview] at hvh
      | some view =>
        dsimp only
        rw [hview] at hvh
        simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, Bool.not_eq_true'] at hvh
        obtain ⟨⟨hdir, hlayers⟩, hstate⟩ := hvh
        have hdir' : prefixOf view.dir m.path = true := hdir ▸ prefixOf_append view.dir rel
        have hdec : stateFrom M .absent view.layers p = j.meaning M p := by
          rw [hlayers]
          exact viewLayers_agree hwf (prefixOf_trans hdir' hmp)
        simp only [hdec]
        rcases hstate with hw | ⟨_, hnw⟩
        · simp [cap, hw]
        · have hne : j.meaning M p ≠ .writable := by
            intro h
            rw [← hdec] at h
            rcases writable_of_stateFrom h with h' | ⟨l, hl, hsays⟩
            · cases h'
            · have : hasWritableGrant view.layers = true :=
                List.any_eq_true.2 ⟨l, hl, by simp [hsays]⟩
              rw [this] at hnw
              cases hnw
          simp [cap, hne]

theorem sound_elsewhere {M : Matcher} {j : Jail} {p : Path} (hwf : WellFormed M j.layers)
    (hfresh : freshIsFresh j = true) (hpv : patternsViewed j = true)
    (hagree : agreesAtRepresentatives j = true) (hnv : isViewAt (nearest j.mounts p) = false) :
    Agree (j.built M p) (j.meaning M p) (j.nothingAt p) (j.belowLeaf p) := by
  have hsig : ∀ b ∈ breakpoints j, prefixOf b p = prefixOf b (rep j p) ∧ (b = p ↔ b = rep j p) :=
    fun b hb => rep_signature hfresh hb
  have hnear : nearest j.mounts p = nearest j.mounts (rep j p) :=
    nearest_congr fun m hm => (hsig m.path (mount_mem_breakpoints hm)).1
  have hnvr : isViewAt (nearest j.mounts (rep j p)) = false := hnear ▸ hnv
  have hr : Agree (j.built noPatterns (rep j p)) (j.meaning noPatterns (rep j p))
      (j.nothingAt (rep j p)) (j.belowLeaf (rep j p)) := by
    have := List.all_eq_true.1 hagree (rep j p) (rep_mem j p)
    simp only [agreesAt, hnvr, Bool.false_or, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true,
      bne_iff_ne, ne_eq] at this
    rcases this with (h | ⟨h₁, h₂⟩) | h
    · exact Or.inl h
    · exact Or.inr (Or.inl ⟨h₁, h₂⟩)
    · exact Or.inr (Or.inr h)
  have hmissing : j.nothingAt p = j.nothingAt (rep j p) ∧ j.belowLeaf p = j.belowLeaf (rep j p) := by
    unfold Jail.nothingAt Jail.belowLeaf
    rw [hnear]
    have hmiss : j.missing.any (prefixOf ·.1 p) = j.missing.any (prefixOf ·.1 (rep j p)) := by
      apply Bool.eq_iff_iff.2
      simp only [List.any_eq_true]
      constructor
      · rintro ⟨e, he, hep⟩
        exact ⟨e, he, (hsig e.1 (missing_mem_breakpoints he)).1 ▸ hep⟩
      · rintro ⟨e, he, hep⟩
        exact ⟨e, he, (hsig e.1 (missing_mem_breakpoints he)).1 ▸ hep⟩
    have hleaf : (j.leaves.any fun e => prefixOf e.1 p && e.1 != p)
        = j.leaves.any fun e => prefixOf e.1 (rep j p) && e.1 != rep j p := by
      apply Bool.eq_iff_iff.2
      simp only [List.any_eq_true, Bool.and_eq_true, bne_iff_ne, ne_eq]
      constructor
      · rintro ⟨e, he, hep, hne⟩
        have hs := hsig e.1 (leaf_mem_breakpoints he)
        exact ⟨e, he, hs.1 ▸ hep, fun h => hne (hs.2.mpr h)⟩
      · rintro ⟨e, he, hep, hne⟩
        have hs := hsig e.1 (leaf_mem_breakpoints he)
        exact ⟨e, he, hs.1 ▸ hep, fun h => hne (hs.2.mp h)⟩
    exact ⟨by rw [hmiss], hleaf⟩
  have hbuilt : j.built M p = j.built noPatterns (rep j p) := by
    unfold Jail.built
    rw [← hnear]
    cases hn : nearest j.mounts p with
    | none => rfl
    | some m =>
      dsimp only
      rw [hn] at hnv
      simp only [isViewAt, Mount.isView] at hnv
      cases hs : m.source with
      | own => rfl
      | alias t => rfl
      | view v rel => simp [hs] at hnv
  -- a literal layer covers the path and its representative alike
  have hlit : ∀ l ∈ j.layers, (∀ k ts, l.region ≠ .pattern k ts) →
      l.covers M p = l.covers noPatterns (rep j p) := by
    intro l hl hnp
    unfold Layer.covers
    cases hreg : l.region with
    | subtree t =>
      simp only [Region.covers]
      exact (hsig t (subtree_mem_breakpoints hl hreg)).1
    | exactly t =>
      have hb := hsig t (exactly_mem_breakpoints hl hreg)
      simp only [Region.covers]
      split
      · exact hb.1
      · apply Bool.eq_iff_iff.2
        simp only [beq_iff_eq]
        exact hb.2
    | pattern k ts => exact absurd hreg (hnp k ts)
  have hmean : j.meaning M p = j.meaning noPatterns (rep j p) := by
    cases hany : j.layers.any (fun l => l.region.isPattern && l.covers M p) with
    | true =>
      -- a pattern covers the path: a restriction at a bare top, where no grant covers it
      obtain ⟨l, hl, hlc⟩ := List.any_eq_true.1 hany
      simp only [Bool.and_eq_true] at hlc
      obtain ⟨hpat, hc⟩ := hlc
      cases hr : l.region with
      | subtree t => simp [Region.isPattern, hr] at hpat
      | exactly t => simp [Region.isPattern, hr] at hpat
      | pattern k ts =>
        obtain ⟨_, t, htp, hbare⟩ := pattern_free hwf hpv hnv hl hr hc
        simp only [Jail.bare, Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at hbare
        obtain ⟨hbase, hnog⟩ := hbare
        have hgrant : ∀ g ∈ j.layers, g.says.isRestriction = false → overlaps g.region t = false := by
          intro g hg hgr
          cases ho : overlaps g.region t with
          | false => rfl
          | true =>
            have : (j.layers.any fun g => !g.says.isRestriction && overlaps g.region t) = true :=
              List.any_eq_true.2 ⟨g, hg, by simp [hgr, ho]⟩
            rw [this] at hnog
            cases hnog
        have hnotM : ∀ g ∈ j.layers, g.says.isRestriction = false → g.covers M p = false := by
          intro g hg hgr
          cases hcg : g.covers M p with
          | false => rfl
          | true =>
            exfalso
            obtain ⟨u, hu, hup⟩ := top_of_covers (hwf g hg) hcg
            have : overlaps g.region t = true :=
              List.any_eq_true.2 ⟨u, hu, by rcases prefixOf_total hup htp with h | h <;> simp [h]⟩
            rw [hgrant g hg hgr] at this
            cases this
        have hnotN : ∀ g ∈ j.layers, g.says.isRestriction = false →
            g.covers noPatterns (rep j p) = false := by
          intro g hg hgr
          cases hreg : g.region with
          | pattern k' ts' => simp [Layer.covers, Region.covers, hreg, noPatterns]
          | subtree t' =>
            rw [← hlit g hg (by simp [hreg])]
            exact hnotM g hg hgr
          | exactly t' =>
            rw [← hlit g hg (by simp [hreg])]
            exact hnotM g hg hgr
        unfold Jail.meaning
        rw [hbase]
        simp only [Base.state]
        rw [absent_of_no_grant hnotM, absent_of_no_grant hnotN]
    | false =>
      -- no pattern covers the path: every layer covers it and its representative alike
      unfold Jail.meaning
      apply stateFrom_congr
      intro l hl
      have hno := List.any_eq_false.1 hany l hl
      cases hr : l.region with
      | pattern k ts =>
        have hf : l.covers M p = false := by
          cases hc : l.covers M p with
          | false => rfl
          | true => exact absurd (by simp [Region.isPattern, hr, hc]) hno
        rw [hf]
        simp [Layer.covers, Region.covers, hr, noPatterns]
      | subtree t => exact hlit l hl (by simp [hr])
      | exactly t => exact hlit l hl (by simp [hr])
  rw [hbuilt, hmean, hmissing.1, hmissing.2]
  exact hr

/-- **Soundness.** A jail the checker certifies builds, at every path, what its grants mean -- or,
where nothing is, nothing either may write, or where nothing can be, anything -- for every matcher
that keeps within its patterns' tops. -/
theorem sound {M : Matcher} {j : Jail} (hwf : WellFormed M j.layers) (hc : j.check = true) (p : Path) :
    Agree (j.built M p) (j.meaning M p) (j.nothingAt p) (j.belowLeaf p) := by
  simp only [Jail.check, Bool.and_eq_true] at hc
  obtain ⟨⟨⟨hfresh, hviews⟩, hpv⟩, hagree⟩ := hc
  cases hv : isViewAt (nearest j.mounts p) with
  | true => exact Or.inl (sound_view hwf hviews hv)
  | false => exact sound_elsewhere hwf hfresh hpv hagree hv

end Place
