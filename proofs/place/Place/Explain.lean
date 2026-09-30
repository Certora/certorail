import Place.Plan

/-!
Why the checker refused a plan, in words, obligation by obligation: for the refusal's message. The
verdict is `Plan.check`'s alone; nothing here is proved, and nothing here decides.
-/
namespace Place

def render (p : Path) : String := "/" ++ "/".intercalate p

def State.word : State → String
  | .absent => "absent"
  | .readOnly => "read-only"
  | .writable => "writable"
  | .hidden => "hidden"

def outOfOrder : List Mount → List (Mount × Mount)
  | [] => []
  | m :: ms => (ms.filter (fun m' => prefixOf m'.path m.path)).map (m, ·) ++ outOfOrder ms

/-- Why *m* has no footing. -/
def Plan.unfooted (pl : Plan) (m : Mount) : String :=
  match parentMount pl.made m.path with
  | none =>
    if m.isView then s!"the view at {render m.path} sits on the host at a name something could replace: "
        ++ "a view on the host base sits only where nothing but root replaces the name"
    else s!"the bind of {render m.path} sits on the host base: when the name under it is replaced, it "
        ++ "detaches or goes with its directory, and the base shows through -- a mount sits on the "
        ++ "empty root, on a view, or is a view at a name nothing replaces"
  | some p =>
    match p.source with
    | .view _ _ =>
      if m.isView then s!"the view at {render m.path} sits inside the view at {render p.path}"
      else s!"the bind back of {render m.path} on the view at {render p.path} has, on the way, a directory "
        ++ "the view's daemon may move, which would not carry the bind along"
    | _ => s!"the mount at {render m.path} is nested in the bind of {render p.path}: replaced from outside, "
        ++ "it detaches into the bind or moves to a name the grants did not give"

def Plan.reasons (pl : Plan) : List String :=
  let j := pl.jail
  let fresh := if freshIsFresh j then [] else ["a path names / as a component"]
  let views := (j.mounts.filter (!viewHolds j ·)).map fun m =>
    s!"the view at {render m.path} is not what the grants make it: mounted at its own path, "
      ++ "holding every layer that reaches its directory, writable wherever it could grant a write"
  let patterns := j.layers.flatMap fun l =>
    match l.region with
    | .pattern k ts =>
      (ts.filter fun t => !(viewedTop j t || (l.says.isRestriction && j.bare t))).map fun t =>
        s!"the pattern {k} reaches {render t}, which no view holds"
    | _ => []
  let agreement := ((representatives j).filter (!agreesAt j ·)).map fun r =>
    s!"at {render r} the jail is {(j.built noPatterns r).word}, and the grants make it "
      ++ (j.meaning noPatterns r).word
  let sits := (pl.mounts.filter (!pl.sitsOn ·)).map fun m =>
    match m.source with
    | .own => s!"the bind of {render m.path}: its source is neither missing nor, as the facts "
        ++ "record it, a file or a directory reached without a link, bound read-only or writable"
    | .alias t => s!"the bind of {render m.path} as it leads: the facts do not record it leading "
        ++ s!"to {render t}, or {render t} as missing, a file or a directory, bound read-only or writable"
    | .view _ _ => s!"the view mounted at {render m.path}: the facts do not record a directory "
        ++ "there reached without a link"
  let alone := (pl.mounts.filter (!pl.aliasAlone ·)).map fun m =>
    s!"the bind of {render m.path} as it leads shares its branch with another mount, or sits on "
      ++ "the host's root: it must stand alone on the empty one"
  let order := (outOfOrder pl.mounts).map fun (m, m') =>
    s!"the mount at {render m'.path} comes after the one at {render m.path}, at or below it"
  let footed := (pl.mounts.filter fun m => (pl.footing m).isNone).map pl.unfooted
  let stable := if pl.rootBindsStable then [] else (pl.made.filter fun m =>
      pl.footing m == some .root && m.source.isBind
        && !(pl.stability.holds m.leads
             && (prefixes m.leads).all fun a => a == m.path || (!pl.grantsWriteAbove a && !pl.jail.belowLeaf a))).map fun m =>
    s!"the bind of {render m.path} leads to {render m.leads}, which something could replace during the run: "
      ++ "for a whole run a bind on the empty root leads only to a stable name no grant makes writable"
  fresh ++ views ++ patterns ++ agreement ++ sits ++ alone ++ order ++ footed ++ stable

end Place
