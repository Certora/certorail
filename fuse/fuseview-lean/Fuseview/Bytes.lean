/-!
Bytes as the kernel and the system calls speak them: names never decoded (a regex decodes one for
itself), and the little-endian fields of the FUSE protocol read and written in place.
-/
namespace Fuseview

/-- A path component, or any byte string a system call takes, as the bytes it is. -/
structure Name where
  bytes : ByteArray
  deriving Inhabited

/-- Byte for byte -- as the arrays behind them, whose equality test is lawful, so a proof may
conclude two names are the same (`Name.eq_of_beq`). -/
def bytesEq (a b : ByteArray) : Bool := a.data == b.data

partial def fnvFrom (b : ByteArray) (i : Nat) (h : UInt64) : UInt64 :=
  if i ≥ b.size then h else fnvFrom b (i + 1) ((h ^^^ b[i]!.toUInt64) * 0x100000001b3)

instance : BEq Name := ⟨fun a b => bytesEq a.bytes b.bytes⟩

theorem Name.eq_of_beq {a b : Name} (h : (a == b) = true) : a = b := by
  obtain ⟨⟨da⟩⟩ := a
  obtain ⟨⟨db⟩⟩ := b
  have : da = db := beq_iff_eq.1 h
  subst this
  rfl
instance : Hashable Name := ⟨fun n => fnvFrom n.bytes 0 0xcbf29ce484222325⟩

def Name.ofString (s : String) : Name := ⟨s.toUTF8⟩

/-- Does *b* end with *suffix*? -/
def endsWith (b suffix : ByteArray) : Bool :=
  b.size ≥ suffix.size && bytesEq (b.extract (b.size - suffix.size) b.size) suffix

/-- *names* joined under *base*, as the path a directory's descriptor is reported at. -/
def joinPath (base : ByteArray) (names : Array Name) : ByteArray :=
  names.foldl (init := base) fun acc n =>
    let acc := if acc.size > 0 && acc[acc.size - 1]! == 47 then acc else acc.push 47
    acc ++ n.bytes

/-- The components of an absolute path, as its string spells them. -/
def splitPath (path : String) : Array Name :=
  ((path.splitOn "/").filter (· ≠ "")).toArray.map Name.ofString

-- little-endian fields --------------------------------------------------------------------------

@[inline] def rd16 (b : ByteArray) (i : Nat) : UInt16 :=
  b[i]!.toUInt16 ||| (b[i + 1]!.toUInt16 <<< 8)

@[inline] def rd32 (b : ByteArray) (i : Nat) : UInt32 :=
  b[i]!.toUInt32 ||| (b[i + 1]!.toUInt32 <<< 8) ||| (b[i + 2]!.toUInt32 <<< 16) ||| (b[i + 3]!.toUInt32 <<< 24)

@[inline] def rd64 (b : ByteArray) (i : Nat) : UInt64 :=
  (rd32 b i).toUInt64 ||| ((rd32 b (i + 4)).toUInt64 <<< 32)

@[inline] def wr16 (b : ByteArray) (v : UInt16) : ByteArray :=
  (b.push v.toUInt8).push (v >>> 8).toUInt8

@[inline] def wr32 (b : ByteArray) (v : UInt32) : ByteArray :=
  (((b.push v.toUInt8).push (v >>> 8).toUInt8).push (v >>> 16).toUInt8).push (v >>> 24).toUInt8

@[inline] def wr64 (b : ByteArray) (v : UInt64) : ByteArray :=
  wr32 (wr32 b v.toUInt32) (v >>> 32).toUInt32

partial def zeros (b : ByteArray) (n : Nat) : ByteArray :=
  if n == 0 then b else zeros (b.push 0) (n - 1)

/-- Overwrite the four bytes at *i* with *v*. -/
def set32 (b : ByteArray) (i : Nat) (v : UInt32) : ByteArray :=
  (((b.set! i v.toUInt8).set! (i + 1) (v >>> 8).toUInt8).set! (i + 2) (v >>> 16).toUInt8).set! (i + 3) (v >>> 24).toUInt8

partial def nulFrom (b : ByteArray) (j : Nat) : Option Nat :=
  if j ≥ b.size then none else if b[j]! == 0 then some j else nulFrom b (j + 1)

/-- The NUL-terminated string at *i* in *b*, and the index past its NUL; none if it has none. -/
def cstr (b : ByteArray) (i : Nat) : Option (Name × Nat) :=
  (nulFrom b i).map fun j => (⟨b.extract i j⟩, j + 1)

end Fuseview
