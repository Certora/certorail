"""Flatten: bubblewrap's placed items, in application order, turned into the fewest mounts that
leave every path as the items would, ancestors first -- the order bubblewrap needs, since a later
mount of an ancestor hides earlier mounts below it.

A mount has a state (read-only or writable) and a source: the host's own path (``Own``), or a
view (``Through``). A mount is kept only where its state or its source differs from what it
would inherit from the nearest kept mount above it, or from the base. So no ``--ro-bind /usr
/usr`` under a read-only ``/``; and a bind under a view is always kept, its source being the
host's where the view's is the daemon's. Run at spawn time, over the recipe's items and that
exec's executable and scratch directory.
"""
import pathlib
from collections.abc import Sequence
from dataclasses import dataclass

from certorail.sandbox.grants import Access, State, within
from certorail.sandbox.place import Base, Bind, EmptyBase, HostBase, Placed, Serve, Served

__all__ = ["Mount", "Nothing", "Own", "Through", "flatten", "state_of"]


@dataclass(frozen=True)
class Own:
    """The host's own path."""


@dataclass(frozen=True)
class Through:
    """*rel* inside *view*."""

    view: Serve
    rel: pathlib.PurePosixPath


@dataclass(frozen=True)
class Nothing:
    """Nothing is there: the policy world's empty base."""


type Source = Own | Through | Nothing


@dataclass(frozen=True)
class Mount:
    path: pathlib.Path
    state: State
    source: Own | Through


def _state(access: Access) -> State:
    return State.WRITABLE if access is Access.WRITABLE else State.READ_ONLY


def _base(base: Base) -> tuple[State, Source]:
    match base:
        case HostBase(writable=w):
            return (State.WRITABLE if w else State.READ_ONLY), Own()
        case EmptyBase():
            return State.ABSENT, Nothing()


def _carried(source: Source, top: pathlib.Path, path: pathlib.Path) -> Source:
    """What *source*, mounted at *top*, shows at *path* below it."""
    match source:
        case Through(view=v, rel=rel):
            return Through(v, rel / path.relative_to(top))
        case Own() | Nothing():
            return source


def _item(item: Placed) -> tuple[pathlib.Path, State, Own | Through]:
    match item:
        case Bind(path=p, access=a):
            return p, _state(a), Own()
        case Served(view=v, access=a):
            return v.directory, _state(a), Through(v, pathlib.PurePosixPath("."))


def state_of(base: Base, items: Sequence[Placed], path: pathlib.Path) -> tuple[State, Source]:
    """What *path* is, and where its contents come from, with *items* applied in order: the last
    item at or above it wins."""
    state, source = _base(base)
    for item in items:
        top, s, src = _item(item)
        if within(path, top):
            state, source = s, _carried(src, top, path)
    return state, source


def flatten(base: Base, items: Sequence[Placed]) -> tuple[Mount, ...]:
    tops = sorted(dict.fromkeys(_item(i)[0] for i in items), key=lambda p: len(p.parts))
    kept: list[Mount] = []
    for path in tops:
        above = [m for m in kept if m.path != path and within(path, m.path)]
        if above:
            nearest = max(above, key=lambda m: len(m.path.parts))
            inherited: tuple[State, Source] = (nearest.state, _carried(nearest.source, nearest.path, path))
        else:
            inherited = _base(base)
        state, source = state_of(base, items, path)
        if (state, source) != inherited:
            assert not isinstance(source, Nothing), "an item is always a mount"
            kept.append(Mount(path, state, source))
    return tuple(kept)
