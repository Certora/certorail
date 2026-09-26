//! The filter (`fuseview.Filter`, over `grants.covers` and `grants.after`): the layers a view
//! holds, asked about concrete paths below the directory it serves. A pattern is matched
//! component by component, as the analysis' ordering matches one whose other side is a real path
//! (`analysis.location_le`); a regex component is Python's `re.fullmatch`, here fancy-regex's.
//!
//! Where a regex cannot be run on a name -- a name that is not UTF-8, which Python would have
//! matched after decoding it with surrogate escapes, or a match past fancy-regex's backtracking
//! limit -- the question has no answer, and every answer built on it is the closed one: the name
//! is neither visible, readable nor writable.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use fancy_regex::Regex;

/// One path component of a pattern: what it lets a concrete name be.
pub enum Component {
    Named(OsString),
    Any,
    OneOf(Vec<OsString>),
    /// anchored at both ends: the whole name must match (`matching`)
    Matching(Regex),
}

impl Component {
    /// The component whose names *pattern* fullmatches, as `re.fullmatch` would: the whole name,
    /// whatever the pattern's own anchors.
    pub fn matching(pattern: &str) -> Result<Component, fancy_regex::Error> {
        Regex::new(&format!(r"\A(?:{pattern})\z")).map(Component::Matching)
    }
}

pub enum Location {
    /// exactly these components
    Path(Vec<Component>),
    /// `prefix/**` (no leaf): the prefix and everything below it; `prefix/**/leaf`: anything
    /// strictly below it whose last component is the leaf
    Splat { prefix: Vec<Component>, leaf: Option<Component> },
}

pub enum Region {
    Subtree(PathBuf),
    Exactly(PathBuf),
    Pattern { location: Location, anchor: PathBuf },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    ReadOnly,
    Writable,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Narrowing {
    NoWrite,
    Hidden,
}

/// What a layer says of the paths it covers: a grant its access, a restriction its narrowing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Says {
    Grant(Access),
    Restrict(Narrowing),
}

pub struct Layer {
    pub region: Region,
    pub says: Says,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Absent,
    ReadOnly,
    Writable,
    Hidden,
}

/// A regex that could not be run on a name.
struct Undecidable;

type Decided<T> = Result<T, Undecidable>;

fn accepts(component: &Component, name: &OsStr) -> Decided<bool> {
    match component {
        Component::Named(n) => Ok(n.as_os_str() == name),
        Component::Any => Ok(true),
        Component::OneOf(names) => Ok(names.iter().any(|n| n.as_os_str() == name)),
        Component::Matching(re) => re.is_match(name.to_str().ok_or(Undecidable)?).map_err(|_| Undecidable),
    }
}

/// Does each component accept the name beside it (as far as both go)?
fn all_accept(components: &[Component], names: &[&OsStr]) -> Decided<bool> {
    for (component, name) in components.iter().zip(names) {
        if !accepts(component, name)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Does *location* denote the path *names* spells, relative to its anchor?
fn denotes(location: &Location, names: &[&OsStr]) -> Decided<bool> {
    match location {
        Location::Path(components) => Ok(components.len() == names.len() && all_accept(components, names)?),
        Location::Splat { prefix, leaf } => {
            if names.len() < prefix.len() || !all_accept(prefix, names)? {
                return Ok(false);
            }
            if names.len() == prefix.len() {
                return Ok(leaf.is_none()); // the prefix itself is denoted only by the reflexive form
            }
            match leaf {
                None => Ok(true),
                Some(leaf) => accepts(leaf, names[names.len() - 1]),
            }
        }
    }
}

/// Does *location* denote some path strictly below *names*, relative to its anchor?
fn names_below(location: &Location, names: &[&OsStr]) -> Decided<bool> {
    match location {
        Location::Path(components) => Ok(components.len() > names.len() && all_accept(components, names)?),
        Location::Splat { prefix, .. } => all_accept(prefix, names),
    }
}

/// *path*'s components below *anchor*, or None when it is not at or below it.
fn relative<'p>(path: &'p Path, anchor: &Path) -> Option<Vec<&'p OsStr>> {
    path.strip_prefix(anchor).ok().map(|rest| rest.iter().collect())
}

/// Does *region* cover *path*? With *below_too* -- a restriction's, which narrows everything below
/// what it names -- also whatever lies below what it covers.
fn covers(region: &Region, path: &Path, below_too: bool) -> Decided<bool> {
    match region {
        Region::Subtree(top) => Ok(path.starts_with(top)),
        Region::Exactly(exact) => Ok(if below_too { path.starts_with(exact) } else { path == exact.as_path() }),
        Region::Pattern { location, anchor } => {
            for candidate in path.ancestors().take(if below_too { usize::MAX } else { 1 }) {
                if let Some(names) = relative(candidate, anchor) {
                    if denotes(location, &names)? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
    }
}

/// Might *region* name something strictly below *path*?
fn reaches_below(region: &Region, path: &Path) -> Decided<bool> {
    match region {
        Region::Subtree(top) | Region::Exactly(top) => Ok(top.as_path() != path && top.starts_with(path)),
        Region::Pattern { location, anchor } => {
            if anchor.starts_with(path) {
                return Ok(true); // at or above where the pattern is anchored
            }
            match relative(path, anchor) {
                None => Ok(false),
                Some(names) => names_below(location, &names),
            }
        }
    }
}

/// Does *region* cover *path* and everything below it? A subtree does, and a pattern `pre/**` (no
/// leaf) that covers the path; nothing else is known to.
fn covers_wholly(region: &Region, path: &Path) -> Decided<bool> {
    match region {
        Region::Subtree(top) => Ok(path.starts_with(top)),
        Region::Pattern { location: Location::Splat { leaf: None, .. }, .. } => covers(region, path, false),
        _ => Ok(false),
    }
}

/// Might *region* decide anything at or below *path*?
fn touches(region: &Region, path: &Path, restriction: bool) -> Decided<bool> {
    Ok(covers(region, path, restriction)? || reaches_below(region, path)?)
}

/// *state*, once a layer saying *says* covers the path: a grant sets its access; no-write turns
/// writable into read-only; hidden turns anything present into hidden. Neither restriction makes
/// an absent path appear.
fn after(state: State, says: Says) -> State {
    match says {
        Says::Grant(Access::Writable) => State::Writable,
        Says::Grant(Access::ReadOnly) => State::ReadOnly,
        Says::Restrict(Narrowing::NoWrite) => {
            if state == State::Writable {
                State::ReadOnly
            } else {
                state
            }
        }
        Says::Restrict(Narrowing::Hidden) => {
            if state == State::Absent {
                state
            } else {
                State::Hidden
            }
        }
    }
}

pub struct Filter {
    directory: PathBuf,
    layers: Vec<Layer>,
}

impl Filter {
    pub fn new(directory: PathBuf, layers: Vec<Layer>) -> Filter {
        Filter { directory, layers }
    }

    fn at(&self, path: &[OsString]) -> PathBuf {
        let mut at = self.directory.clone();
        at.extend(path);
        at
    }

    /// *path*'s state, by the layers in order, and whether a hidden layer has the last word on
    /// it -- covers it, with no grant covering it after.
    fn decided(&self, path: &[OsString]) -> Decided<(State, bool)> {
        let at = self.at(path);
        let (mut state, mut hidden) = (State::Absent, false);
        for layer in &self.layers {
            let restriction = matches!(layer.says, Says::Restrict(_));
            if covers(&layer.region, &at, restriction)? {
                state = after(state, layer.says);
                hidden = layer.says == Says::Restrict(Narrowing::Hidden) || (hidden && restriction);
            }
        }
        Ok((state, hidden))
    }

    fn is_readable(&self, path: &[OsString]) -> Decided<bool> {
        Ok(matches!(self.decided(path)?.0, State::ReadOnly | State::Writable))
    }

    /// A directory exists for the jail iff it is the served directory, readable, or on the way to
    /// something a grant names below it that no hidden layer after the grant covers wholly.
    fn is_dir_visible(&self, path: &[OsString]) -> Decided<bool> {
        if path.is_empty() || self.is_readable(path)? {
            return Ok(true);
        }
        let at = self.at(path);
        for (i, layer) in self.layers.iter().enumerate() {
            if !matches!(layer.says, Says::Grant(_)) || !reaches_below(&layer.region, &at)? {
                continue;
            }
            let mut hidden = false;
            for later in &self.layers[i + 1..] {
                if later.says == Says::Restrict(Narrowing::Hidden) && covers(&later.region, &at, true)? {
                    hidden = true;
                    break;
                }
            }
            if !hidden {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_visible(&self, path: &[OsString], is_dir: bool) -> Decided<bool> {
        if self.is_readable(path)? {
            return Ok(true);
        }
        if let Some((_, parent)) = path.split_last() {
            if self.is_readable(parent)? && !self.decided(path)?.1 {
                return Ok(true);
            }
        }
        Ok(is_dir && self.is_dir_visible(path)?)
    }

    /// A file's contents open, a directory lists every name.
    pub fn readable(&self, path: &[OsString]) -> bool {
        self.is_readable(path).unwrap_or(false)
    }

    /// Does the entry look up and list? Readable; under a readable directory, by name, unless
    /// hidden; or a directory on the way to a grant.
    pub fn visible(&self, path: &[OsString], is_dir: bool) -> bool {
        self.is_visible(path, is_dir).unwrap_or(false)
    }

    /// Writable: the name may be created, changed or removed. Never the served directory itself,
    /// which is a mountpoint.
    pub fn may_write(&self, path: &[OsString]) -> bool {
        !path.is_empty() && matches!(self.decided(path), Ok((State::Writable, _)))
    }

    /// May a directory move from *src* to *dst*? A directory's path is every path beneath it, so
    /// only where each of those is decided alike before and after: a writable grant covers both
    /// ends wholly, and no layer after it covers or reaches below either -- every path below either
    /// end is then writable, by that grant, with nothing else having a say.
    pub fn may_move_dir(&self, src: &[OsString], dst: &[OsString]) -> bool {
        self.movable(&self.at(src), &self.at(dst)).unwrap_or(false)
    }

    fn movable(&self, a: &Path, b: &Path) -> Decided<bool> {
        for (i, layer) in self.layers.iter().enumerate() {
            if layer.says != Says::Grant(Access::Writable)
                || !covers_wholly(&layer.region, a)?
                || !covers_wholly(&layer.region, b)?
            {
                continue;
            }
            let mut untouched = true;
            for later in &self.layers[i + 1..] {
                let restriction = matches!(later.says, Says::Restrict(_));
                if touches(&later.region, a, restriction)? || touches(&later.region, b, restriction)? {
                    untouched = false;
                    break;
                }
            }
            if untouched {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// tests/test_fuseview.py's TestFilter and TestLayers, case for case.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    const READ: Says = Says::Grant(Access::ReadOnly);
    const WRITE: Says = Says::Grant(Access::Writable);
    const NO_WRITE: Says = Says::Restrict(Narrowing::NoWrite);
    const HIDDEN: Says = Says::Restrict(Narrowing::Hidden);

    fn at(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn named(name: &str) -> Component {
        Component::Named(name.into())
    }

    fn matching(pattern: &str) -> Component {
        Component::matching(pattern).expect("a regex")
    }

    fn layer(says: Says, region: Region) -> Layer {
        Layer { region, says }
    }

    /// `prefix/**`, or `prefix/**/leaf`, under *anchor*
    fn splat(anchor: &str, prefix: Vec<Component>, leaf: Option<Component>) -> Region {
        Region::Pattern { location: Location::Splat { prefix, leaf }, anchor: anchor.into() }
    }

    fn path(anchor: &str, components: Vec<Component>) -> Region {
        Region::Pattern { location: Location::Path(components), anchor: anchor.into() }
    }

    fn subtree(p: &str) -> Region {
        Region::Subtree(p.into())
    }

    fn exactly(p: &str) -> Region {
        Region::Exactly(p.into())
    }

    fn dir_visible(f: &Filter, parts: &[&str]) -> bool {
        f.is_dir_visible(&at(parts)).unwrap_or(false)
    }

    /// read src/**/<.*\.py> and docs/**, write out/**, no-write out/**/.git
    fn section() -> Filter {
        Filter::new(
            "/r".into(),
            vec![
                layer(READ, splat("/r", vec![named("src")], Some(matching(r".*\.py")))),
                layer(READ, splat("/r", vec![named("docs")], None)),
                layer(WRITE, splat("/r", vec![named("out")], None)),
                layer(NO_WRITE, splat("/r", vec![named("out")], Some(named(".git")))),
            ],
        )
    }

    #[test]
    fn files() {
        let f = section();
        assert!(f.readable(&at(&["src", "a.py"])));
        assert!(f.readable(&at(&["src", "pkg", "deep", "b.py"])));
        assert!(!f.readable(&at(&["src", "a.txt"])));
        assert!(f.readable(&at(&["docs", "x", "y.txt"])));
        assert!(f.readable(&at(&["out", "artifact"]))); // a write grant reads too
        assert!(!f.readable(&at(&["secrets", "key.pem"])));
        assert!(!f.readable(&at(&["a.py"])));
    }

    #[test]
    fn directories() {
        let f = section();
        assert!(dir_visible(&f, &[]));
        assert!(dir_visible(&f, &["src"])); // a grant has paths below it
        assert!(dir_visible(&f, &["src", "pkg"]));
        assert!(dir_visible(&f, &["docs"]));
        assert!(!dir_visible(&f, &["notes"])); // no grant has paths below it
        assert!(!dir_visible(&f, &["notes", "sub"]));
        assert!(!dir_visible(&f, &["secrets"]));
    }

    #[test]
    fn writes() {
        let f = section();
        assert!(f.may_write(&at(&["out", "new"])));
        assert!(f.may_write(&at(&["out", "deep", "new"])));
        assert!(!f.may_write(&at(&["out", ".git"])));
        assert!(!f.may_write(&at(&["out", "x", ".git", "config"]))); // at or below a protection
        assert!(!f.may_write(&at(&["src", "a.py"]))); // a read grant is not writable
        assert!(!f.may_write(&at(&["elsewhere"])));
        assert!(!f.may_write(&at(&[]))); // the mountpoint itself
    }

    #[test]
    fn names_are_matched_exactly() {
        let f = section();
        assert!(!f.readable(&at(&["DOCS", "readme"])));
        assert!(f.readable(&at(&["src", "abcdefghijklmnopqrstuvwxyz.py"])));
        let narrow = Filter::new("/r".into(), vec![layer(READ, path("/r", vec![named("pub"), matching(r"[a-z]\.txt")]))]);
        assert!(!narrow.readable(&at(&["pub", "A.txt"])));
        assert!(!narrow.readable(&at(&["pub", "abcdefghijklmnopqrstuvwxyz.txt"])));
        assert!(narrow.readable(&at(&["pub", "a.txt"])));
    }

    #[test]
    fn a_literal_directory_lists_its_names_but_opens_none() {
        let f = Filter::new("/r".into(), vec![layer(READ, path("/r", vec![named("src")]))]);
        assert!(f.readable(&at(&["src"]))); // it lists
        assert!(f.visible(&at(&["src", "a.py"]), false)); // its entries show, by name
        assert!(!f.readable(&at(&["src", "a.py"]))); // but do not open
        assert!(!f.visible(&at(&["src", "sub", "b.py"]), false));
    }

    #[test]
    fn a_later_layer_wins_where_it_overlaps() {
        let f = Filter::new(
            "/r".into(),
            vec![
                layer(WRITE, subtree("/r/out")),
                layer(NO_WRITE, subtree("/r/out/keep")),
                layer(WRITE, subtree("/r/out/keep/open")),
            ],
        );
        assert!(f.may_write(&at(&["out", "x"])));
        assert!(!f.may_write(&at(&["out", "keep", "x"])));
        assert!(f.readable(&at(&["out", "keep", "x"])));
        assert!(f.may_write(&at(&["out", "keep", "open", "y"])));
    }

    #[test]
    fn absolute_layers_over_a_directory_that_is_no_root() {
        let f = Filter::new(
            "/opt/data".into(),
            vec![
                layer(READ, splat("/", vec![named("opt"), named("data"), matching("[a-z]+")], None)),
                layer(READ, exactly("/opt/data/README")),
            ],
        );
        assert!(dir_visible(&f, &[]));
        assert!(f.readable(&at(&["abc", "x"])));
        assert!(!f.visible(&at(&["ABC"]), true));
        assert!(f.readable(&at(&["README"])));
        assert!(!f.readable(&at(&["README.old"])));
    }

    #[test]
    fn a_hidden_name_does_not_show_under_a_readable_directory() {
        let f = Filter::new(
            "/h".into(),
            vec![layer(READ, exactly("/h")), layer(WRITE, subtree("/h/proj")), layer(HIDDEN, subtree("/h/.ssh"))],
        );
        assert!(f.visible(&at(&["notes.txt"]), false));
        assert!(!f.readable(&at(&["notes.txt"])));
        assert!(f.visible(&at(&["proj"]), true));
        assert!(!f.visible(&at(&[".ssh"]), true));
        assert!(!f.visible(&at(&[".ssh", "id_ed25519"]), false));
        assert!(!f.may_write(&at(&[".ssh", "id_ed25519"])));
    }

    #[test]
    fn a_hidden_directory_leads_only_to_what_a_later_grant_names() {
        let home = || layer(READ, subtree("/h"));
        let hide = || layer(HIDDEN, subtree("/h/.ssh"));
        let known = || layer(READ, exactly("/h/.ssh/known_hosts"));
        let f = Filter::new("/h".into(), vec![home(), hide(), known()]);
        assert!(f.visible(&at(&[".ssh"]), true)); // on the way to known_hosts
        assert!(!f.readable(&at(&[".ssh"]))); // its listing shows that alone
        assert!(f.readable(&at(&[".ssh", "known_hosts"])));
        assert!(!f.visible(&at(&[".ssh", "id_ed25519"]), false));
        // the grant before the hide: the hide has the last word on everything below it
        let f = Filter::new("/h".into(), vec![known(), home(), hide()]);
        assert!(!f.visible(&at(&[".ssh"]), true));
        assert!(!f.readable(&at(&[".ssh", "known_hosts"])));
    }

    #[test]
    fn a_directory_moves_only_where_everything_below_is_decided_alike() {
        let everything = || splat("/r", vec![], None);
        let rw = Filter::new("/r".into(), vec![layer(READ, everything()), layer(WRITE, everything())]);
        assert!(rw.may_move_dir(&at(&["a", "x"]), &at(&["a", "y"])));
        assert!(rw.may_move_dir(&at(&["a", "x"]), &at(&["b", "x"])));
        let git = Filter::new("/r".into(), vec![layer(WRITE, everything()), layer(NO_WRITE, splat("/r", vec![], Some(named(".git"))))]);
        assert!(!git.may_move_dir(&at(&["a", "x"]), &at(&["a", "y"]))); // a later protection reaches below
        let out = Filter::new("/r".into(), vec![layer(READ, everything()), layer(WRITE, subtree("/r/out"))]);
        assert!(out.may_move_dir(&at(&["out", "a"]), &at(&["out", "b"])));
        assert!(!out.may_move_dir(&at(&["out", "a"]), &at(&["src", "a"])));
        let hide = Filter::new("/r".into(), vec![layer(WRITE, everything()), layer(HIDDEN, subtree("/r/secret"))]);
        assert!(hide.may_move_dir(&at(&["src", "x"]), &at(&["src", "y"]))); // a hide elsewhere does not matter
        assert!(!hide.may_move_dir(&at(&["src", "x"]), &at(&["secret", "x"])));
        let again = Filter::new(
            "/r".into(),
            vec![layer(WRITE, subtree("/r")), layer(NO_WRITE, subtree("/r/keep")), layer(WRITE, subtree("/r"))],
        );
        assert!(again.may_move_dir(&at(&["keep", "x"]), &at(&["keep", "y"]))); // a later whole grant settles it
        let leaf = Filter::new("/r".into(), vec![layer(WRITE, splat("/r", vec![], Some(Component::Any)))]);
        assert!(!leaf.may_move_dir(&at(&["a", "x"]), &at(&["a", "y"]))); // a pattern with a leaf is not whole
    }

    #[test]
    fn a_name_no_regex_can_read_fails_closed() {
        // not UTF-8: a hide by pattern still hides it, and a grant by pattern does not grant it
        let odd = OsString::from_vec(b"key\xff.pem".to_vec());
        let f = Filter::new(
            "/r".into(),
            vec![layer(READ, subtree("/r")), layer(HIDDEN, splat("/r", vec![], Some(matching(r".*\.pem"))))],
        );
        let path = vec![OsString::from("keys"), odd.clone()];
        assert!(!f.visible(&path, false));
        let f = Filter::new("/r".into(), vec![layer(READ, splat("/r", vec![], Some(matching(r".*\.pem"))))]);
        assert!(!f.readable(&path));
        assert!(f.readable(&at(&["keys", "a.pem"])));
    }
}
