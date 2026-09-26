//! A view daemon's specification (`viewdaemon.ViewSpec.document()`, format 2) as the filter's
//! layers. A regex that does not compile here refuses the whole specification: a pattern read
//! differently is a grant or a restriction read differently.

use std::ffi::OsString;
use std::path::PathBuf;

use serde_json::Value;

use crate::filter::{Access, Component, Layer, Location, Narrowing, Region, Says};

const FORMAT: u64 = 2;

pub struct Spec {
    pub directory: PathBuf,
    pub layers: Vec<Layer>,
}

pub fn parse(text: &str) -> Result<Spec, String> {
    let body: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    match body.get("format").and_then(Value::as_u64) {
        Some(FORMAT) => {}
        other => return Err(format!("format {other:?}, expected {FORMAT}")),
    }
    let directory = path(body.get("directory"))?;
    let layers = body
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("no list of layers")?
        .iter()
        .map(layer)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Spec { directory, layers })
}

fn path(v: Option<&Value>) -> Result<PathBuf, String> {
    v.and_then(Value::as_str).map(PathBuf::from).ok_or_else(|| format!("not a path: {v:?}"))
}

fn layer(v: &Value) -> Result<Layer, String> {
    let region = region(v.get("region").ok_or_else(|| format!("a layer with no region: {v}"))?)?;
    let says = match (v.get("grant").and_then(Value::as_str), v.get("restrict").and_then(Value::as_str)) {
        (Some("read-only"), None) => Says::Grant(Access::ReadOnly),
        (Some("writable"), None) => Says::Grant(Access::Writable),
        (None, Some("no-write")) => Says::Restrict(Narrowing::NoWrite),
        (None, Some("hidden")) => Says::Restrict(Narrowing::Hidden),
        _ => return Err(format!("a layer that says nothing known: {v}")),
    };
    Ok(Layer { region, says })
}

fn region(v: &Value) -> Result<Region, String> {
    if let Some(p) = v.get("subtree") {
        return Ok(Region::Subtree(path(Some(p))?));
    }
    if let Some(p) = v.get("exactly") {
        return Ok(Region::Exactly(path(Some(p))?));
    }
    match (v.get("pattern"), v.get("anchor")) {
        (Some(location_doc), anchor @ Some(_)) => {
            Ok(Region::Pattern { location: location(location_doc)?, anchor: path(anchor)? })
        }
        _ => Err(format!("a region of no known kind: {v}")),
    }
}

fn location(v: &Value) -> Result<Location, String> {
    if let Some(components_doc) = v.get("path") {
        return Ok(Location::Path(components(components_doc)?));
    }
    let prefix = components(v.get("prefix").ok_or_else(|| format!("a location of no known kind: {v}"))?)?;
    let leaf = match v.get("leaf") {
        None | Some(Value::Null) => None,
        Some(c) => Some(component(c)?),
    };
    Ok(Location::Splat { prefix, leaf })
}

fn components(v: &Value) -> Result<Vec<Component>, String> {
    v.as_array().ok_or_else(|| format!("not a list of components: {v}"))?.iter().map(component).collect()
}

fn component(v: &Value) -> Result<Component, String> {
    if let Some(name) = v.as_str() {
        return Ok(Component::Named(OsString::from(name)));
    }
    if v.get("any").is_some() {
        return Ok(Component::Any);
    }
    if let Some(names) = v.get("one_of").and_then(Value::as_array) {
        return names
            .iter()
            .map(|n| n.as_str().map(OsString::from).ok_or_else(|| format!("not a name: {n}")))
            .collect::<Result<Vec<_>, _>>()
            .map(Component::OneOf);
    }
    if let Some(pattern) = v.get("regex").and_then(Value::as_str) {
        return Component::matching(pattern).map_err(|e| format!("the regex {pattern:?} does not compile here: {e}"));
    }
    Err(format!("a component of no known kind: {v}"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use crate::filter::Filter;

    /// A document as `ViewSpec.document()` writes one, every kind of region and component in it:
    /// read src/**/<.*\.py> and {docs,notes}/**, write out/**, no-write out/**/.git, hide
    /// /r/docs/private, read /r/README exactly, read pub/*/<[a-z]\.txt>.
    const DOCUMENT: &str = r#"{"directory":"/r","format":2,"layers":[
{"grant":"read-only","region":{"anchor":"/r","pattern":{"absolute":false,"leaf":{"regex":".*\\.py"},"prefix":["src"]}}},
{"grant":"read-only","region":{"anchor":"/r","pattern":{"absolute":false,"leaf":null,"prefix":[{"one_of":["docs","notes"]}]}}},
{"grant":"writable","region":{"anchor":"/r","pattern":{"absolute":false,"leaf":null,"prefix":["out"]}}},
{"region":{"anchor":"/r","pattern":{"absolute":false,"leaf":".git","prefix":["out"]}},"restrict":"no-write"},
{"region":{"subtree":"/r/docs/private"},"restrict":"hidden"},
{"grant":"read-only","region":{"exactly":"/r/README"}},
{"grant":"read-only","region":{"anchor":"/r","pattern":{"absolute":false,"path":["pub",{"any":true},{"regex":"[a-z]\\.txt"}]}}}
]}"#;

    fn at(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_document_decodes_to_the_layers_it_spells() {
        let spec = super::parse(DOCUMENT).expect("a document");
        assert_eq!(spec.directory, std::path::Path::new("/r"));
        let f = Filter::new(spec.directory, spec.layers);
        assert!(f.readable(&at(&["src", "a", "b.py"])));
        assert!(!f.readable(&at(&["src", "a.txt"])));
        assert!(f.readable(&at(&["notes", "x"])));
        assert!(!f.readable(&at(&["other", "x"])));
        assert!(f.may_write(&at(&["out", "new"])));
        assert!(!f.may_write(&at(&["out", "x", ".git", "config"])));
        assert!(!f.visible(&at(&["docs", "private"]), true));
        assert!(!f.visible(&at(&["docs", "private", "key"]), false));
        assert!(f.readable(&at(&["README"])));
        assert!(!f.readable(&at(&["README.old"])));
        assert!(f.readable(&at(&["pub", "any", "a.txt"])));
        assert!(!f.readable(&at(&["pub", "any", "ab.txt"])));
        assert!(f.visible(&at(&["pub"]), true)); // on the way
    }

    #[test]
    fn what_it_cannot_read_it_refuses() {
        assert!(super::parse(r#"{"directory":"/r","format":1,"layers":[]}"#).is_err());
        let bad_regex = r#"{"directory":"/r","format":2,"layers":[{"grant":"read-only","region":{"anchor":"/r","pattern":{"absolute":false,"path":[{"regex":"(unclosed"}]}}}]}"#;
        assert!(super::parse(bad_regex).is_err());
        let unknown = r#"{"directory":"/r","format":2,"layers":[{"grant":"everything","region":{"subtree":"/r"}}]}"#;
        assert!(super::parse(unknown).is_err());
    }
}
