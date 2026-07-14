//! JSON and JSONL structure inference (experimental).
//!
//! Only coarse structural facts are derived: property names, broad scalar
//! types, array/object shape, nullability, and required/optional inference
//! from field presence. The safe schema subset never emits value-derived
//! `enum`, `const`, `examples`, `default`, exact lengths, exact numeric
//! bounds, inferred patterns, hashes, or fingerprints.

use crate::manifest::{PathInfo, Scan};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_SAMPLE_RECORDS: u64 = 10_000;
const MAX_STRUCTURE_PATHS: usize = 1_000;

#[derive(Debug, Default)]
pub struct Node {
    /// Times this path was observed at all.
    count: u64,
    /// Times this path was observed as an object (denominator for required).
    object_count: u64,
    types: BTreeSet<&'static str>,
    props: BTreeMap<String, Node>,
    items: Option<Box<Node>>,
}

impl Node {
    pub fn observe(&mut self, value: &Value) {
        self.count += 1;
        match value {
            Value::Null => {
                self.types.insert("null");
            }
            Value::Bool(_) => {
                self.types.insert("boolean");
            }
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    self.types.insert("integer");
                } else {
                    self.types.insert("number");
                }
            }
            Value::String(_) => {
                self.types.insert("string");
            }
            Value::Array(elements) => {
                self.types.insert("array");
                let item = self.items.get_or_insert_with(Default::default);
                for element in elements {
                    item.observe(element);
                }
            }
            Value::Object(map) => {
                self.types.insert("object");
                self.object_count += 1;
                for (key, val) in map {
                    self.props.entry(key.clone()).or_default().observe(val);
                }
            }
        }
    }

    fn type_list(&self) -> Vec<String> {
        self.types.iter().map(|t| t.to_string()).collect()
    }

    /// Broad scalar/structural types observed at this node (e.g. `["object"]`,
    /// `["integer", "string"]`). Never includes values.
    pub fn observed_types(&self) -> Vec<String> {
        self.type_list()
    }

    /// Look up a child by property name, if this node was ever an object with
    /// that key.
    pub fn property(&self, name: &str) -> Option<&Node> {
        self.props.get(name)
    }

    /// Names of all observed properties, in stable order.
    pub fn property_names(&self) -> impl Iterator<Item = &str> {
        self.props.keys().map(String::as_str)
    }

    /// The element node for observed array items, if any.
    pub fn items(&self) -> Option<&Node> {
        self.items.as_deref()
    }

    /// Flatten to `$.a.b[]`-style paths with broad types.
    pub fn structure_paths(&self) -> (Vec<PathInfo>, bool) {
        let mut out = Vec::new();
        let mut truncated = false;
        self.collect_paths("$", &mut out, &mut truncated);
        (out, truncated)
    }

    fn collect_paths(&self, path: &str, out: &mut Vec<PathInfo>, truncated: &mut bool) {
        if out.len() >= MAX_STRUCTURE_PATHS {
            *truncated = true;
            return;
        }
        out.push(PathInfo {
            path: path.to_string(),
            types: self.type_list(),
        });
        for (key, child) in &self.props {
            child.collect_paths(&format!("{path}.{key}"), out, truncated);
        }
        if let Some(items) = &self.items {
            items.collect_paths(&format!("{path}[]"), out, truncated);
        }
    }

    /// Emit the safe JSON Schema subset.
    pub fn to_schema(&self) -> Value {
        let mut schema = Map::new();
        let types = self.type_list();
        match types.len() {
            0 => {}
            1 => {
                schema.insert("type".into(), Value::String(types[0].clone()));
            }
            _ => {
                schema.insert(
                    "type".into(),
                    Value::Array(types.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        if !self.props.is_empty() {
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (key, child) in &self.props {
                properties.insert(key.clone(), child.to_schema());
                if child.count == self.object_count {
                    required.push(Value::String(key.clone()));
                }
            }
            schema.insert("properties".into(), Value::Object(properties));
            if !required.is_empty() {
                schema.insert("required".into(), Value::Array(required));
            }
        }
        if let Some(items) = &self.items {
            schema.insert("items".into(), items.to_schema());
        }
        Value::Object(schema)
    }
}

pub struct JsonlResult {
    pub root: Node,
    pub scan: Scan,
}

/// Stream JSONL text, observing up to `sample_limit` records (all records
/// when `full_scan`). Malformed lines are counted, never echoed.
pub fn scan_jsonl(text: &str, sample_limit: u64, full_scan: bool) -> JsonlResult {
    let mut root = Node::default();
    let mut sampled: u64 = 0;
    let mut malformed: u64 = 0;
    let mut reached_end = true;
    for line in text.lines() {
        if !full_scan && sampled >= sample_limit {
            reached_end = false;
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => {
                root.observe(&value);
                sampled += 1;
            }
            Err(_) => malformed += 1,
        }
    }
    let scan = Scan {
        mode: if reached_end { "full" } else { "sample" }.to_string(),
        sampled_records: sampled,
        record_count: if reached_end { Some(sampled) } else { None },
        complete: reached_end,
        malformed_records: if malformed > 0 { Some(malformed) } else { None },
    };
    JsonlResult { root, scan }
}

/// Parse a whole JSON document into a structure node. Returns None on
/// invalid JSON; the parse error is discarded so third-party error strings
/// (which may embed source text) never reach a caller.
pub fn scan_json(text: &str) -> Option<Node> {
    let value: Value = serde_json::from_str(text).ok()?;
    let mut root = Node::default();
    root.observe(&value);
    Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORBIDDEN_SCHEMA_KEYWORDS: &[&str] = &[
        "enum",
        "const",
        "examples",
        "default",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "pattern",
        "format",
    ];

    fn assert_no_forbidden_keywords(schema: &Value) {
        if let Value::Object(map) = schema {
            for (key, val) in map {
                assert!(
                    !FORBIDDEN_SCHEMA_KEYWORDS.contains(&key.as_str()),
                    "forbidden keyword in schema: {key}"
                );
                assert_no_forbidden_keywords(val);
            }
        }
        if let Value::Array(items) = schema {
            for item in items {
                assert_no_forbidden_keywords(item);
            }
        }
    }

    #[test]
    fn schema_has_no_value_derived_keywords_or_values() {
        let jsonl = concat!(
            "{\"id\": 1, \"token\": \"CANARY_JSONL_TOKEN_1\", \"tags\": [\"a\"], \"opt\": null}\n",
            "{\"id\": 2, \"token\": \"CANARY_JSONL_TOKEN_2\", \"nested\": {\"deep\": 1.5}}\n",
            "not json at all CANARY_MALFORMED\n",
        );
        let result = scan_jsonl(jsonl, 100, false);
        let schema = result.root.to_schema();
        let rendered = serde_json::to_string_pretty(&schema).unwrap();
        assert!(!rendered.contains("CANARY"), "schema leaked a value");
        assert_no_forbidden_keywords(&schema);
        assert_eq!(result.scan.sampled_records, 2);
        assert_eq!(result.scan.malformed_records, Some(1));
        assert!(result.scan.complete);

        // Structural facts survive.
        assert!(rendered.contains("\"token\""));
        assert!(rendered.contains("\"required\""));
    }

    #[test]
    fn required_tracks_presence_across_records() {
        let jsonl = "{\"always\": 1, \"sometimes\": 2}\n{\"always\": 3}\n";
        let schema = scan_jsonl(jsonl, 100, false).root.to_schema();
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "always");
    }

    #[test]
    fn sampling_never_claims_completeness() {
        let mut jsonl = String::new();
        for i in 0..50 {
            jsonl.push_str(&format!("{{\"i\": {i}}}\n"));
        }
        let result = scan_jsonl(&jsonl, 10, false);
        assert_eq!(result.scan.mode, "sample");
        assert_eq!(result.scan.sampled_records, 10);
        assert_eq!(result.scan.record_count, None);
        assert!(!result.scan.complete);

        let full = scan_jsonl(&jsonl, 10, true);
        assert_eq!(full.scan.mode, "full");
        assert_eq!(full.scan.record_count, Some(50));
        assert!(full.scan.complete);
    }

    #[test]
    fn structure_paths_are_coarse() {
        let node = scan_json(r#"{"a": {"b": [1, "x"]}, "c": true}"#).unwrap();
        let (paths, truncated) = node.structure_paths();
        assert!(!truncated);
        let rendered: Vec<String> = paths
            .iter()
            .map(|p| format!("{} {}", p.path, p.types.join("|")))
            .collect();
        assert_eq!(
            rendered,
            vec![
                "$ object",
                "$.a object",
                "$.a.b array",
                "$.a.b[] integer|string",
                "$.c boolean",
            ]
        );
    }
}
