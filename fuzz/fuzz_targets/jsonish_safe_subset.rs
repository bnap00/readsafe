#![no_main]
//! The inferred schema must stay inside the safe structural subset no matter
//! what records it sees. This target feeds arbitrary bytes as JSONL, builds a
//! schema, and asserts that every schema-structural node uses only the allowed
//! keywords — never a value-derived one like `enum`, `const`, `examples`,
//! `default`, exact bounds, or `pattern`. Property *names* are opaque (a field
//! may legitimately be named "enum"), so the walk distinguishes schema
//! keywords from property keys. It also proves the inference path never panics.

use libfuzzer_sys::fuzz_target;
use readsafe_core::jsonish;
use serde_json::Value;

/// Keys permitted at a schema-structural position (mirrors `Node::to_schema`).
const ALLOWED_SCHEMA_KEYS: &[&str] = &["type", "properties", "required", "items"];

/// Walk a schema node, checking that only allowed keywords appear in
/// schema-structural positions. Property names (keys under `properties`) are
/// not schema keywords and are not checked.
fn assert_safe_schema(schema: &Value) {
    let Value::Object(map) = schema else {
        return;
    };
    for key in map.keys() {
        assert!(
            ALLOWED_SCHEMA_KEYS.contains(&key.as_str()),
            "schema emitted a non-allowed keyword: {key}"
        );
    }
    if let Some(Value::Object(props)) = map.get("properties") {
        for child in props.values() {
            assert_safe_schema(child);
        }
    }
    if let Some(items) = map.get("items") {
        assert_safe_schema(items);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let result = jsonish::scan_jsonl(text, 1_000, true);
    assert_safe_schema(&result.root.to_schema());
});
