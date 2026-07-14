//! `readsafe infer` (safe schema inference) and
//! `readsafe validate --manifest` (structure drift detection).

use crate::inspect::{display_path, dotenv_entry, file_kind, Kind};
use crate::output::{Operation, TOOL_VERSION};
use readsafe_core::error::{ErrorCode, SafeError};
use readsafe_core::fsops;
use readsafe_core::jsonish;
use readsafe_core::manifest::{Manifest, Scan, SCHEMA_VERSION};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

pub fn infer(
    path: &Path,
    schema_out: Option<&Path>,
    full_scan: bool,
    sample: u64,
    json_output: bool,
    allow_symlink: bool,
) -> Result<i32, SafeError> {
    let kind = file_kind(path).ok_or_else(|| {
        SafeError::new(
            ErrorCode::UnsupportedFormat,
            "infer supports .json and .jsonl/.ndjson files",
        )
        .with_path(display_path(path))
    })?;
    let text = fsops::read_text(path, allow_symlink)?;
    let (node, scan): (jsonish::Node, Option<Scan>) = match kind {
        Kind::Json => {
            let node = jsonish::scan_json(&text).ok_or_else(|| {
                SafeError::new(ErrorCode::ParseError, "file is not valid JSON")
                    .with_path(display_path(path))
            })?;
            (node, None)
        }
        Kind::Jsonl => {
            let result = jsonish::scan_jsonl(&text, sample, full_scan);
            (result.root, Some(result.scan))
        }
        Kind::Dotenv => {
            return Err(SafeError::new(
                ErrorCode::UnsupportedFormat,
                "infer supports .json and .jsonl/.ndjson files",
            )
            .with_path(display_path(path)));
        }
    };

    let mut schema = node.to_schema();
    if let Value::Object(map) = &mut schema {
        let mut meta = json!({
            "schemaVersion": SCHEMA_VERSION,
            "toolVersion": TOOL_VERSION,
            "source": "inferred",
            "confidence": if scan.as_ref().is_none_or(|s| s.complete) { "medium" } else { "low" },
        });
        if let Some(scan) = &scan {
            meta["scan"] = serde_json::to_value(scan).unwrap();
        }
        map.insert("x-readsafe".to_string(), meta);
    }
    let rendered = serde_json::to_string_pretty(&schema).unwrap();

    match schema_out {
        Some(out_path) => {
            std::fs::write(out_path, format!("{rendered}\n")).map_err(|_| {
                SafeError::new(ErrorCode::FileIo, "could not write schema file")
                    .with_path(display_path(out_path))
            })?;
            let mut operation = Operation::new("infer", display_path(path));
            operation.schema_out = Some(display_path(out_path));
            operation.scan = scan;
            crate::output::print_operation(operation, json_output);
        }
        None => println!("{rendered}"),
    }
    Ok(0)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationEnvelope {
    schema_version: &'static str,
    validation: Validation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Validation {
    ok: bool,
    drift: Vec<Drift>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Drift {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    change: &'static str,
}

/// Validate a JSON/JSONL file's structure against an explicit schema produced
/// by `readsafe infer`. Reports structural violations by path only — required
/// properties missing, unexpected properties, and broad type mismatches. No
/// value from the file or the schema is ever read into the report.
pub fn validate_schema(
    file: &Path,
    schema_path: &Path,
    json_output: bool,
    allow_symlink: bool,
) -> Result<i32, SafeError> {
    let kind = file_kind(file).ok_or_else(|| {
        SafeError::new(
            ErrorCode::UnsupportedFormat,
            "validate --schema supports .json and .jsonl/.ndjson files",
        )
        .with_path(display_path(file))
    })?;
    if kind == Kind::Dotenv {
        return Err(SafeError::new(
            ErrorCode::UnsupportedFormat,
            "validate --schema supports .json and .jsonl/.ndjson files",
        )
        .with_path(display_path(file)));
    }

    let text = fsops::read_text(file, allow_symlink)?;
    let node = match kind {
        Kind::Json => jsonish::scan_json(&text).ok_or_else(|| {
            SafeError::new(ErrorCode::ParseError, "file is not valid JSON")
                .with_path(display_path(file))
        })?,
        Kind::Jsonl => jsonish::scan_jsonl(&text, jsonish::DEFAULT_SAMPLE_RECORDS, true).root,
        Kind::Dotenv => unreachable!(),
    };

    let schema_text = fsops::read_text(schema_path, allow_symlink)?;
    let schema: Value = serde_json::from_str(&schema_text).map_err(|_| {
        SafeError::new(ErrorCode::ManifestInvalid, "schema is not valid JSON")
            .with_path(display_path(schema_path))
    })?;

    let mut drift = Vec::new();
    compare_schema(&schema, &node, "$", &mut drift);

    let ok = drift.is_empty();
    if json_output {
        let envelope = ValidationEnvelope {
            schema_version: SCHEMA_VERSION,
            validation: Validation { ok, drift },
        };
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else if ok {
        println!("validate: ok, structure matches schema");
    } else {
        println!("validate: schema violations");
        for item in &drift {
            match &item.name {
                Some(name) => println!("  {} {} {}", item.path, name, item.change),
                None => println!("  {} {}", item.path, item.change),
            }
        }
    }
    Ok(if ok { 0 } else { 1 })
}

/// Walk the schema and the observed structure in parallel, recording
/// violations by path. Driven by the schema so only declared constraints are
/// checked; the `x-readsafe` metadata block and any other non-constraint keys
/// are ignored. Property names are structural (never values).
fn compare_schema(schema: &Value, node: &jsonish::Node, path: &str, drift: &mut Vec<Drift>) {
    let Value::Object(schema_map) = schema else {
        return;
    };

    if let Some(allowed) = schema_types(schema_map) {
        for observed in node.observed_types() {
            if observed != "null" && !allowed.contains(&observed) {
                drift.push(Drift {
                    path: path.to_string(),
                    name: None,
                    change: "typeMismatch",
                });
                break;
            }
        }
    }

    if let Some(Value::Object(properties)) = schema_map.get("properties") {
        if let Some(Value::Array(required)) = schema_map.get("required") {
            for name in required.iter().filter_map(Value::as_str) {
                if node.property(name).is_none() {
                    drift.push(Drift {
                        path: path.to_string(),
                        name: Some(name.to_string()),
                        change: "missingRequired",
                    });
                }
            }
        }
        for observed in node.property_names() {
            if !properties.contains_key(observed) {
                drift.push(Drift {
                    path: path.to_string(),
                    name: Some(observed.to_string()),
                    change: "unexpected",
                });
            }
        }
        for (name, child_schema) in properties {
            if let Some(child_node) = node.property(name) {
                compare_schema(child_schema, child_node, &format!("{path}.{name}"), drift);
            }
        }
    }

    if let Some(items_schema) = schema_map.get("items") {
        if let Some(items_node) = node.items() {
            compare_schema(items_schema, items_node, &format!("{path}[]"), drift);
        }
    }
}

/// Collect the allowed types from a schema object's `type` keyword, whether a
/// single string or an array.
fn schema_types(schema_map: &serde_json::Map<String, Value>) -> Option<Vec<String>> {
    match schema_map.get("type")? {
        Value::String(t) => Some(vec![t.clone()]),
        Value::Array(list) => Some(
            list.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect(),
        ),
        _ => None,
    }
}

/// Compare dotenv files against a previously generated manifest. Reports
/// structural drift only; values are never read into the report.
pub fn validate_manifest(manifest_path: &Path, json_output: bool) -> Result<i32, SafeError> {
    let text = fsops::read_text(manifest_path, false)?;
    let manifest: Manifest = serde_json::from_str(&text).map_err(|_| {
        SafeError::new(
            ErrorCode::ManifestInvalid,
            "manifest is not valid ReadSafe manifest JSON",
        )
        .with_path(display_path(manifest_path))
    })?;

    let mut drift = Vec::new();
    for file in &manifest.files {
        if file.kind != "dotenv" {
            continue;
        }
        let Some(expected) = &file.variables else {
            continue;
        };
        let path = Path::new(&file.path);
        let current = match fsops::read_text(path, false) {
            Ok(text) => dotenv_entry(path, &text),
            Err(_) => {
                drift.push(Drift {
                    path: file.path.clone(),
                    name: None,
                    change: "fileMissing",
                });
                continue;
            }
        };
        let current_vars = current.variables.unwrap_or_default();
        for expected_var in expected {
            match current_vars.iter().find(|v| v.name == expected_var.name) {
                None => drift.push(Drift {
                    path: file.path.clone(),
                    name: Some(expected_var.name.clone()),
                    change: "removed",
                }),
                Some(actual) => {
                    if actual.var_type != expected_var.var_type {
                        drift.push(Drift {
                            path: file.path.clone(),
                            name: Some(expected_var.name.clone()),
                            change: "typeChanged",
                        });
                    } else if actual.sensitive != expected_var.sensitive {
                        drift.push(Drift {
                            path: file.path.clone(),
                            name: Some(expected_var.name.clone()),
                            change: "sensitivityChanged",
                        });
                    }
                }
            }
        }
        for actual in &current_vars {
            if !expected.iter().any(|v| v.name == actual.name) {
                drift.push(Drift {
                    path: file.path.clone(),
                    name: Some(actual.name.clone()),
                    change: "added",
                });
            }
        }
    }

    let ok = drift.is_empty();
    if json_output {
        let envelope = ValidationEnvelope {
            schema_version: SCHEMA_VERSION,
            validation: Validation { ok, drift },
        };
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else if ok {
        println!("validate: ok, no structure drift");
    } else {
        println!("validate: drift detected");
        for item in &drift {
            match &item.name {
                Some(name) => println!("  {} {} {}", item.path, name, item.change),
                None => println!("  {} {}", item.path, item.change),
            }
        }
    }
    Ok(if ok { 0 } else { 1 })
}
