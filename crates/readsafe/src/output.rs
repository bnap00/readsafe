//! Output envelopes for the machine contract (schemaVersion 0.1) and the
//! shared rendering rules. Success JSON goes to stdout; errors go to stderr
//! (JSON-formatted under `--json`). Reasons are `&'static str` end to end,
//! so raw values cannot reach either channel through these types.

use readsafe_core::error::SafeError;
use readsafe_core::manifest::{Scan, SCHEMA_VERSION};
use serde::Serialize;

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationEnvelope {
    pub schema_version: &'static str,
    pub operation: Operation,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    #[serde(rename = "type")]
    pub op_type: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_write: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<Scan>,
    pub value_exposed: bool,
}

impl Operation {
    pub fn new(op_type: &'static str, path: String) -> Operation {
        Operation {
            op_type,
            path,
            value_exposed: false,
            ..Default::default()
        }
    }
}

pub fn print_operation(operation: Operation, json: bool) {
    if json {
        let envelope = OperationEnvelope {
            schema_version: SCHEMA_VERSION,
            operation,
        };
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else {
        let op = &operation;
        let mut line = format!("{} {}", op.op_type, op.path);
        if let Some(key) = &op.key {
            line.push_str(&format!(" {key}"));
        }
        if let (Some(old), Some(new)) = (&op.old_key, &op.new_key) {
            line.push_str(&format!(" {old} -> {new}"));
        }
        if let Some(valid) = op.valid {
            if valid {
                line.push_str(": valid");
            } else {
                line.push_str(&format!(
                    ": invalid ({})",
                    op.reason.unwrap_or("validation failed")
                ));
            }
        } else if let Some(changed) = op.changed {
            match (op.would_write, op.written) {
                (Some(would), _) => line.push_str(if would {
                    ": would write (dry run)"
                } else {
                    ": no change (dry run)"
                }),
                (_, Some(true)) => line.push_str(": written"),
                (_, Some(false)) => line.push_str(if changed {
                    ": not written"
                } else {
                    ": no change"
                }),
                _ => {}
            }
        }
        if let Some(schema_out) = &op.schema_out {
            line.push_str(&format!(": schema written to {schema_out}"));
        }
        line.push_str(" [values not shown]");
        println!("{line}");
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    schema_version: &'static str,
    error: ErrorBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    reason: &'static str,
    value_exposed: bool,
}

/// Render an error to stderr and return its exit code.
pub fn print_error(error: &SafeError, json: bool) -> i32 {
    if json {
        let envelope = ErrorEnvelope {
            schema_version: SCHEMA_VERSION,
            error: ErrorBody {
                code: error.code.as_str(),
                path: error.path.clone(),
                key: error.key.clone(),
                reason: error.reason,
                value_exposed: false,
            },
        };
        eprintln!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else {
        eprintln!("readsafe: error: {error}");
    }
    error.code.exit_code()
}
