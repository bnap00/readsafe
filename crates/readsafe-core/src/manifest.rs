//! The agent-facing manifest contract (schemaVersion 0.1).
//!
//! Canonical ordering: files sorted by path, variables sorted by name,
//! structure paths sorted by path. No timestamps by default. Every entry
//! carries `valueExposed: false`; nothing in these types can hold a raw
//! value.

use crate::classify::Confidence;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: String,
    pub tool_version: String,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn new(tool_version: &str, mut files: Vec<FileEntry>) -> Manifest {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Manifest {
            schema_version: SCHEMA_VERSION.to_string(),
            tool_version: tool_version.to_string(),
            files,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub path: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malformed_lines: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<Variable>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structure: Option<Vec<PathInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<Scan>,
    pub value_exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub name: String,
    #[serde(rename = "type")]
    pub var_type: String,
    pub required: bool,
    pub sensitive: bool,
    pub source: String,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_redacted: Option<bool>,
    pub value_exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInfo {
    pub path: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scan {
    pub mode: String,
    pub sampled_records: u64,
    pub record_count: Option<u64>,
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malformed_records: Option<u64>,
}
