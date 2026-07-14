//! `readsafe inspect`: redacted structure metadata for supported files.

use readsafe_core::classify::{classify, infer_type};
use readsafe_core::dotenv::Document;
use readsafe_core::error::{ErrorCode, SafeError};
use readsafe_core::fsops;
use readsafe_core::jsonish;
use readsafe_core::manifest::{FileEntry, Manifest, Variable};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dotenv,
    Json,
    Jsonl,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Dotenv => "dotenv",
            Kind::Json => "json",
            Kind::Jsonl => "jsonl",
        }
    }
}

pub fn file_kind(path: &Path) -> Option<Kind> {
    let name = path.file_name()?.to_str()?;
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return Some(Kind::Dotenv);
    }
    if name.ends_with(".json") {
        return Some(Kind::Json);
    }
    if name.ends_with(".jsonl") || name.ends_with(".ndjson") {
        return Some(Kind::Jsonl);
    }
    None
}

pub fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "__pycache__",
];

/// Expand CLI paths. Directories are walked recursively for dotenv files
/// only; JSON/JSONL must be named explicitly so public config workflows are
/// not disturbed. Explicitly named unsupported files are an error.
fn expand(paths: &[PathBuf]) -> Result<Vec<(PathBuf, Kind)>, SafeError> {
    let mut out = Vec::new();
    for path in paths {
        if path.is_dir() {
            walk(path, &mut out);
        } else {
            match file_kind(path) {
                Some(kind) => out.push((path.clone(), kind)),
                None => {
                    return Err(SafeError::new(
                        ErrorCode::UnsupportedFormat,
                        "unsupported file format; supported: dotenv, .json, .jsonl/.ndjson",
                    )
                    .with_path(display_path(path)));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<(PathBuf, Kind)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !SKIP_DIRS.contains(&name) && !name.starts_with('.') {
                walk(&entry, out);
            }
        } else if matches!(file_kind(&entry), Some(Kind::Dotenv)) {
            out.push((entry, Kind::Dotenv));
        }
    }
}

/// Keys listed in a sibling `.env.example`, used as the `required` signal.
fn example_keys(path: &Path) -> Option<HashSet<String>> {
    let name = path.file_name()?.to_str()?;
    if name == ".env.example" {
        return None;
    }
    let example = path.parent()?.join(".env.example");
    let text = std::fs::read_to_string(example).ok()?;
    Some(
        Document::parse(&text)
            .entries()
            .map(|e| e.key.clone())
            .collect(),
    )
}

pub fn dotenv_entry(path: &Path, text: &str) -> FileEntry {
    let doc = Document::parse(text);
    let required_keys = example_keys(path);
    let mut variables: Vec<Variable> = doc
        .entries()
        .map(|entry| {
            let classification = classify(&entry.key, &entry.value);
            let (var_type, type_confidence) = infer_type(&entry.key, &entry.value);
            let confidence = if classification.sensitive {
                std::cmp::min(classification.confidence, type_confidence)
            } else {
                type_confidence
            };
            Variable {
                name: entry.key.clone(),
                var_type: var_type.to_string(),
                required: required_keys
                    .as_ref()
                    .is_some_and(|keys| keys.contains(&entry.key)),
                sensitive: classification.sensitive,
                source: "inferred".to_string(),
                confidence,
                description_redacted: if doc.entry_has_comment(&entry.key) {
                    Some(true)
                } else {
                    None
                },
                value_exposed: false,
            }
        })
        .collect();
    variables.sort_by(|a, b| a.name.cmp(&b.name));
    variables.dedup_by(|a, b| a.name == b.name);
    let malformed = doc.malformed_count() as u64;
    FileEntry {
        path: display_path(path),
        kind: "dotenv".to_string(),
        experimental: None,
        malformed_lines: if malformed > 0 { Some(malformed) } else { None },
        variables: Some(variables),
        structure: None,
        scan: None,
        value_exposed: false,
    }
}

fn json_entry(path: &Path, text: &str, kind: Kind) -> Result<FileEntry, SafeError> {
    let (structure, scan) = match kind {
        Kind::Json => {
            let node = jsonish::scan_json(text).ok_or_else(|| {
                SafeError::new(ErrorCode::ParseError, "file is not valid JSON")
                    .with_path(display_path(path))
            })?;
            (node.structure_paths().0, None)
        }
        Kind::Jsonl => {
            let result = jsonish::scan_jsonl(text, jsonish::DEFAULT_SAMPLE_RECORDS, false);
            (result.root.structure_paths().0, Some(result.scan))
        }
        Kind::Dotenv => unreachable!(),
    };
    Ok(FileEntry {
        path: display_path(path),
        kind: kind.as_str().to_string(),
        experimental: Some(true),
        malformed_lines: None,
        variables: None,
        structure: Some(structure),
        scan,
        value_exposed: false,
    })
}

pub fn build_manifest(paths: &[PathBuf], allow_symlink: bool) -> Result<Manifest, SafeError> {
    let mut files = Vec::new();
    for (path, kind) in expand(paths)? {
        let text = fsops::read_text(&path, allow_symlink)?;
        let entry = match kind {
            Kind::Dotenv => dotenv_entry(&path, &text),
            Kind::Json | Kind::Jsonl => json_entry(&path, &text, kind)?,
        };
        files.push(entry);
    }
    Ok(Manifest::new(crate::output::TOOL_VERSION, files))
}

pub fn run(
    paths: &[PathBuf],
    json: bool,
    out: Option<&Path>,
    allow_symlink: bool,
) -> Result<i32, SafeError> {
    let manifest = build_manifest(paths, allow_symlink)?;
    let rendered = serde_json::to_string_pretty(&manifest).unwrap();
    match out {
        Some(out_path) => {
            std::fs::write(out_path, format!("{rendered}\n")).map_err(|_| {
                SafeError::new(ErrorCode::FileIo, "could not write manifest file")
                    .with_path(display_path(out_path))
            })?;
            if !json {
                println!(
                    "manifest written to {} [values not shown]",
                    display_path(out_path)
                );
            }
        }
        None if json => println!("{rendered}"),
        None => print_human(&manifest),
    }
    Ok(0)
}

fn print_human(manifest: &Manifest) {
    for file in &manifest.files {
        let extra = match (&file.scan, file.experimental) {
            (Some(scan), _) => format!(
                ", {} records {}",
                scan.sampled_records,
                if scan.complete { "scanned" } else { "sampled" }
            ),
            (None, Some(true)) => ", experimental".to_string(),
            _ => String::new(),
        };
        println!("{} ({}{extra})", file.path, file.kind);
        if let Some(variables) = &file.variables {
            for variable in variables {
                println!(
                    "  {:<24} {:<9} {:<9} {}[value not shown]",
                    variable.name,
                    variable.var_type,
                    if variable.sensitive {
                        "sensitive"
                    } else {
                        "public"
                    },
                    if variable.required { "required " } else { "" },
                );
            }
        }
        if let Some(structure) = &file.structure {
            for info in structure {
                println!("  {:<32} {}", info.path, info.types.join("|"));
            }
        }
        if let Some(malformed) = file.malformed_lines {
            println!("  ({malformed} malformed line(s) not shown)");
        }
    }
}
