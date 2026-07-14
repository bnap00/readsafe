//! End-to-end tests against the real binary.
//!
//! The canary harness: every fixture embeds `CANARY_*` strings standing in
//! for secrets, and [`Run::assert_clean`] asserts that no output channel —
//! stdout, stderr, or any file the command created — contains a canary.
//! Every test that touches a canary fixture must call it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CANARY: &str = "CANARY";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

impl Run {
    fn assert_clean(&self) {
        assert!(
            !self.stdout.contains(CANARY),
            "canary leaked to stdout:\n{}",
            self.stdout.replace(CANARY, "CANARY<REDACTED-IN-ASSERT>")
        );
        assert!(
            !self.stderr.contains(CANARY),
            "canary leaked to stderr:\n{}",
            self.stderr.replace(CANARY, "CANARY<REDACTED-IN-ASSERT>")
        );
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).expect("stdout is not valid JSON")
    }

    fn err_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stderr).expect("stderr is not valid JSON")
    }
}

fn readsafe(args: &[&str], stdin: Option<&str>, cwd: Option<&Path>) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_readsafe"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn().expect("failed to run readsafe");
    if let Some(input) = stdin {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code().unwrap_or(-1),
    }
}

/// Copy a fixture into a fresh temp dir so mutating tests are isolated.
fn sandbox(test: &str, fixture_names: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("readsafe-cli-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for name in fixture_names {
        fs::copy(fixtures().join(name), dir.join(name)).unwrap();
    }
    dir
}

fn assert_no_temp_leftovers(dir: &Path) {
    let leftovers: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("readsafe-tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary file left behind");
}

// ---------------------------------------------------------------- inspect

#[test]
fn inspect_reports_structure_without_values() {
    let path = fixtures().join("canary.env");
    let run = readsafe(&["inspect", path.to_str().unwrap(), "--json"], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    let manifest = run.json();
    assert_eq!(manifest["schemaVersion"], "0.1");
    let variables = manifest["files"][0]["variables"].as_array().unwrap();

    let get = |name: &str| {
        variables
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("missing variable {name}"))
    };
    assert_eq!(get("DATABASE_URL")["type"], "url");
    assert_eq!(get("DATABASE_URL")["sensitive"], true);
    assert_eq!(get("API_PORT")["type"], "port");
    assert_eq!(get("API_PORT")["sensitive"], false);
    assert_eq!(get("SUPPORT_EMAIL")["type"], "email");
    assert_eq!(get("API_TOKEN")["sensitive"], true);
    assert_eq!(get("API_TOKEN")["descriptionRedacted"], true);
    assert_eq!(get("AWS_SECRET_ACCESS_KEY")["sensitive"], true);
    assert_eq!(get("REQUEST_ID")["type"], "uuid");
    for variable in variables {
        assert_eq!(variable["valueExposed"], false);
        assert!(variable.get("value").is_none());
    }
    // Canonical ordering: variables sorted by name.
    let names: Vec<&str> = variables
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn inspect_human_output_is_also_clean() {
    let path = fixtures().join("canary.env");
    let run = readsafe(&["inspect", path.to_str().unwrap()], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("DATABASE_URL"));
}

#[test]
fn inspect_is_deterministic() {
    let path = fixtures().join("canary.env");
    let first = readsafe(&["inspect", path.to_str().unwrap(), "--json"], None, None);
    let second = readsafe(&["inspect", path.to_str().unwrap(), "--json"], None, None);
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
}

#[test]
fn inspect_out_writes_clean_manifest() {
    let dir = sandbox("inspect-out", &["canary.env"]);
    let run = readsafe(
        &["inspect", "canary.env", "--out", "manifest.json"],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let written = fs::read_to_string(dir.join("manifest.json")).unwrap();
    assert!(
        !written.contains(CANARY),
        "canary leaked into --out manifest"
    );
    let manifest: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(manifest["files"][0]["kind"], "dotenv");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inspect_directory_finds_dotenv_and_reads_env_example_required() {
    let dir = fixtures().join("reqdir");
    let run = readsafe(&["inspect", dir.to_str().unwrap(), "--json"], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    let manifest = run.json();
    let files = manifest["files"].as_array().unwrap();
    let env_file = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("/.env"))
        .unwrap();
    let variables = env_file["variables"].as_array().unwrap();
    let needed = variables.iter().find(|v| v["name"] == "NEEDED").unwrap();
    let extra = variables.iter().find(|v| v["name"] == "EXTRA").unwrap();
    assert_eq!(needed["required"], true);
    assert_eq!(extra["required"], false);
}

#[test]
fn inspect_unsupported_format_is_exit_3() {
    let dir = sandbox("unsupported", &[]);
    fs::write(dir.join("notes.txt"), "CANARY_TXT_0000\n").unwrap();
    let run = readsafe(&["inspect", "notes.txt", "--json"], None, Some(&dir));
    run.assert_clean();
    assert_eq!(run.code, 3);
    assert_eq!(run.err_json()["error"]["code"], "UNSUPPORTED_FORMAT");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inspect_malformed_file_counts_lines_without_echoing() {
    let path = fixtures().join("malformed.env");
    let run = readsafe(&["inspect", path.to_str().unwrap(), "--json"], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    let manifest = run.json();
    assert_eq!(manifest["files"][0]["malformedLines"], 2);
}

#[test]
fn inspect_missing_file_is_exit_4() {
    let run = readsafe(&["inspect", "/nonexistent/.env", "--json"], None, None);
    assert_eq!(run.code, 4);
    assert_eq!(run.err_json()["error"]["code"], "FILE_NOT_FOUND");
}

// -------------------------------------------------------------------- env

#[test]
fn env_set_dry_run_reports_without_writing() {
    let dir = sandbox("set-dry", &["canary.env"]);
    let before = fs::read_to_string(dir.join("canary.env")).unwrap();
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "NEW_KEY",
            "--value-from-stdin",
            "--dry-run",
            "--json",
        ],
        Some("CANARY_NEW_VALUE_5e5e"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let op = &run.json()["operation"];
    assert_eq!(op["type"], "env.set");
    assert_eq!(op["changed"], true);
    assert_eq!(op["wouldWrite"], true);
    assert_eq!(op["valueExposed"], false);
    assert_eq!(fs::read_to_string(dir.join("canary.env")).unwrap(), before);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_set_apply_touches_only_the_target_line() {
    let dir = sandbox("set-apply", &["canary.env"]);
    let before = fs::read_to_string(dir.join("canary.env")).unwrap();
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "API_PORT",
            "--value-from-stdin",
            "--type",
            "port",
            "--json",
        ],
        Some("9090"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["operation"]["written"], true);
    let after = fs::read_to_string(dir.join("canary.env")).unwrap();
    assert_eq!(after, before.replace("API_PORT=8080", "API_PORT=9090"));
    assert_no_temp_leftovers(&dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_set_same_value_is_a_no_op() {
    let dir = sandbox("set-noop", &["canary.env"]);
    let before = fs::read_to_string(dir.join("canary.env")).unwrap();
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "APP_NAME",
            "--value-from-stdin",
            "--json",
        ],
        Some("readsafe-demo"),
        Some(&dir),
    );
    run.assert_clean();
    let op = &run.json()["operation"];
    assert_eq!(op["changed"], false);
    assert_eq!(op["written"], false);
    assert_eq!(fs::read_to_string(dir.join("canary.env")).unwrap(), before);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_set_updating_a_secret_value_never_echoes_old_or_new() {
    let dir = sandbox("set-secret", &["canary.env"]);
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "API_TOKEN",
            "--value-from-stdin",
            "--json",
        ],
        Some("CANARY_REPLACEMENT_TOKEN_6f6f"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    // Old canary gone from file, new one present, quoting style kept.
    let after = fs::read_to_string(dir.join("canary.env")).unwrap();
    assert!(after.contains("API_TOKEN=\"CANARY_REPLACEMENT_TOKEN_6f6f\"  # rotate quarterly"));
    assert!(!after.contains("CANARY_API_TOKEN_1b2c"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_set_without_stdin_flag_is_usage_error() {
    let dir = sandbox("set-usage", &["canary.env"]);
    let run = readsafe(
        &["env", "set", "canary.env", "K", "--json"],
        Some("value"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 2);
    assert_eq!(run.err_json()["error"]["code"], "USAGE");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_set_invalid_value_reason_is_value_free() {
    let dir = sandbox("set-invalid", &["canary.env"]);
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "SUPPORT_EMAIL",
            "--value-from-stdin",
            "--type",
            "email",
            "--json",
        ],
        Some("CANARY_NOT_AN_EMAIL_7a7a"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 1);
    let error = &run.err_json()["error"];
    assert_eq!(error["code"], "ENV_VALUE_INVALID");
    assert_eq!(error["valueExposed"], false);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_remove_and_rename_flow() {
    let dir = sandbox("remove-rename", &["canary.env"]);
    let run = readsafe(
        &["env", "remove", "canary.env", "EMPTY_VALUE", "--json"],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.json()["operation"]["changed"], true);
    let run = readsafe(
        &["env", "remove", "canary.env", "EMPTY_VALUE", "--json"],
        None,
        Some(&dir),
    );
    assert_eq!(run.json()["operation"]["changed"], false);

    let run = readsafe(
        &[
            "env",
            "rename",
            "canary.env",
            "APP_NAME",
            "SERVICE_NAME",
            "--json",
        ],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let after = fs::read_to_string(dir.join("canary.env")).unwrap();
    assert!(after.contains("SERVICE_NAME=readsafe-demo"));
    assert!(!after.contains("APP_NAME"));

    let run = readsafe(
        &["env", "rename", "canary.env", "MISSING", "X", "--json"],
        None,
        Some(&dir),
    );
    assert_eq!(run.code, 1);
    assert_eq!(run.err_json()["error"]["code"], "ENV_KEY_NOT_FOUND");

    let run = readsafe(
        &[
            "env",
            "rename",
            "canary.env",
            "API_PORT",
            "SERVICE_NAME",
            "--json",
        ],
        None,
        Some(&dir),
    );
    assert_eq!(run.code, 1);
    assert_eq!(run.err_json()["error"]["code"], "ENV_KEY_EXISTS");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_keys_are_refused_with_exit_6() {
    let dir = sandbox("dup", &["duplicate.env"]);
    for args in [
        vec!["env", "remove", "duplicate.env", "DUP_KEY", "--json"],
        vec![
            "env",
            "rename",
            "duplicate.env",
            "DUP_KEY",
            "OTHER",
            "--json",
        ],
        vec![
            "env",
            "test",
            "duplicate.env",
            "DUP_KEY",
            "--type",
            "int",
            "--json",
        ],
    ] {
        let run = readsafe(&args, None, Some(&dir));
        run.assert_clean();
        assert_eq!(run.code, 6, "args: {args:?}");
        assert_eq!(run.err_json()["error"]["code"], "ENV_DUPLICATE_KEY");
    }
    let run = readsafe(
        &[
            "env",
            "set",
            "duplicate.env",
            "DUP_KEY",
            "--value-from-stdin",
            "--json",
        ],
        Some("x"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 6);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_test_validates_without_returning_value() {
    let path = fixtures().join("canary.env");
    let path = path.to_str().unwrap();
    let ok = readsafe(
        &[
            "env",
            "test",
            path,
            "SUPPORT_EMAIL",
            "--type",
            "email",
            "--json",
        ],
        None,
        None,
    );
    ok.assert_clean();
    assert_eq!(ok.code, 0);
    assert_eq!(ok.json()["operation"]["valid"], true);

    let bad = readsafe(
        &["env", "test", path, "API_TOKEN", "--type", "port", "--json"],
        None,
        None,
    );
    bad.assert_clean();
    assert_eq!(bad.code, 1);
    let op = &bad.json()["operation"];
    assert_eq!(op["valid"], false);
    assert_eq!(op["reason"], "value is not a valid TCP port");

    let missing = readsafe(
        &[
            "env",
            "test",
            path,
            "NO_SUCH_KEY",
            "--type",
            "int",
            "--json",
        ],
        None,
        None,
    );
    missing.assert_clean();
    assert_eq!(missing.code, 1);
    assert_eq!(missing.err_json()["error"]["code"], "ENV_KEY_NOT_FOUND");

    let bad_spec = readsafe(
        &["env", "test", path, "API_PORT", "--type", "nope", "--json"],
        None,
        None,
    );
    bad_spec.assert_clean();
    assert_eq!(bad_spec.code, 2);
    assert_eq!(bad_spec.err_json()["error"]["code"], "INVALID_TYPE_SPEC");
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_unless_allowed() {
    let dir = sandbox("symlink", &["canary.env"]);
    std::os::unix::fs::symlink(dir.join("canary.env"), dir.join("link.env")).unwrap();
    let run = readsafe(&["inspect", "link.env", "--json"], None, Some(&dir));
    run.assert_clean();
    assert_eq!(run.code, 4);
    assert_eq!(run.err_json()["error"]["code"], "SYMLINK_REFUSED");

    let run = readsafe(
        &["inspect", "link.env", "--json", "--allow-symlink"],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let _ = fs::remove_dir_all(&dir);
}

// --------------------------------------------------------- infer/validate

#[test]
fn infer_emits_safe_schema_only() {
    let path = fixtures().join("events.jsonl");
    let run = readsafe(&["infer", path.to_str().unwrap()], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    let schema = run.json();
    for forbidden in [
        "enum",
        "const",
        "examples",
        "default",
        "minLength",
        "maxLength",
        "pattern",
    ] {
        assert!(
            !run.stdout.contains(&format!("\"{forbidden}\"")),
            "forbidden keyword {forbidden} in schema"
        );
    }
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"]["token"].is_object());
    let scan = &schema["x-readsafe"]["scan"];
    assert_eq!(scan["complete"], true);
    assert_eq!(scan["sampledRecords"], 3);
    assert_eq!(scan["malformedRecords"], 1);
    // token appears in every record; user is present in all three too.
    let required = schema["required"].as_array().unwrap();
    assert!(required.iter().any(|v| v == "token"));
}

#[test]
fn infer_schema_out_and_json_inspection_are_clean() {
    let dir = sandbox("infer-out", &["events.jsonl", "config.json"]);
    let run = readsafe(
        &[
            "infer",
            "events.jsonl",
            "--schema-out",
            "events.schema.json",
            "--json",
        ],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let schema_text = fs::read_to_string(dir.join("events.schema.json")).unwrap();
    assert!(
        !schema_text.contains(CANARY),
        "canary leaked into schema file"
    );

    let run = readsafe(&["inspect", "config.json", "--json"], None, Some(&dir));
    run.assert_clean();
    assert_eq!(run.code, 0);
    let manifest = run.json();
    assert_eq!(manifest["files"][0]["experimental"], true);
    let structure = manifest["files"][0]["structure"].as_array().unwrap();
    assert!(structure.iter().any(|p| p["path"] == "$.service.apiKey"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn validate_detects_structure_drift() {
    let dir = sandbox("validate", &["canary.env"]);
    let run = readsafe(
        &["inspect", "canary.env", "--out", "manifest.json"],
        None,
        Some(&dir),
    );
    assert_eq!(run.code, 0);

    let run = readsafe(
        &["validate", "--manifest", "manifest.json", "--json"],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["validation"]["ok"], true);

    // Drift: add a key out of band.
    let mut content = fs::read_to_string(dir.join("canary.env")).unwrap();
    content.push_str("BRAND_NEW_KEY=1\n");
    fs::write(dir.join("canary.env"), content).unwrap();

    let run = readsafe(
        &["validate", "--manifest", "manifest.json", "--json"],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 1);
    let validation = &run.json()["validation"];
    assert_eq!(validation["ok"], false);
    let drift = validation["drift"].as_array().unwrap();
    assert!(drift
        .iter()
        .any(|d| d["name"] == "BRAND_NEW_KEY" && d["change"] == "added"));
    let _ = fs::remove_dir_all(&dir);
}

/// `env set --value-fd N` reads the new value from an inherited descriptor.
/// The harness pipes stdin, which is fd 0, so `--value-fd 0` exercises the
/// descriptor path without an extra dependency.
#[cfg(unix)]
#[test]
fn env_set_value_fd_reads_from_descriptor() {
    let dir = sandbox("set-fd", &["canary.env"]);
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "FD_KEY",
            "--value-fd",
            "0",
            "--json",
        ],
        Some("fd-supplied-value\n"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["operation"]["written"], true);
    let after = fs::read_to_string(dir.join("canary.env")).unwrap();
    assert!(after.contains("FD_KEY=fd-supplied-value"));
    assert_no_temp_leftovers(&dir);
    let _ = fs::remove_dir_all(&dir);
}

/// The two value sources are mutually exclusive; clap rejects the combination
/// before anything is read or written.
#[test]
fn env_set_conflicting_value_sources_are_rejected() {
    let dir = sandbox("set-conflict", &["canary.env"]);
    let before = fs::read_to_string(dir.join("canary.env")).unwrap();
    let run = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "K",
            "--value-from-stdin",
            "--value-fd",
            "0",
        ],
        Some("x"),
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 2);
    assert_eq!(fs::read_to_string(dir.join("canary.env")).unwrap(), before);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn validate_schema_accepts_matching_and_flags_violations_by_path() {
    let dir = sandbox("validate-schema", &["config.json"]);
    let run = readsafe(
        &[
            "infer",
            "config.json",
            "--schema-out",
            "config.schema.json",
            "--json",
        ],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);

    // The source file matches its own inferred schema.
    let run = readsafe(
        &[
            "validate",
            "config.json",
            "--schema",
            "config.schema.json",
            "--json",
        ],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["validation"]["ok"], true);

    // A drifted document: missing a required key, a broad type change, an
    // unexpected key, and a missing nested required key.
    fs::write(
        dir.join("drift.json"),
        r#"{"service": {"name": "x"}, "ports": "not-an-array", "surprise": 1}"#,
    )
    .unwrap();
    let run = readsafe(
        &[
            "validate",
            "drift.json",
            "--schema",
            "config.schema.json",
            "--json",
        ],
        None,
        Some(&dir),
    );
    run.assert_clean();
    assert_eq!(run.code, 1);
    let validation = &run.json()["validation"];
    assert_eq!(validation["ok"], false);
    let drift = validation["drift"].as_array().unwrap();
    let has = |path: &str, name: Option<&str>, change: &str| {
        drift.iter().any(|d| {
            d["path"] == path
                && d["change"] == change
                && match name {
                    Some(n) => d["name"] == n,
                    None => d["name"].is_null(),
                }
        })
    };
    assert!(has("$", Some("debug"), "missingRequired"), "{drift:?}");
    assert!(has("$", Some("surprise"), "unexpected"), "{drift:?}");
    assert!(has("$.ports", None, "typeMismatch"), "{drift:?}");
    assert!(
        has("$.service", Some("apiKey"), "missingRequired"),
        "{drift:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The flagship agent-workflow check: a scripted session that only ever sees
/// ReadSafe output performs a full dotenv change, and the entire transcript
/// (every stdout and stderr byte the agent would observe) is canary-clean —
/// even though the value it supplies and the file it edits are secrets.
#[test]
fn agent_workflow_transcript_is_canary_clean() {
    let dir = sandbox("agent-workflow", &["canary.env"]);
    let secret = "CANARY_AGENT_SUPPLIED_SECRET_9z9z";
    let mut transcript = String::new();
    let mut record = |run: &Run| {
        transcript.push_str(&run.stdout);
        transcript.push_str(&run.stderr);
    };

    // 1. Discover structure without opening the file.
    let step = readsafe(&["inspect", "canary.env", "--json"], None, Some(&dir));
    assert_eq!(step.code, 0);
    record(&step);

    // 2. Redacted dry run of a secret rotation.
    let step = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "API_TOKEN",
            "--value-from-stdin",
            "--dry-run",
            "--json",
        ],
        Some(secret),
        Some(&dir),
    );
    assert_eq!(step.code, 0);
    record(&step);

    // 3. Apply the write.
    let step = readsafe(
        &[
            "env",
            "set",
            "canary.env",
            "API_TOKEN",
            "--value-from-stdin",
            "--json",
        ],
        Some(secret),
        Some(&dir),
    );
    assert_eq!(step.code, 0);
    record(&step);

    // 4. Validate an unrelated key's shape.
    let step = readsafe(
        &[
            "env",
            "test",
            "canary.env",
            "SUPPORT_EMAIL",
            "--type",
            "email",
            "--json",
        ],
        None,
        Some(&dir),
    );
    assert_eq!(step.code, 0);
    record(&step);

    // The write really happened (the file holds the secret)...
    let after = fs::read_to_string(dir.join("canary.env")).unwrap();
    assert!(after.contains(secret));
    // ...but nothing the agent saw contains any canary.
    assert!(
        !transcript.contains(CANARY),
        "agent transcript leaked a canary:\n{}",
        transcript.replace(CANARY, "CANARY<REDACTED-IN-ASSERT>")
    );
    assert_no_temp_leftovers(&dir);
    let _ = fs::remove_dir_all(&dir);
}

/// The packaged forcing skill ships runnable examples; verify they exercise
/// the real CLI, produce the frozen 0.1 contract, and stay redacted — so the
/// documentation cannot drift away from actual behaviour.
#[test]
fn packaged_forcing_skill_examples_match_cli() {
    let package = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/forcing-skill");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(package.join("skill.json")).unwrap()).unwrap();
    assert_eq!(manifest["targetsToolContract"], "0.1");

    let example = package.join("examples/app.env");
    let example = example.to_str().unwrap();

    let run = readsafe(&["inspect", example, "--json"], None, None);
    run.assert_clean();
    assert_eq!(run.code, 0);
    let m = run.json();
    assert_eq!(m["schemaVersion"], "0.1");
    let vars = m["files"][0]["variables"].as_array().unwrap();
    let get = |name: &str| vars.iter().find(|v| v["name"] == name).unwrap();
    assert_eq!(get("DATABASE_URL")["sensitive"], true);
    assert_eq!(get("API_TOKEN")["sensitive"], true);
    assert_eq!(get("API_TOKEN")["descriptionRedacted"], true);
    assert_eq!(get("SUPPORT_EMAIL")["type"], "email");
    assert_eq!(get("API_PORT")["type"], "port");

    let run = readsafe(
        &[
            "env",
            "test",
            example,
            "SUPPORT_EMAIL",
            "--type",
            "email",
            "--json",
        ],
        None,
        None,
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    assert_eq!(run.json()["operation"]["valid"], true);

    // The documented secret-rotation dry run works and exposes nothing.
    let run = readsafe(
        &[
            "env",
            "set",
            example,
            "API_TOKEN",
            "--value-from-stdin",
            "--dry-run",
            "--json",
        ],
        Some("a-brand-new-token"),
        None,
    );
    run.assert_clean();
    assert_eq!(run.code, 0);
    let op = &run.json()["operation"];
    assert_eq!(op["wouldWrite"], true);
    assert_eq!(op["valueExposed"], false);
}

// ------------------------------------------------------------ canary sweep

/// Run every read-only command against every canary fixture and assert no
/// output channel ever contains a canary, regardless of exit status.
#[test]
fn canary_sweep_across_commands_and_fixtures() {
    let fixture_dir = fixtures();
    let dotenvs = ["canary.env", "duplicate.env", "malformed.env"];
    for name in dotenvs {
        let path = fixture_dir.join(name);
        let path = path.to_str().unwrap();
        readsafe(&["inspect", path, "--json"], None, None).assert_clean();
        readsafe(&["inspect", path], None, None).assert_clean();
        readsafe(
            &["env", "test", path, "DUP_KEY", "--type", "int", "--json"],
            None,
            None,
        )
        .assert_clean();
        readsafe(
            &["env", "test", path, "GOOD", "--type", "email", "--json"],
            None,
            None,
        )
        .assert_clean();
        readsafe(
            &["env", "remove", path, "UNCLOSED", "--dry-run", "--json"],
            None,
            None,
        )
        .assert_clean();
    }
    for name in ["events.jsonl", "config.json"] {
        let path = fixture_dir.join(name);
        let path = path.to_str().unwrap();
        readsafe(&["inspect", path, "--json"], None, None).assert_clean();
        readsafe(&["infer", path], None, None).assert_clean();
        readsafe(&["infer", path, "--full-scan"], None, None).assert_clean();
    }
}
