//! `readsafe env set|remove|rename|test`: narrow dotenv operations.
//!
//! New values arrive via stdin, never as command arguments. Dry runs and
//! results report the operation only — no diff context, no values.

use crate::inspect::display_path;
use crate::output::Operation;
use readsafe_core::dotenv::{Document, SetOutcome};
use readsafe_core::error::{ErrorCode, SafeError};
use readsafe_core::fsops;
use readsafe_core::validators;
use std::io::Read;
use std::path::Path;

pub struct WriteFlags {
    pub dry_run: bool,
    pub allow_symlink: bool,
}

/// Strip a single trailing newline (LF or CRLF) so both `printf '%s'` and
/// line-buffered producers behave predictably. Never touches interior bytes.
fn strip_one_trailing_newline(mut buf: String) -> String {
    if let Some(stripped) = buf.strip_suffix('\n') {
        buf = stripped.strip_suffix('\r').unwrap_or(stripped).to_string();
    }
    buf
}

/// Read the new value from stdin.
pub fn value_from_stdin() -> Result<String, SafeError> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|_| SafeError::new(ErrorCode::Usage, "could not read value from stdin"))?;
    Ok(strip_one_trailing_newline(buf))
}

/// Read the new value from an inherited file descriptor. This lets a parent
/// process hand ReadSafe a secret without it ever appearing in argv, in shell
/// history, or on a pipe a sibling process could also read. The descriptor is
/// consumed (and closed) here.
#[cfg(unix)]
pub fn value_from_fd(fd: i32) -> Result<String, SafeError> {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    if fd < 0 {
        return Err(SafeError::new(
            ErrorCode::Usage,
            "--value-fd must be a non-negative file descriptor number",
        ));
    }
    if fd == 1 || fd == 2 {
        return Err(SafeError::new(
            ErrorCode::Usage,
            "--value-fd must not be stdout or stderr",
        ));
    }
    // Safety: the descriptor is provided by the caller and expected to be a
    // readable inherited fd. Taking ownership closes it on drop, which is the
    // intended lifetime for a one-shot secret hand-off.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|_| SafeError::new(ErrorCode::Usage, "could not read value from --value-fd"))?;
    Ok(strip_one_trailing_newline(buf))
}

/// File-descriptor value input is a Unix facility; on other platforms callers
/// must use stdin.
#[cfg(not(unix))]
pub fn value_from_fd(_fd: i32) -> Result<String, SafeError> {
    Err(SafeError::new(
        ErrorCode::Usage,
        "--value-fd is only supported on Unix; use --value-from-stdin",
    ))
}

fn load(
    path: &Path,
    allow_symlink: bool,
    create_missing: bool,
) -> Result<(Document, bool), SafeError> {
    match fsops::read_text(path, allow_symlink) {
        Ok(text) => Ok((Document::parse(&text), true)),
        Err(err) if err.code == ErrorCode::FileNotFound && create_missing => {
            Ok((Document::parse(""), false))
        }
        Err(err) => Err(err),
    }
}

fn locate(err: SafeError, path: &Path) -> SafeError {
    if err.path.is_none() {
        err.with_path(display_path(path))
    } else {
        err
    }
}

fn finish_write(
    doc: &Document,
    path: &Path,
    changed: bool,
    flags: &WriteFlags,
    mut operation: Operation,
) -> Result<Operation, SafeError> {
    if flags.dry_run {
        operation.changed = Some(changed);
        operation.would_write = Some(changed);
    } else {
        if changed {
            fsops::atomic_write(path, &doc.render(), flags.allow_symlink)?;
        }
        operation.changed = Some(changed);
        operation.written = Some(changed);
    }
    Ok(operation)
}

pub fn set(
    path: &Path,
    key: &str,
    value: &str,
    value_type: Option<&str>,
    flags: &WriteFlags,
) -> Result<Operation, SafeError> {
    if let Some(spec) = value_type {
        let parsed = validators::parse_type(spec)?;
        validators::validate(&parsed, value).map_err(|reason| {
            SafeError::new(ErrorCode::EnvValueInvalid, reason)
                .with_path(display_path(path))
                .with_key(key)
        })?;
    }
    let (mut doc, _existed) = load(path, flags.allow_symlink, true)?;
    let outcome = doc.set(key, value).map_err(|e| locate(e, path))?;
    let changed = !matches!(outcome, SetOutcome::Updated { changed: false });
    let mut operation = Operation::new("env.set", display_path(path));
    operation.key = Some(key.to_string());
    operation = finish_write(&doc, path, changed, flags, operation)?;
    Ok(operation)
}

pub fn remove(path: &Path, key: &str, flags: &WriteFlags) -> Result<Operation, SafeError> {
    let (mut doc, _) = load(path, flags.allow_symlink, false)?;
    let removed = doc.remove(key).map_err(|e| locate(e, path))?;
    let mut operation = Operation::new("env.remove", display_path(path));
    operation.key = Some(key.to_string());
    finish_write(&doc, path, removed, flags, operation)
}

pub fn rename(
    path: &Path,
    old_key: &str,
    new_key: &str,
    flags: &WriteFlags,
) -> Result<Operation, SafeError> {
    let (mut doc, _) = load(path, flags.allow_symlink, false)?;
    doc.rename(old_key, new_key).map_err(|e| locate(e, path))?;
    let mut operation = Operation::new("env.rename", display_path(path));
    operation.old_key = Some(old_key.to_string());
    operation.new_key = Some(new_key.to_string());
    finish_write(&doc, path, true, flags, operation)
}

/// Validate an existing value without returning it. Exit code 0 when valid,
/// 1 when invalid.
pub fn test(
    path: &Path,
    key: &str,
    type_spec: &str,
    allow_symlink: bool,
) -> Result<(Operation, i32), SafeError> {
    let parsed = validators::parse_type(type_spec)?;
    let (doc, _) = load(path, allow_symlink, false)?;
    let entry = doc.get(key).map_err(|e| locate(e, path))?.ok_or_else(|| {
        SafeError::new(ErrorCode::EnvKeyNotFound, "key not found")
            .with_path(display_path(path))
            .with_key(key)
    })?;
    let mut operation = Operation::new("env.test", display_path(path));
    operation.key = Some(key.to_string());
    match validators::validate(&parsed, &entry.value) {
        Ok(()) => {
            operation.valid = Some(true);
            Ok((operation, 0))
        }
        Err(reason) => {
            operation.valid = Some(false);
            operation.reason = Some(reason);
            Ok((operation, 1))
        }
    }
}
