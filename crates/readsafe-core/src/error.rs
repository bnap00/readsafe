//! Error types for ReadSafe.
//!
//! Reasons are assembled from fixed strings plus structural identifiers
//! (paths, key names, machine codes). File *values* must never be routed
//! into an error. `reason` is a `&'static str` precisely so that a value
//! cannot be interpolated into it.

/// Machine-readable error codes, frozen for schemaVersion 0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    EnvKeyNotFound,
    EnvKeyExists,
    EnvDuplicateKey,
    EnvValueInvalid,
    EnvInvalidKey,
    FileNotFound,
    FileIo,
    FileNotUtf8,
    SymlinkRefused,
    UnsupportedFormat,
    ParseError,
    InvalidTypeSpec,
    ManifestInvalid,
    UnsafeOutputPrevented,
    Usage,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::EnvKeyNotFound => "ENV_KEY_NOT_FOUND",
            ErrorCode::EnvKeyExists => "ENV_KEY_EXISTS",
            ErrorCode::EnvDuplicateKey => "ENV_DUPLICATE_KEY",
            ErrorCode::EnvValueInvalid => "ENV_VALUE_INVALID",
            ErrorCode::EnvInvalidKey => "ENV_INVALID_KEY",
            ErrorCode::FileNotFound => "FILE_NOT_FOUND",
            ErrorCode::FileIo => "FILE_IO",
            ErrorCode::FileNotUtf8 => "FILE_NOT_UTF8",
            ErrorCode::SymlinkRefused => "SYMLINK_REFUSED",
            ErrorCode::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            ErrorCode::ParseError => "PARSE_ERROR",
            ErrorCode::InvalidTypeSpec => "INVALID_TYPE_SPEC",
            ErrorCode::ManifestInvalid => "MANIFEST_INVALID",
            ErrorCode::UnsafeOutputPrevented => "UNSAFE_OUTPUT_PREVENTED",
            ErrorCode::Usage => "USAGE",
        }
    }

    /// Exit codes frozen by the CLI contract:
    /// 0 success, 1 validation/policy failure, 2 invalid usage,
    /// 3 unsupported format, 4 file access/write failure,
    /// 5 unsafe output prevented, 6 ambiguous operation.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorCode::EnvKeyNotFound
            | ErrorCode::EnvKeyExists
            | ErrorCode::EnvValueInvalid
            | ErrorCode::ManifestInvalid => 1,
            ErrorCode::EnvInvalidKey | ErrorCode::InvalidTypeSpec | ErrorCode::Usage => 2,
            ErrorCode::UnsupportedFormat | ErrorCode::FileNotUtf8 | ErrorCode::ParseError => 3,
            ErrorCode::FileNotFound | ErrorCode::FileIo | ErrorCode::SymlinkRefused => 4,
            ErrorCode::UnsafeOutputPrevented => 5,
            ErrorCode::EnvDuplicateKey => 6,
        }
    }
}

/// An error safe to render on any output channel.
///
/// `reason` is restricted to `&'static str` so a raw file value can never
/// reach an error message through this type.
#[derive(Debug, Clone)]
pub struct SafeError {
    pub code: ErrorCode,
    pub path: Option<String>,
    pub key: Option<String>,
    pub reason: &'static str,
}

impl SafeError {
    pub fn new(code: ErrorCode, reason: &'static str) -> Self {
        SafeError {
            code,
            path: None,
            key: None,
            reason,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }
}

impl std::fmt::Display for SafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.reason)?;
        if let Some(path) = &self.path {
            write!(f, " (path: {path}")?;
            if let Some(key) = &self.key {
                write!(f, ", key: {key}")?;
            }
            write!(f, ")")?;
        } else if let Some(key) = &self.key {
            write!(f, " (key: {key})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SafeError {}
