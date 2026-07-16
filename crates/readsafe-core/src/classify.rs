//! Sensitivity classification and broad type inference.
//!
//! Classification fails closed: uncertain signals mark a variable sensitive
//! rather than exposing it. Confidence describes classifier certainty and is
//! never interpreted as permission to expose a value.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub struct Classification {
    pub sensitive: bool,
    pub confidence: Confidence,
}

/// Key-name tokens that mark a variable sensitive regardless of value.
const SENSITIVE_KEY_TOKENS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "key",
    "apikey",
    "credential",
    "credentials",
    "auth",
    "dsn",
    "salt",
    "cert",
    "certificate",
    "session",
    "cookie",
    "signature",
    "private",
    "license",
];

/// Value prefixes of well-known credential formats.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "eyJ",
    "glpat-",
    "npm_",
    "dop_v1_",
    "shpat_",
    "shpss_",
];

pub fn classify(key: &str, value: &str) -> Classification {
    let lower = key.to_ascii_lowercase();
    let key_tokens: Vec<&str> = lower.split(['_', '.', '-']).collect();
    if key_tokens.iter().any(|t| SENSITIVE_KEY_TOKENS.contains(t)) || lower.contains("database_url")
    {
        return Classification {
            sensitive: true,
            confidence: Confidence::High,
        };
    }

    if value.starts_with("-----BEGIN") || is_credential_url(value) {
        return Classification {
            sensitive: true,
            confidence: Confidence::High,
        };
    }
    if TOKEN_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Classification {
            sensitive: true,
            confidence: Confidence::High,
        };
    }
    // Long opaque strings: fail closed with low confidence.
    if value.len() >= 32
        && !value.contains(char::is_whitespace)
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && !value.contains("://")
    {
        return Classification {
            sensitive: true,
            confidence: Confidence::Low,
        };
    }

    Classification {
        sensitive: false,
        confidence: Confidence::Medium,
    }
}

/// A URL whose authority carries `user:password@`.
pub fn is_credential_url(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let authority = &value[scheme_end + 3..];
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    match authority.rfind('@') {
        Some(at) => authority[..at].contains(':'),
        None => false,
    }
}

/// Broad inferred type for the manifest. Only coarse shapes are reported;
/// exact lengths, patterns, and value fragments are never derived here.
pub fn infer_type(key: &str, value: &str) -> (&'static str, Confidence) {
    if value.is_empty() {
        return ("string", Confidence::Low);
    }
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        return ("bool", Confidence::High);
    }
    if let Ok(n) = value.parse::<i64>() {
        if (0..=65535).contains(&n) && key.to_ascii_lowercase().contains("port") {
            return ("port", Confidence::High);
        }
        return ("int", Confidence::High);
    }
    if is_uuid(value) {
        return ("uuid", Confidence::High);
    }
    if is_url_shape(value) {
        return ("url", Confidence::High);
    }
    if is_email_shape(value) {
        return ("email", Confidence::High);
    }
    ("string", Confidence::Medium)
}

pub fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(len, g)| g.len() == *len && g.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn is_url_shape(value: &str) -> bool {
    match value.find("://") {
        Some(idx) if idx > 0 => {
            let scheme = &value[..idx];
            let mut chars = scheme.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                && value.len() > idx + 3
        }
        _ => false,
    }
}

pub fn is_email_shape(value: &str) -> bool {
    let mut parts = value.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && !local.contains(char::is_whitespace)
                && domain.contains('.')
                && is_hostname(domain)
        }
        _ => false,
    }
}

pub fn is_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_name_signals() {
        for key in [
            "API_TOKEN",
            "SECRET",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "PRIVATE_KEY",
            "SESSION_SECRET",
            "DATABASE_URL",
            "public_key",
            "auth.token",
        ] {
            assert!(classify(key, "x").sensitive, "expected sensitive: {key}");
        }
        for key in ["APP_NAME", "TIMEOUT_MS", "SUPPORT_EMAIL", "LOG_LEVEL"] {
            assert!(!classify(key, "plain").sensitive, "expected public: {key}");
        }
    }

    #[test]
    fn value_shape_signals() {
        // Secret-looking values under innocent key names still classify.
        assert!(classify("INNOCENT", "ghp_abcdefghijklmnop1234").sensitive);
        assert!(classify("INNOCENT", "-----BEGIN RSA PRIVATE KEY-----").sensitive);
        assert!(classify("INNOCENT", "postgres://user:pass@host/db").sensitive);
        assert!(
            classify("INNOCENT", "a1B2c3D4e5F6g7H8i9J0a1B2c3D4e5F6").sensitive,
            "long opaque string should fail closed"
        );
        assert!(!classify("HOMEPAGE", "https://example.com/docs").sensitive);
        assert!(!classify("GREETING", "hello world").sensitive);
    }

    #[test]
    fn credential_urls() {
        assert!(is_credential_url("postgres://u:p@h:5432/db"));
        assert!(!is_credential_url("https://example.com/a:b@c"));
        assert!(!is_credential_url("https://user@example.com/"));
        assert!(!is_credential_url("not a url"));
    }

    #[test]
    fn broad_types() {
        assert_eq!(infer_type("X", "true").0, "bool");
        assert_eq!(infer_type("X", "42").0, "int");
        assert_eq!(infer_type("API_PORT", "8080").0, "port");
        assert_eq!(infer_type("X", "8080").0, "int");
        assert_eq!(
            infer_type("X", "123e4567-e89b-12d3-a456-426614174000").0,
            "uuid"
        );
        assert_eq!(infer_type("X", "https://example.com").0, "url");
        assert_eq!(infer_type("X", "a@b.co").0, "email");
        assert_eq!(infer_type("X", "plain text").0, "string");
        assert_eq!(infer_type("X", "").1, Confidence::Low);
    }
}
