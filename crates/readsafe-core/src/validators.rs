//! Value validators for `readsafe env test` and `env set --type`.
//!
//! Validation reasons are `&'static str` so the tested value can never be
//! interpolated into a result or error message.

use crate::classify;
use crate::error::{ErrorCode, SafeError};

#[derive(Debug, Clone)]
pub enum ValueType {
    Email,
    Url,
    Port,
    Hostname,
    Uuid,
    Semver,
    Int,
    Bool,
    Enum(Vec<String>),
    Regex(regex_lite::Regex),
}

impl ValueType {
    pub fn name(&self) -> &'static str {
        match self {
            ValueType::Email => "email",
            ValueType::Url => "url",
            ValueType::Port => "port",
            ValueType::Hostname => "hostname",
            ValueType::Uuid => "uuid",
            ValueType::Semver => "semver",
            ValueType::Int => "int",
            ValueType::Bool => "bool",
            ValueType::Enum(_) => "enum",
            ValueType::Regex(_) => "regex",
        }
    }
}

/// Parse a `--type` spec such as `email`, `enum(a,b,c)`, or `regex(^v\d+$)`.
pub fn parse_type(spec: &str) -> Result<ValueType, SafeError> {
    match spec {
        "email" => return Ok(ValueType::Email),
        "url" => return Ok(ValueType::Url),
        "port" => return Ok(ValueType::Port),
        "hostname" => return Ok(ValueType::Hostname),
        "uuid" => return Ok(ValueType::Uuid),
        "semver" => return Ok(ValueType::Semver),
        "int" => return Ok(ValueType::Int),
        "bool" => return Ok(ValueType::Bool),
        _ => {}
    }
    if let Some(inner) = spec.strip_prefix("enum(").and_then(|s| s.strip_suffix(')')) {
        let options: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if options.is_empty() {
            return Err(SafeError::new(
                ErrorCode::InvalidTypeSpec,
                "enum(...) requires at least one option",
            ));
        }
        return Ok(ValueType::Enum(options));
    }
    if let Some(inner) = spec
        .strip_prefix("regex(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let anchored = format!("^(?:{inner})$");
        return match regex_lite::Regex::new(&anchored) {
            Ok(re) => Ok(ValueType::Regex(re)),
            Err(_) => Err(SafeError::new(
                ErrorCode::InvalidTypeSpec,
                "regex(...) pattern failed to compile",
            )),
        };
    }
    Err(SafeError::new(
        ErrorCode::InvalidTypeSpec,
        "unknown type; expected one of email, url, port, hostname, uuid, semver, int, bool, enum(...), regex(...)",
    ))
}

/// Validate a value. Returns a static failure reason that never contains
/// the value.
pub fn validate(value_type: &ValueType, value: &str) -> Result<(), &'static str> {
    let ok = match value_type {
        ValueType::Email => classify::is_email_shape(value),
        ValueType::Url => classify::is_url_shape(value),
        ValueType::Port => matches!(value.parse::<u32>(), Ok(n) if (1..=65535).contains(&n)),
        ValueType::Hostname => classify::is_hostname(value),
        ValueType::Uuid => classify::is_uuid(value),
        ValueType::Semver => is_semver(value),
        ValueType::Int => value.parse::<i64>().is_ok(),
        ValueType::Bool => {
            let lower = value.to_ascii_lowercase();
            lower == "true" || lower == "false"
        }
        ValueType::Enum(options) => options.iter().any(|o| o == value),
        ValueType::Regex(re) => re.is_match(value),
    };
    if ok {
        Ok(())
    } else {
        Err(match value_type {
            ValueType::Email => "value is not a valid email address",
            ValueType::Url => "value is not a valid URL",
            ValueType::Port => "value is not a valid TCP port",
            ValueType::Hostname => "value is not a valid hostname",
            ValueType::Uuid => "value is not a valid UUID",
            ValueType::Semver => "value is not a valid semantic version",
            ValueType::Int => "value is not a valid integer",
            ValueType::Bool => "value is not a boolean",
            ValueType::Enum(_) => "value is not one of the allowed enum options",
            ValueType::Regex(_) => "value does not match the supplied pattern",
        })
    }
}

fn is_semver(value: &str) -> bool {
    let core = value.split_once('+').map(|(c, _)| c).unwrap_or(value);
    let (core, _pre) = match core.split_once('-') {
        Some((c, pre)) if !pre.is_empty() => (c, Some(pre)),
        None => (core, None),
        _ => return false,
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(spec: &str, value: &str) -> bool {
        validate(&parse_type(spec).unwrap(), value).is_ok()
    }

    #[test]
    fn validator_table() {
        assert!(check("email", "a@example.com"));
        assert!(!check("email", "not-an-email"));
        assert!(check("url", "https://example.com/x"));
        assert!(!check("url", "example.com"));
        assert!(check("port", "8080"));
        assert!(!check("port", "0"));
        assert!(!check("port", "70000"));
        assert!(check("hostname", "db.internal"));
        assert!(!check("hostname", "-bad-.example"));
        assert!(check("uuid", "123e4567-e89b-12d3-a456-426614174000"));
        assert!(!check("uuid", "123e4567"));
        assert!(check("semver", "1.2.3"));
        assert!(check("semver", "1.2.3-rc.1+build5"));
        assert!(!check("semver", "1.2"));
        assert!(!check("semver", "01.2.3"));
        assert!(check("int", "-42"));
        assert!(!check("int", "4.2"));
        assert!(check("bool", "TRUE"));
        assert!(!check("bool", "yes"));
        assert!(check("enum(dev,staging,prod)", "staging"));
        assert!(!check("enum(dev,staging,prod)", "qa"));
        assert!(check("regex(v\\d+)", "v12"));
        assert!(!check("regex(v\\d+)", "v12x"));
    }

    #[test]
    fn bad_specs_are_usage_errors() {
        assert!(parse_type("nope").is_err());
        assert!(parse_type("enum()").is_err());
        assert!(parse_type("regex(() ").is_err());
    }

    #[test]
    fn failure_reasons_are_static_and_value_free() {
        let err = validate(&parse_type("port").unwrap(), "CANARY_99999").unwrap_err();
        assert!(!err.contains("CANARY"));
    }
}
