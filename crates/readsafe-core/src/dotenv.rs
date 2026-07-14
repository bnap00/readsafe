//! Lossless dotenv document model.
//!
//! Parsing never fails: lines that cannot be understood are preserved as
//! [`Item::Malformed`] with their exact bytes and are re-emitted verbatim on
//! render. An unedited document renders byte-for-byte identical to its input
//! (ordering, comments, whitespace, quoting, newline style, trailing
//! newline). Edits rewrite only the affected logical line.
//!
//! Raw values live inside [`Entry::value`] and stay inside this process.
//! Nothing in this module formats values into errors or rendered metadata.

use crate::error::{ErrorCode, SafeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    None,
    Single,
    Double,
}

/// One `KEY=value` logical line, possibly spanning multiple physical lines
/// when the value is quoted across newlines.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Exact source bytes for this logical line, including terminators.
    raw: String,
    pub key: String,
    /// Decoded value. Never emitted by callers; see crate-level rules.
    pub value: String,
    pub export: bool,
    pub quote: Quote,
    /// Raw tail after the value, e.g. `"  # rotate quarterly"`. Empty if none.
    inline_tail: String,
    leading_ws: String,
    /// Line terminator to reuse when this entry is rewritten.
    newline: String,
}

impl Entry {
    pub fn has_comment(&self) -> bool {
        self.inline_tail.contains('#')
    }
}

#[derive(Debug, Clone)]
pub enum Item {
    Blank(String),
    Comment(String),
    /// A line (or unterminated quoted block) that is not a valid entry.
    /// Raw bytes are preserved for round-trip but must never be echoed.
    Malformed(String),
    Entry(Entry),
}

impl Item {
    fn raw(&self) -> &str {
        match self {
            Item::Blank(raw) | Item::Comment(raw) | Item::Malformed(raw) => raw,
            Item::Entry(entry) => &entry.raw,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Document {
    pub items: Vec<Item>,
    /// Dominant newline style, used for appended lines.
    newline: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOutcome {
    Created,
    Updated { changed: bool },
}

impl Document {
    pub fn parse(input: &str) -> Document {
        let lines = split_physical(input);
        let newline = dominant_newline(&lines);
        let mut items = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let (content, ending) = &lines[i];
            let trimmed = content.trim_start();
            if trimmed.is_empty() {
                items.push(Item::Blank(format!("{content}{ending}")));
                i += 1;
            } else if trimmed.starts_with('#') {
                items.push(Item::Comment(format!("{content}{ending}")));
                i += 1;
            } else {
                match parse_entry(&lines, i) {
                    Some((entry, consumed)) => {
                        items.push(Item::Entry(entry));
                        i += consumed;
                    }
                    None => {
                        items.push(Item::Malformed(format!("{content}{ending}")));
                        i += 1;
                    }
                }
            }
        }
        Document { items, newline }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for item in &self.items {
            out.push_str(item.raw());
        }
        out
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.items.iter().filter_map(|item| match item {
            Item::Entry(entry) => Some(entry),
            _ => None,
        })
    }

    pub fn malformed_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| matches!(item, Item::Malformed(_)))
            .count()
    }

    /// Whether an entry has an inline comment or sits directly under a
    /// comment line. Used to report `descriptionRedacted` without exposing
    /// the comment text.
    pub fn entry_has_comment(&self, key: &str) -> bool {
        for (idx, item) in self.items.iter().enumerate() {
            if let Item::Entry(entry) = item {
                if entry.key == key {
                    if entry.has_comment() {
                        return true;
                    }
                    if idx > 0 {
                        if let Item::Comment(_) = self.items[idx - 1] {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn indices_of(&self, key: &str) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(idx, item)| match item {
                Item::Entry(entry) if entry.key == key => Some(idx),
                _ => None,
            })
            .collect()
    }

    fn single_index(&self, key: &str) -> Result<Option<usize>, SafeError> {
        let indices = self.indices_of(key);
        match indices.len() {
            0 => Ok(None),
            1 => Ok(Some(indices[0])),
            _ => Err(SafeError::new(
                ErrorCode::EnvDuplicateKey,
                "key appears more than once; refusing ambiguous operation",
            )
            .with_key(key)),
        }
    }

    /// Add or update one key. Refuses duplicate keys.
    pub fn set(&mut self, key: &str, value: &str) -> Result<SetOutcome, SafeError> {
        validate_key(key)?;
        match self.single_index(key)? {
            Some(idx) => {
                let Item::Entry(entry) = &mut self.items[idx] else {
                    unreachable!()
                };
                if entry.value == value {
                    return Ok(SetOutcome::Updated { changed: false });
                }
                entry.value = value.to_string();
                entry.quote = choose_quote(value, entry.quote);
                rebuild_raw(entry);
                Ok(SetOutcome::Updated { changed: true })
            }
            None => {
                self.ensure_trailing_newline();
                let mut entry = Entry {
                    raw: String::new(),
                    key: key.to_string(),
                    value: value.to_string(),
                    export: false,
                    quote: choose_quote(value, Quote::None),
                    inline_tail: String::new(),
                    leading_ws: String::new(),
                    newline: self.newline.clone(),
                };
                rebuild_raw(&mut entry);
                self.items.push(Item::Entry(entry));
                Ok(SetOutcome::Created)
            }
        }
    }

    /// Remove one key. Returns whether the key existed. Refuses duplicates.
    pub fn remove(&mut self, key: &str) -> Result<bool, SafeError> {
        match self.single_index(key)? {
            Some(idx) => {
                self.items.remove(idx);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Rename a key, keeping the value inside the document.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), SafeError> {
        validate_key(new)?;
        if self.single_index(new)?.is_some() {
            return Err(
                SafeError::new(ErrorCode::EnvKeyExists, "target key already exists").with_key(new),
            );
        }
        match self.single_index(old)? {
            Some(idx) => {
                let Item::Entry(entry) = &mut self.items[idx] else {
                    unreachable!()
                };
                entry.key = new.to_string();
                rebuild_raw(entry);
                Ok(())
            }
            None => Err(SafeError::new(ErrorCode::EnvKeyNotFound, "key not found").with_key(old)),
        }
    }

    /// Look up a single entry, refusing duplicates.
    pub fn get(&self, key: &str) -> Result<Option<&Entry>, SafeError> {
        Ok(self.single_index(key)?.map(|idx| {
            let Item::Entry(entry) = &self.items[idx] else {
                unreachable!()
            };
            entry
        }))
    }

    fn ensure_trailing_newline(&mut self) {
        let newline = self.newline.clone();
        if let Some(last) = self.items.last_mut() {
            let ends_with_newline = last.raw().ends_with('\n');
            if !ends_with_newline {
                match last {
                    Item::Blank(raw) | Item::Comment(raw) | Item::Malformed(raw) => {
                        raw.push_str(&newline)
                    }
                    Item::Entry(entry) => {
                        entry.newline = newline.clone();
                        entry.raw.push_str(&newline);
                    }
                }
            }
        }
    }
}

pub fn validate_key(key: &str) -> Result<(), SafeError> {
    let mut chars = key.chars();
    let valid = match chars.next() {
        Some(first) => {
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        }
        None => false,
    };
    if valid {
        Ok(())
    } else {
        Err(SafeError::new(
            ErrorCode::EnvInvalidKey,
            "key must start with a letter or underscore and contain only letters, digits, underscores, or dots",
        ))
    }
}

/// Split into (content, terminator) pairs. A lone `\r` stays in content.
fn split_physical(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut content = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' {
            out.push((std::mem::take(&mut content), "\n".to_string()));
        } else if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
            out.push((std::mem::take(&mut content), "\r\n".to_string()));
        } else {
            content.push(c);
        }
    }
    if !content.is_empty() {
        out.push((content, String::new()));
    }
    out
}

fn dominant_newline(lines: &[(String, String)]) -> String {
    let crlf = lines.iter().filter(|(_, e)| e == "\r\n").count();
    let lf = lines.iter().filter(|(_, e)| e == "\n").count();
    if crlf > lf {
        "\r\n".to_string()
    } else {
        "\n".to_string()
    }
}

/// Parse an entry starting at physical line `start`. Returns the entry and
/// the number of physical lines consumed, or None if malformed.
fn parse_entry(lines: &[(String, String)], start: usize) -> Option<(Entry, usize)> {
    let (content, _) = &lines[start];
    let trimmed = content.trim_start();
    let leading_ws = content[..content.len() - trimmed.len()].to_string();

    let mut rest = trimmed;
    let mut export = false;
    if let Some(after_export) = rest.strip_prefix("export") {
        if after_export.starts_with(char::is_whitespace) {
            export = true;
            rest = after_export.trim_start();
        }
    }

    let eq = rest.find('=')?;
    let key = rest[..eq].trim_end().to_string();
    if validate_key(&key).is_err() {
        return None;
    }
    let after = rest[eq + 1..].trim_start();

    let (value, quote, inline_tail, consumed) =
        if let Some(quote_char) = after.chars().next().filter(|c| *c == '"' || *c == '\'') {
            parse_quoted(lines, start, &after[1..], quote_char)?
        } else {
            let (value, tail) = split_unquoted(after);
            (value, Quote::None, tail, 1)
        };

    let mut raw = String::new();
    for (line_content, line_ending) in &lines[start..start + consumed] {
        raw.push_str(line_content);
        raw.push_str(line_ending);
    }
    let newline = lines[start + consumed - 1].1.clone();

    Some((
        Entry {
            raw,
            key,
            value,
            export,
            quote,
            inline_tail,
            leading_ws,
            newline,
        },
        consumed,
    ))
}

/// Scan a quoted value that may span physical lines. `first` is the text of
/// the opening line after the opening quote.
fn parse_quoted(
    lines: &[(String, String)],
    start: usize,
    first: &str,
    quote_char: char,
) -> Option<(String, Quote, String, usize)> {
    let mut buf = first.to_string();
    let mut consumed = 1;
    loop {
        if let Some(close) = find_close(&buf, quote_char) {
            let value_raw = &buf[..close];
            let remainder = &buf[close + quote_char.len_utf8()..];
            let rem_trimmed = remainder.trim_start();
            let inline_tail = if rem_trimmed.is_empty() {
                String::new()
            } else if rem_trimmed.starts_with('#') {
                remainder.to_string()
            } else {
                // Junk after the closing quote: treat as malformed.
                return None;
            };
            let value = if quote_char == '"' {
                unescape_double(value_raw)
            } else {
                value_raw.to_string()
            };
            let quote = if quote_char == '"' {
                Quote::Double
            } else {
                Quote::Single
            };
            return Some((value, quote, inline_tail, consumed));
        }
        // Quote continues onto the next physical line.
        if start + consumed >= lines.len() {
            return None; // unterminated
        }
        buf.push_str(&lines[start + consumed - 1].1);
        buf.push_str(&lines[start + consumed].0);
        consumed += 1;
    }
}

fn find_close(s: &str, quote_char: char) -> Option<usize> {
    let mut escaped = false;
    for (idx, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote_char == '"' && c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote_char {
            return Some(idx);
        }
    }
    None
}

/// Split an unquoted value from its inline comment. A `#` starts a comment
/// only at the beginning of the value or after whitespace.
fn split_unquoted(after: &str) -> (String, String) {
    let mut prev_ws = true;
    for (idx, c) in after.char_indices() {
        if c == '#' && prev_ws {
            // Back up over the whitespace so the tail preserves it.
            let ws_start = after[..idx].trim_end().len();
            return (after[..ws_start].to_string(), after[ws_start..].to_string());
        }
        prev_ws = c.is_whitespace();
    }
    (after.trim_end().to_string(), String::new())
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('$') => out.push('$'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn needs_quoting(value: &str) -> bool {
    value.chars().any(|c| {
        c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\' | '$' | '`') || c.is_control()
    })
}

/// Keep the original quoting style when it can represent the new value;
/// upgrade to double quotes when it cannot.
fn choose_quote(value: &str, previous: Quote) -> Quote {
    match previous {
        Quote::Double => Quote::Double,
        Quote::Single => {
            if value.contains('\'') {
                Quote::Double
            } else {
                Quote::Single
            }
        }
        Quote::None => {
            if needs_quoting(value) {
                Quote::Double
            } else {
                Quote::None
            }
        }
    }
}

fn rebuild_raw(entry: &mut Entry) {
    let quoted = match entry.quote {
        Quote::None => entry.value.clone(),
        Quote::Single => format!("'{}'", entry.value),
        Quote::Double => format!("\"{}\"", escape_double(&entry.value)),
    };
    let export = if entry.export { "export " } else { "" };
    entry.raw = format!(
        "{}{}{}={}{}{}",
        entry.leading_ws, export, entry.key, quoted, entry.inline_tail, entry.newline
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(input: &str) {
        let doc = Document::parse(input);
        assert_eq!(doc.render(), input, "round-trip failed");
    }

    #[test]
    fn roundtrips_exactly() {
        let cases = [
            "",
            "A=1\n",
            "A=1",
            "# comment\n\nA=1\nB=two words no quotes\n",
            "export A=1\n  INDENTED=x\n",
            "A='single quoted'\nB=\"double \\\"quoted\\\"\"\n",
            "A=value # trailing comment\nB=v#notcomment\n",
            "CRLF=1\r\nOTHER=2\r\n",
            "MIXED=1\r\nUNIX=2\n",
            "MULTI=\"line one\nline two\"\nAFTER=1\n",
            "MALFORMED LINE WITHOUT EQUALS\nA=1\n",
            "UNCLOSED=\"never closes\nstill inside\n",
            "EMPTY=\nWS=   \nTRAILING=x   \n",
            "1BAD=starts with digit\n",
            "A==double equals\n",
            "UNICODE=héllo wörld\n",
            "TAIL='v'   # spaced comment\n",
        ];
        for case in cases {
            roundtrip(case);
        }
    }

    #[test]
    fn parses_values() {
        let doc = Document::parse(
            "A=plain\nB=\"esc\\n\\\"aped\\\"\"\nC='lit\\eral'\nD=with # comment\nE=\n",
        );
        let vals: Vec<(&str, &str)> = doc
            .entries()
            .map(|e| (e.key.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(
            vals,
            vec![
                ("A", "plain"),
                ("B", "esc\n\"aped\""),
                ("C", "lit\\eral"),
                ("D", "with"),
                ("E", ""),
            ]
        );
    }

    #[test]
    fn multiline_value_is_decoded_and_preserved() {
        let input = "M=\"one\ntwo\"\nN=1\n";
        let doc = Document::parse(input);
        let m = doc.get("M").unwrap().unwrap();
        assert_eq!(m.value, "one\ntwo");
        assert_eq!(doc.render(), input);
    }

    #[test]
    fn set_updates_only_target_line() {
        let input = "# head\nA=1\nB=\"two\"  # note\nC=3\n";
        let mut doc = Document::parse(input);
        let outcome = doc.set("B", "new value").unwrap();
        assert_eq!(outcome, SetOutcome::Updated { changed: true });
        assert_eq!(doc.render(), "# head\nA=1\nB=\"new value\"  # note\nC=3\n");
    }

    #[test]
    fn set_same_value_reports_unchanged() {
        let mut doc = Document::parse("A=1\n");
        assert_eq!(
            doc.set("A", "1").unwrap(),
            SetOutcome::Updated { changed: false }
        );
        assert_eq!(doc.render(), "A=1\n");
    }

    #[test]
    fn set_appends_with_newline_repair() {
        let mut doc = Document::parse("A=1");
        assert_eq!(doc.set("B", "2").unwrap(), SetOutcome::Created);
        assert_eq!(doc.render(), "A=1\nB=2\n");
    }

    #[test]
    fn set_appends_crlf_in_crlf_file() {
        let mut doc = Document::parse("A=1\r\nB=2\r\n");
        doc.set("C", "3").unwrap();
        assert_eq!(doc.render(), "A=1\r\nB=2\r\nC=3\r\n");
    }

    #[test]
    fn set_quotes_values_that_need_it() {
        let mut doc = Document::parse("A=1\n");
        doc.set("A", "two words").unwrap();
        assert_eq!(doc.render(), "A=\"two words\"\n");
        doc.set("A", "line1\nline2").unwrap();
        assert_eq!(doc.render(), "A=\"line1\\nline2\"\n");
    }

    #[test]
    fn duplicate_key_is_refused() {
        let mut doc = Document::parse("D=1\nX=2\nD=3\n");
        let err = doc.set("D", "z").unwrap_err();
        assert_eq!(err.code, ErrorCode::EnvDuplicateKey);
        let err = doc.remove("D").unwrap_err();
        assert_eq!(err.code, ErrorCode::EnvDuplicateKey);
        let err = doc.get("D").unwrap_err();
        assert_eq!(err.code, ErrorCode::EnvDuplicateKey);
    }

    #[test]
    fn remove_and_rename() {
        let mut doc = Document::parse("A=1\nB=2\nC=3\n");
        assert!(doc.remove("B").unwrap());
        assert!(!doc.remove("B").unwrap());
        doc.rename("C", "D").unwrap();
        assert_eq!(doc.render(), "A=1\nD=3\n");
        let err = doc.rename("MISSING", "E").unwrap_err();
        assert_eq!(err.code, ErrorCode::EnvKeyNotFound);
        let err = doc.rename("A", "D").unwrap_err();
        assert_eq!(err.code, ErrorCode::EnvKeyExists);
    }

    #[test]
    fn export_prefix_is_preserved_on_edit() {
        let mut doc = Document::parse("export TOKEN='old'\n");
        doc.set("TOKEN", "new").unwrap();
        assert_eq!(doc.render(), "export TOKEN='new'\n");
    }

    #[test]
    fn malformed_lines_are_counted_not_lost() {
        let doc = Document::parse("GOOD=1\nnot a real line\nALSO=2\n");
        assert_eq!(doc.malformed_count(), 1);
        assert_eq!(doc.entries().count(), 2);
    }
}
