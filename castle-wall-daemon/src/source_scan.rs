//! Test-only source scanning shared by the C2a2 structural tests (T1, T4, T9,
//! T12, T14, T15, T16) and the C2a2b journal-writer parity tests (T2, T7, T-P1 to
//! T-P3). One helper set rather than a copy per test: a hand-mirrored scanner is
//! the shape that drifts (AGENTS rule 5).
//!
//! These read the crate's own source files from `CARGO_MANIFEST_DIR`; they never
//! touch operator state.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `<crate>/<dir>`, recursively, as (path relative to the
/// crate root with `/` separators, contents), sorted by path.
pub(crate) fn rust_files_under(dir: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.join(dir)];
    while let Some(next) = stack.pop() {
        let entries = std::fs::read_dir(&next)
            .unwrap_or_else(|e| panic!("cannot read source dir {next:?}: {e}"));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot read an entry of {next:?}: {e}"))
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or_else(|e| panic!("{path:?} is outside the crate: {e}"))
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
                out.push((rel, text));
            }
        }
    }
    out.sort();
    out
}

/// The crate's library and daemon-binary source: every `src/**/*.rs` except the
/// separate `src/bin/` executables, which never host the stop guard.
pub(crate) fn daemon_sources() -> Vec<(String, String)> {
    rust_files_under("src")
        .into_iter()
        .filter(|(path, _)| !path.starts_with("src/bin/"))
        .collect()
}

/// Byte ranges of every `#[cfg(test)]` module body (`#[cfg(test)]` line followed
/// by a `mod <name> {` line), matched by brace depth. Braces inside string, raw
/// string and char literals and inside `//` comments are ignored.
pub(crate) fn cfg_test_module_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut search = 0;
    while let Some(found) = text[search..].find("#[cfg(test)]") {
        let attr = search + found;
        search = attr + "#[cfg(test)]".len();
        let after = &text[search..];
        let next_line = after.trim_start();
        let is_mod = next_line.starts_with("mod ") || next_line.starts_with("pub mod ");
        if !is_mod {
            continue;
        }
        let Some(open_rel) = after.find('{') else {
            continue;
        };
        // A `mod x;` declaration (no body) ends at `;` before any `{`.
        if after[..open_rel].contains(';') {
            continue;
        }
        let open = search + open_rel;
        if let Some(close) = matching_brace(text, open) {
            ranges.push((attr, close + 1));
            search = close + 1;
        }
    }
    ranges
}

/// Index of the `}` matching the `{` at `open`.
pub(crate) fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'r' if matches!(bytes.get(i + 1), Some(b'"') | Some(b'#'))
                && (i == 0 || !is_ident_byte(bytes[i - 1])) =>
            {
                let mut hashes = 0;
                let mut j = i + 1;
                while bytes.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if bytes.get(j) == Some(&b'"') {
                    let mut close = String::from("\"");
                    close.push_str(&"#".repeat(hashes));
                    let from = j + 1;
                    let end = text[from..].find(&close)? + from + close.len();
                    i = end;
                    continue;
                }
            }
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal: 'x', '\n', '\''. A lifetime has no closing quote
                // within the next few bytes and is left alone.
                if bytes.get(i + 1) == Some(&b'\\') {
                    if let Some(rel) = text[i + 3..].find('\'') {
                        i += 3 + rel;
                    }
                } else if bytes.get(i + 2) == Some(&b'\'') {
                    i += 2;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `text` with every `#[cfg(test)]` module body blanked (replaced by spaces,
/// newlines kept so line numbers survive): the production part of a file.
pub(crate) fn production_part(text: &str) -> String {
    let mut out: Vec<u8> = text.as_bytes().to_vec();
    for (start, end) in cfg_test_module_ranges(text) {
        for byte in &mut out[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `text` with every whole-line `//` comment blanked, so a token named in prose
/// (a doc comment explaining a rule) is not read as code.
pub(crate) fn without_comment_lines(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The name of the `fn` whose signature most closely precedes byte `offset`.
pub(crate) fn enclosing_fn(text: &str, offset: usize) -> String {
    for line in text[..offset].lines().rev() {
        let mut t = line.trim_start();
        loop {
            let before = t;
            for prefix in [
                "pub(crate) ",
                "pub(super) ",
                "pub ",
                "unsafe ",
                "extern \"C\" ",
                "const ",
                "async ",
            ] {
                if let Some(rest) = t.strip_prefix(prefix) {
                    t = rest;
                }
            }
            if t == before {
                break;
            }
        }
        if let Some(rest) = t.strip_prefix("fn ") {
            return rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
        }
    }
    String::new()
}

/// The identifier immediately before byte `offset` (which points at a `.`).
///
/// Whitespace and newlines between the receiver and the `.` are skipped, so
/// rustfmt's wrapped method-chain form (`self.flag` on one line, `.store(true`
/// indented on the next) resolves to the same receiver as the one-line form.
/// Without that, a wrapped writer read as the empty receiver and was silently
/// dropped from every writer-set scan (round-1 code gate).
///
/// A zero-argument accessor call (`self.engine.mutation_cancel_flag()`) resolves
/// to the accessor's name. Any other shape (a call with arguments, an index, a
/// parenthesised expression) returns the empty string, which callers must treat
/// as unclassifiable, never as "not a stop flag".
pub(crate) fn receiver_before(text: &str, offset: usize) -> String {
    let head = text[..offset].trim_end();
    let head = head.strip_suffix("()").unwrap_or(head);
    let start = head
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
        .map(|i| i + 1)
        .unwrap_or(0);
    head[start..].to_string()
}

/// Every byte offset of `needle` in `text`.
pub(crate) fn offsets_of(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle).map(|(i, _)| i).collect()
}

/// Every byte offset of `needle` in `text` that is NOT preceded by an identifier
/// character, a `.` or a `:`.
///
/// This is the "unqualified call" reading: `store(` matches a call of a local or
/// injected `store`, while `.store(` (an atomic's method), `x_store(` (another
/// function) and `journal::store(` (a path-qualified call) do not.
pub(crate) fn offsets_of_unqualified(text: &str, needle: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    offsets_of(text, needle)
        .into_iter()
        .filter(|&at| {
            at == 0 || {
                let prev = bytes[at - 1];
                !(is_ident_byte(prev) || prev == b'.' || prev == b':')
            }
        })
        .collect()
}

/// The top-level parameters of the first parenthesised list in `signature`, as
/// `(name, type)` pairs.
///
/// The list is split at commas at bracket depth zero, depth counted over `()`,
/// `<>` and `[]`, where the `>` of a `->` is not a closing angle bracket; so a
/// closure type such as `impl FnOnce(&Path, &Record) -> Result<(), Error>` stays one
/// parameter. The name is the text before the first single `:` (never a `::`), and
/// the type is the rest with every run of whitespace collapsed to one space. A
/// receiver such as `&self` has an empty type. Empty entries (a trailing comma) are
/// skipped.
pub(crate) fn top_level_params(signature: &str) -> Vec<(String, String)> {
    let Some(open) = signature.find('(') else {
        return Vec::new();
    };
    let bytes = signature.as_bytes();
    let mut out = Vec::new();
    let mut push = |raw: &str| {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        let rb = raw.as_bytes();
        let colon = (0..rb.len()).find(|&i| {
            rb[i] == b':' && rb.get(i + 1) != Some(&b':') && (i == 0 || rb[i - 1] != b':')
        });
        let (name, ty) = match colon {
            Some(i) => (&raw[..i], &raw[i + 1..]),
            None => (raw, ""),
        };
        out.push((
            name.split_whitespace().collect::<Vec<_>>().join(" "),
            ty.split_whitespace().collect::<Vec<_>>().join(" "),
        ));
    };
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'<' => depth += 1,
            b'>' if i > 0 && bytes[i - 1] == b'-' => {}
            b')' | b']' | b'>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    push(&signature[start..i]);
                    break;
                }
            }
            b',' if depth == 1 => {
                push(&signature[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// `text` with the CONTENTS of every string literal (plain, escaped, and raw
/// `r"..."`/`r#"..."#`) replaced by spaces, quotes and newlines kept, so a word in a
/// message is not read as an identifier. A `'"'` char literal is not a string.
pub(crate) fn blank_string_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'\'') => {
                i += 3;
                continue;
            }
            b'r' if matches!(bytes.get(i + 1), Some(b'"') | Some(b'#'))
                && (i == 0 || !is_ident_byte(bytes[i - 1])) =>
            {
                let mut hashes = 0;
                let mut j = i + 1;
                while bytes.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if bytes.get(j) == Some(&b'"') {
                    let close = format!("\"{}", "#".repeat(hashes));
                    let from = j + 1;
                    let end = text[from..]
                        .find(&close)
                        .map(|o| from + o)
                        .unwrap_or(bytes.len());
                    blank(&mut out, from, end);
                    i = end + close.len();
                    continue;
                }
            }
            b'"' => {
                let from = i + 1;
                let mut j = from;
                while j < bytes.len() && bytes[j] != b'"' {
                    if bytes[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let end = j.min(bytes.len());
                blank(&mut out, from, end);
                i = end + 1;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether byte `offset` of `text` falls inside one of `ranges`.
pub(crate) fn in_ranges(ranges: &[(usize, usize)], offset: usize) -> bool {
    ranges.iter().any(|(s, e)| (*s..*e).contains(&offset))
}

/// 1-based line number of byte `offset`.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

/// The text of `fn <name>(` in `code`, from the signature to the brace that
/// closes its body. Braces in literals are not modelled; the functions this is
/// used on contain none that are unbalanced.
pub(crate) fn fn_body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} must exist"));
    let open = start
        + code[start..]
            .find('{')
            .unwrap_or_else(|| panic!("fn {name} must have a body"));
    let close = matching_brace(code, open).unwrap_or_else(|| panic!("fn {name} is unterminated"));
    &code[start..=close]
}

/// The `///` doc-comment block immediately above `fn <name>(` in `text`.
pub(crate) fn doc_block_of(text: &str, name: &str) -> String {
    let at = text
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} must exist"));
    let mut docs: Vec<&str> = text[..at]
        .lines()
        .rev()
        .skip(1)
        .map(str::trim)
        .take_while(|l| l.starts_with("///") || l.starts_with("#["))
        .collect();
    docs.reverse();
    docs.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{blank_string_literals, offsets_of_unqualified, receiver_before, top_level_params};

    /// Words inside plain, escaped, multi-line and raw string literals are blanked;
    /// code outside them, a `'"'` char literal, and line structure survive.
    #[test]
    fn blank_string_literals_hides_only_literal_contents() {
        let text = "let a = journal; f(\"the journal key\", '\"', journal)\n\
                    g(\"x \\\" journal \\\n  journal\")\n\
                    h(r#\"raw journal \"quoted\" \"#, journal.path())";
        let blanked = blank_string_literals(text);
        assert_eq!(blanked.len(), text.len());
        assert_eq!(blanked.lines().count(), text.lines().count());
        assert_eq!(blanked.matches("journal").count(), 3, "{blanked}");
        assert!(blanked.contains("'\"'"));
        assert!(blanked.contains("journal.path()"));
    }

    /// The unqualified reading excludes a method call, a longer identifier and a
    /// path-qualified call, and keeps a bare call. The needle is assembled with
    /// `concat!` so this module's own source never reads as a journal writer.
    #[test]
    fn offsets_of_unqualified_keeps_only_a_bare_call() {
        const NEEDLE: &str = concat!("sto", "re(");
        let text = format!(
            "flag.{NEEDLE}true); x_{NEEDLE}a); journal::{NEEDLE}b); {NEEDLE}c);\n{NEEDLE}d)"
        );
        let hits = offsets_of_unqualified(&text, NEEDLE);
        let tails: Vec<&str> = hits
            .iter()
            .map(|&at| &text[at + NEEDLE.len()..at + NEEDLE.len() + 1])
            .collect();
        assert_eq!(tails, vec!["c", "d"], "{text}");
    }

    /// W2's signature yields its five parameters, and the injected store's closure
    /// type is kept whole (its `->` does not close an angle bracket).
    #[test]
    fn top_level_params_splits_the_confined_writer_signature() {
        let signature = "fn persist_confined_uid_write_ahead_with_store(
    journal: &OwnedJournalHandle,
    key: &JournalAuthKey,
    uid: u32,
    role: ConfinedRole,
    store: impl FnOnce(&Path, &OwnershipJournal, &JournalAuthKey) -> Result<(), OwnershipJournalError>,
) -> Result<WriteAheadReceipt, OwnershipJournalError> {";
        let params = top_level_params(signature);
        let names: Vec<&str> = params.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["journal", "key", "uid", "role", "store"]);
        assert_eq!(params[0].1, "&OwnedJournalHandle");
        assert_eq!(
            params[4].1,
            "impl FnOnce(&Path, &OwnershipJournal, &JournalAuthKey) -> Result<(), OwnershipJournalError>"
        );
        // A path type keeps its `::` and a receiver has an empty type.
        let params = top_level_params("fn f(&self, p: &std::path::Path, m: Map<u32, Vec<u8>>)");
        assert_eq!(
            params,
            vec![
                ("&self".to_string(), String::new()),
                ("p".to_string(), "&std::path::Path".to_string()),
                ("m".to_string(), "Map<u32, Vec<u8>>".to_string()),
            ]
        );
    }

    /// The one-line and the rustfmt-wrapped method-chain forms name the same
    /// receiver. The store token is assembled with `concat!` so this module's own
    /// source never reads as a stop-flag writer to T14's scan.
    #[test]
    fn receiver_before_reads_through_the_wrapped_chain_form() {
        const STORE: &str = concat!(".st", "ore(true, Ordering::SeqCst);");
        for (text, receiver) in [
            (format!("self.shutdown_flag{STORE}"), "shutdown_flag"),
            (
                format!("self.daemon_shutdown_request\n            {STORE}"),
                "daemon_shutdown_request",
            ),
            (format!("flag\r\n\t{STORE}"), "flag"),
            (
                format!("self.decision_engine\n    .mutation_cancel_flag()\n    {STORE}"),
                "mutation_cancel_flag",
            ),
            (format!("flags[0]{STORE}"), ""),
        ] {
            let at = text.find(STORE).expect("store");
            assert_eq!(receiver_before(&text, at), receiver, "{text:?}");
        }
    }
}
