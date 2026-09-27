//! Test-only source scanning shared by the C2a2 structural tests (T1, T4, T9,
//! T12, T14, T15, T16). One helper set rather than a copy per test: a
//! hand-mirrored scanner is the shape that drifts (AGENTS rule 5).
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
fn matching_brace(text: &str, open: usize) -> Option<usize> {
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
            return rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        }
    }
    String::new()
}

/// The identifier immediately before byte `offset` (which points at a `.`).
pub(crate) fn receiver_before(text: &str, offset: usize) -> String {
    let head = &text[..offset];
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

/// Whether byte `offset` of `text` falls inside one of `ranges`.
pub(crate) fn in_ranges(ranges: &[(usize, usize)], offset: usize) -> bool {
    ranges.iter().any(|(s, e)| (*s..*e).contains(&offset))
}

/// 1-based line number of byte `offset`.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}
