#!/usr/bin/env python3
"""
Castle Wall daemon stdout-discipline gate.

Asserts that every `println!` or `eprintln!` macro call in non-test Rust
source files inside `castle-wall-daemon/src/` is annotated with a `// SAFETY:`
comment naming why raw stdout/stderr is the contract at that site (CLI help
text, parse-error reporting, startup or shutdown banners that operators or
smoke harnesses scrape, etc.). The gate exits 0 with a one-line PASS message
when the daemon is clean, and exits 1 with a list of unannotated sites
otherwise.

Lines inside `#[cfg(test)] mod` blocks are excluded from the scan: test code
uses `println!`/`eprintln!` for diagnostic output and converting it to a
structured logger is not the job of this gate. Files under
`castle-wall-daemon/tests/` are also excluded; they are Cargo integration
test crates by convention.

Closes full-sweep finding #98 (21 raw println/eprintln occurrences in the
daemon source). Without this gate, future commits could re-introduce
unannotated stdout/stderr writes in production paths and erode the daemon's
operator log surface (raw writes bypass any structured logging facility
operators wire up later).

The annotation walk-back is parallel to the panic-discipline gate but uses a
distinct marker (`SAFETY:`, capital case) so the two domains stay
independently auditable. A given line is annotated if a `// SAFETY:` comment
appears within a 20-line window above the call site, with the walk-back
allowed to traverse contiguous println/eprintln calls and line comments
(stops at blank lines or any other code).

Usage:
    python3 castle-wall-daemon/scripts/check-stdout-discipline.py
    python3 castle-wall-daemon/scripts/check-stdout-discipline.py --quiet
    python3 castle-wall-daemon/scripts/check-stdout-discipline.py --root <path>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable

PRINTLN_OR_EPRINTLN_RE = re.compile(r"\b(println|eprintln)\s*!")
CFG_TEST_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
MOD_DECL_RE = re.compile(r"^\s*(pub\s+)?mod\s+\w+")
# Match `// SAFETY: ...` line comments only. Exclude `///` (outer doc) and
# `//!` (inner doc), which are rustdoc syntax and the wrong place for inline
# channel-contract notes. Capital `SAFETY:` is intentional and distinct from
# the panic-discipline gate's `Safety:` so the two domains stay separate.
SAFETY_COMMENT_RE = re.compile(r"^\s*//[^/!].*\bSAFETY:")
LINE_COMMENT_RE = re.compile(r"^\s*//[^/!]")
LOOKBACK_LIMIT = 20


@dataclass(frozen=True)
class Site:
    """A single `println!` or `eprintln!` call site."""

    path: str
    line: int  # 1-based
    text: str


def find_test_mod_lines(lines: list[str]) -> list[bool]:
    """
    Return a list of booleans the same length as `lines`, where True marks a
    line as part of a `#[cfg(test)]` followed by `mod ... { ... }` block.

    Mirrors the panic-discipline gate's parser by design: brace-counting that
    ignores braces inside line comments and string literals, including
    single-line and MULTI-LINE raw strings (`r"..."`, `r#"..."#` with any
    hash count) and multi-line normal strings. String state is tracked across
    line boundaries via `scrub_lines`, so a brace inside a raw-string JSON
    fixture cannot desync the depth counter and end the test region early
    (the false-positive that cost a CI round on PR #500).
    """
    n = len(lines)
    in_test = [False] * n
    scrubbed_lines = scrub_lines(lines)
    i = 0
    while i < n:
        if CFG_TEST_RE.match(lines[i]):
            j = i + 1
            while j < n and lines[j].strip() == "":
                j += 1
            if j < n and MOD_DECL_RE.match(lines[j]):
                start = i
                k = j
                while k < n and "{" not in scrubbed_lines[k]:
                    k += 1
                if k >= n:
                    break
                depth = 0
                started = False
                end_line = None
                m = k
                while m < n:
                    stripped = scrubbed_lines[m]
                    for ch in stripped:
                        if ch == "{":
                            depth += 1
                            started = True
                        elif ch == "}":
                            depth -= 1
                            if started and depth == 0:
                                end_line = m
                                break
                    if end_line is not None:
                        break
                    m += 1
                if end_line is not None:
                    for q in range(start, end_line + 1):
                        in_test[q] = True
                    i = end_line + 1
                    continue
        i += 1
    return in_test


def scrub_lines(lines: list[str]) -> list[str]:
    """
    Scrub a whole file's worth of lines at once, tracking string state across
    line boundaries. Returns a list the same length as `lines`, where string
    contents and `//` line-comment tails are replaced with placeholder spaces
    so that brace-counting and macro-name matching only see structural source.

    Handles, conservatively and line-based:
      * single-line and multi-line normal strings (`"..."`), honoring
        backslash escapes;
      * single-line and multi-line raw strings (`r"..."`, `r#"..."#`, any
        hash count), in which backslashes are literal and the only terminator
        is a `"` followed by the matching number of `#`;
      * nested quote characters inside raw strings (a `"` that is not followed
        by the right hash count does not end the raw string);
      * char literals (`'x'`, `'\\n'`, `'\\''`, `'"'`, `'\\u{..}'`), consumed as
        inert units so a `"` inside one cannot open string state, while a bare
        lifetime tick (`'a`, `'static`) is left untouched;
      * single-line and MULTI-LINE `/* ... */` block comments, including Rust's
        nested block comments, so a stray `"` inside a block comment cannot
        open a persistent string state that masks real code below it.

    While inside any string or block comment the emitted characters are
    spaces, so braces and `println!`/`eprintln!` tokens inside that content
    never count.

    Kept byte-identical to the panic-discipline gate's helper of the same name
    so the two gates stay auditable as a pair.
    """
    out: list[str] = []
    # `state` carries the open context across lines:
    #   None                      -> not in a string or block comment
    #   ("normal", None)          -> inside a "..." string
    #   ("raw", n)                -> inside an r#..#"..."#..# raw string whose
    #                                terminator is `"` + n `#`
    #   ("block", depth)          -> inside a `/* ... */` block comment nested
    #                                `depth` levels deep (Rust block comments
    #                                nest, so depth tracks `/*`/`*/` balance)
    state: tuple[str, int | None] | None = None
    for line in lines:
        scrubbed, state = _scrub_one(line, state)
        out.append(scrubbed)
    return out


def _scrub_one(
    line: str, state: tuple[str, int | None] | None
) -> tuple[str, tuple[str, int | None] | None]:
    """Scrub a single line given the inbound multi-line `state`.

    Returns `(scrubbed_line, outbound_state)`.
    """
    out: list[str] = []
    i = 0
    length = len(line)
    while i < length:
        c = line[i]
        # --- currently inside a `/* ... */` block comment (may nest) ---
        if state is not None and state[0] == "block":
            depth = state[1] or 0
            if c == "/" and i + 1 < length and line[i + 1] == "*":
                depth += 1
                state = ("block", depth)
                out.append("  ")
                i += 2
                continue
            if c == "*" and i + 1 < length and line[i + 1] == "/":
                depth -= 1
                if depth <= 0:
                    state = None
                else:
                    state = ("block", depth)
                out.append("  ")
                i += 2
                continue
            out.append(" ")
            i += 1
            continue
        # --- currently inside a multi-line string ---
        if state is not None:
            kind, hashes = state
            if kind == "normal":
                if c == "\\" and i + 1 < length:
                    out.append("  ")
                    i += 2
                    continue
                if c == '"':
                    state = None
                    out.append(" ")
                    i += 1
                    continue
                out.append(" ")
                i += 1
                continue
            # raw string: only `"` + the right number of `#` terminates it;
            # backslashes are literal and quotes inside are content.
            if c == '"':
                h = 0
                while i + 1 + h < length and line[i + 1 + h] == "#":
                    h += 1
                if h >= (hashes or 0):
                    state = None
                    consume = 1 + (hashes or 0)
                    out.append(" " * consume)
                    i += consume
                    continue
                out.append(" ")
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        # --- not in a string ---
        # char literal: `'x'`, `'\n'`, `'\''`, `'"'`. Must be consumed as a
        # unit so a `"` inside it does not toggle string state and blank the
        # rest of the file. A bare `'` that is NOT a complete char literal is
        # a lifetime tick (`'a`, `'static`) and is emitted verbatim.
        char_lit = _match_char_literal(line, i)
        if char_lit is not None:
            out.append(" " * char_lit)
            i += char_lit
            continue
        raw_open = _match_raw_open(line, i)
        if raw_open is not None:
            consumed, hashes = raw_open
            out.append(" " * consumed)
            i += consumed
            state = ("raw", hashes)
            continue
        if c == '"':
            state = ("normal", None)
            out.append(" ")
            i += 1
            continue
        # block comment opener `/*` (Rust block comments nest). Tested before
        # the `//` line-comment case so `/*` is not mistaken for `//`.
        if c == "/" and i + 1 < length and line[i + 1] == "*":
            state = ("block", 1)
            out.append("  ")
            i += 2
            continue
        if c == "/" and i + 1 < length and line[i + 1] == "/":
            out.extend([" "] * (length - i))
            break
        out.append(c)
        i += 1
    return "".join(out), state


def _match_raw_open(line: str, i: int) -> tuple[int, int] | None:
    """If a raw-string opener begins at index `i`, return
    `(chars_consumed_through_opening_quote, hash_count)`; else None.

    Recognizes the plain raw form `r"`, `r#"`, `r##"`, ... and the prefixed
    raw forms with a single byte-string (`b`) or C-string (`c`) prefix:
    `br"`, `br#"`, `cr"`, `cr#"`, ... All are raw strings whose terminator is
    `"` followed by the same number of `#`. The opener must be at an
    identifier boundary so a token like `for"` or `expr#` is not misread (the
    char before the prefix/`r` must not be an identifier character).
    """
    c = line[i]
    if c not in ("r", "b", "c"):
        return None
    if i > 0:
        prev = line[i - 1]
        if prev.isalnum() or prev == "_":
            return None
    j = i
    # optional single `b` (byte-string) or `c` (C-string) prefix before `r`.
    if c in ("b", "c"):
        j += 1
        if j >= len(line) or line[j] != "r":
            return None
    j += 1
    hashes = 0
    while j < len(line) and line[j] == "#":
        hashes += 1
        j += 1
    if j < len(line) and line[j] == '"':
        return (j - i + 1, hashes)
    return None


def _match_char_literal(line: str, i: int) -> int | None:
    """If a complete char literal begins at index `i`, return its length in
    characters (so the caller can blank it); else None.

    Recognizes `'x'` (any single non-`'`, non-`\\` char, including `"`) and
    `'\\<esc>'` (a backslash escape, e.g. `'\\n'`, `'\\''`, `'\\\\'`, `'\\u{1F600}'`).
    Deliberately conservative: a `'` that does not close into a valid char
    literal is treated as a lifetime tick (`'a`, `'static`) by returning None,
    so the caller emits the `'` verbatim and does NOT enter string state.

    Kept byte-identical to the panic-discipline gate's helper of the same name.
    """
    if i >= len(line) or line[i] != "'":
        return None
    n = len(line)
    # Escaped char literal: '\<...>'
    if i + 1 < n and line[i + 1] == "\\":
        j = i + 2
        if j >= n:
            return None
        if line[j] == "u" and j + 1 < n and line[j + 1] == "{":
            k = line.find("}", j + 2)
            if k == -1:
                return None
            j = k + 1
        else:
            j += 1
        if j < n and line[j] == "'":
            return (j - i + 1)
        return None
    # Simple char literal: 'x' where x is a single char that is not ' or \.
    if i + 2 < n and line[i + 1] != "'" and line[i + 2] == "'":
        return 3
    return None


# Backwards-compatible single-line wrapper. Scrubs one isolated line with no
# inbound multi-line state. Multi-line correctness comes from `scrub_lines`;
# this remains for any caller that scrubs a known-standalone line.
def _strip_comments_and_strings(line: str) -> str:
    scrubbed, _ = _scrub_one(line, None)
    return scrubbed


def find_println_eprintln_sites(path: str, lines: list[str]) -> list[Site]:
    """Return all production-code `println!`/`eprintln!` sites in `lines`."""
    in_test = find_test_mod_lines(lines)
    scrubbed_lines = scrub_lines(lines)
    sites: list[Site] = []
    for idx, line in enumerate(lines):
        if in_test[idx]:
            continue
        if PRINTLN_OR_EPRINTLN_RE.search(scrubbed_lines[idx]):
            sites.append(Site(path=path, line=idx + 1, text=line.rstrip("\n")))
    return sites


def is_annotated(lines: list[str], site_index: int) -> bool:
    """
    Walk back from `site_index` (0-based) up to LOOKBACK_LIMIT lines, looking
    for a `// SAFETY:` comment. Stop early at a blank line or at any line
    containing non-print, non-comment code. The walk-back deliberately
    traverses contiguous `println!`/`eprintln!` calls and `//` line comments
    so that a single annotation can cover a structural output block (CLI
    help, multi-line banners, etc.) that shares one channel-contract.

    Scrubbing is done over the whole `lines` array so multi-line string state
    is tracked correctly; a `println!` literal inside a multi-line string
    above the site does not short-circuit the walk-back.
    """
    scrubbed_lines = scrub_lines(lines)
    start = max(0, site_index - LOOKBACK_LIMIT)
    for j in range(site_index - 1, start - 1, -1):
        line = lines[j]
        stripped = line.strip()
        if stripped == "":
            return False
        if SAFETY_COMMENT_RE.match(line):
            return True
        if LINE_COMMENT_RE.match(line):
            continue
        if PRINTLN_OR_EPRINTLN_RE.search(scrubbed_lines[j]):
            continue
        # Multi-line macro continuations: a line that is purely arguments
        # (no semicolon-terminated statement, no other macro call) and lives
        # inside a `println!(...)` or `eprintln!(...)` invocation should not
        # break the walk-back. Detect via "no recognizable code" heuristic:
        # if the scrubbed line contains only punctuation/whitespace plus
        # identifier fragments and ends with a comma or open paren, treat
        # it as a continuation. This is a permissive readiness signal; the
        # strict line-by-line lookback for the macro-name line is what
        # establishes the SAFETY contract.
        if _looks_like_macro_continuation(scrubbed_lines[j]):
            continue
        return False
    return False


_CONTINUATION_RE = re.compile(r"^[\s\w\.,&\*\(\)\[\]\{\}:'\"<>+\-/=!?]*$")


def _looks_like_macro_continuation(scrubbed: str) -> bool:
    """
    Heuristic: a line with no statement-terminator (`;`) and no recognizable
    Rust keyword that would re-open scope is treated as a multi-line macro
    argument continuation. This avoids a false negative when an annotated
    `eprintln!(...)` spans several lines and the next call site walks back
    through them. False positives here only widen the lookback; the SAFETY
    comment must still be present within LOOKBACK_LIMIT.
    """
    if ";" in scrubbed:
        return False
    s = scrubbed.strip()
    if not s:
        return False
    # Reject lines containing structural statement starters that should
    # break the walk (let, if, match, fn, return, etc.).
    leading = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)", scrubbed)
    if leading:
        word = leading.group(1)
        breakers = {
            "let",
            "if",
            "else",
            "match",
            "fn",
            "return",
            "for",
            "while",
            "loop",
            "use",
            "mod",
            "struct",
            "enum",
            "impl",
            "trait",
            "pub",
            "const",
            "static",
            "type",
            "unsafe",
        }
        if word in breakers:
            return False
    return bool(_CONTINUATION_RE.match(scrubbed))


def collect_rust_src_files(root: str) -> list[str]:
    """List all .rs files under `<root>/src/` (production code only)."""
    src_root = os.path.join(root, "src")
    if not os.path.isdir(src_root):
        return []
    out: list[str] = []
    for cur, _dirs, files in os.walk(src_root):
        for name in files:
            if name.endswith(".rs"):
                out.append(os.path.join(cur, name))
    out.sort()
    return out


def scan(root: str) -> tuple[list[Site], list[Site]]:
    """Return (annotated, unannotated) production-code sites under `<root>/src/`."""
    annotated: list[Site] = []
    unannotated: list[Site] = []
    for path in collect_rust_src_files(root):
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for site in find_println_eprintln_sites(path, lines):
            if is_annotated(lines, site.line - 1):
                annotated.append(site)
            else:
                unannotated.append(site)
    return annotated, unannotated


def format_failure(unannotated: Iterable[Site], root: str) -> str:
    out = [
        "Castle Wall daemon stdout-discipline gate FAILED.",
        "",
        "Each `println!` or `eprintln!` call in non-test Rust source must",
        "carry an immediately preceding `// SAFETY:` comment naming why raw",
        "stdout/stderr is the contract at that site. See:",
        "  castle-wall-daemon/docs/PANIC_DISCIPLINE.md (Log discipline section)",
        "",
        "Unannotated sites:",
    ]
    for site in unannotated:
        rel = os.path.relpath(site.path, start=root)
        out.append(f"  {rel}:{site.line}: {site.text.strip()}")
    out.append("")
    out.append(
        "Fix by adding a `// SAFETY: <reason>` comment block above the call site,"
    )
    out.append(
        "or by routing the message through a structured logging facility if the"
    )
    out.append(
        "site is residual debug output (in which case raw stdout/stderr is the"
    )
    out.append("wrong channel).")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Castle Wall daemon stdout-discipline gate"
    )
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="Path to the castle-wall-daemon directory (default: parent of scripts/)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress success output"
    )
    args = parser.parse_args(argv)

    annotated, unannotated = scan(args.root)
    if unannotated:
        print(format_failure(unannotated, args.root), file=sys.stderr)
        return 1

    if not args.quiet:
        print(
            f"Castle Wall daemon stdout-discipline gate PASS: "
            f"{len(annotated)} annotated production-code site(s), 0 unannotated."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
