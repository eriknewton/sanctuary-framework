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
    ignores braces inside line comments and double-quoted strings; raw-string
    and character literals are not parsed (rare in this daemon and not
    present today).
    """
    n = len(lines)
    in_test = [False] * n
    i = 0
    while i < n:
        if CFG_TEST_RE.match(lines[i]):
            j = i + 1
            while j < n and lines[j].strip() == "":
                j += 1
            if j < n and MOD_DECL_RE.match(lines[j]):
                start = i
                k = j
                while k < n and "{" not in _strip_comments_and_strings(lines[k]):
                    k += 1
                if k >= n:
                    break
                depth = 0
                started = False
                end_line = None
                m = k
                while m < n:
                    stripped = _strip_comments_and_strings(lines[m])
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


def _strip_comments_and_strings(line: str) -> str:
    """
    Replace double-quoted string contents and the tail of any `//` line
    comment with placeholder spaces, so brace-counting and macro-name
    matching only see structural source. Backslash-escaped quotes inside
    strings are honored.
    """
    out = []
    i = 0
    in_str = False
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                out.append("  ")
                i += 2
                continue
            if c == '"':
                in_str = False
                out.append(" ")
            else:
                out.append(" ")
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            out.extend([" "] * (len(line) - i))
            break
        out.append(c)
        i += 1
    return "".join(out)


def find_println_eprintln_sites(path: str, lines: list[str]) -> list[Site]:
    """Return all production-code `println!`/`eprintln!` sites in `lines`."""
    in_test = find_test_mod_lines(lines)
    sites: list[Site] = []
    for idx, line in enumerate(lines):
        if in_test[idx]:
            continue
        scrubbed = _strip_comments_and_strings(line)
        if PRINTLN_OR_EPRINTLN_RE.search(scrubbed):
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
    """
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
        scrubbed = _strip_comments_and_strings(line)
        if PRINTLN_OR_EPRINTLN_RE.search(scrubbed):
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
        if _looks_like_macro_continuation(scrubbed):
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
