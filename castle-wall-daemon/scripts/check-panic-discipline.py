#!/usr/bin/env python3
"""
Castle Wall daemon panic-discipline gate.

Asserts that every `.unwrap()` or `.expect(...)` call in non-test Rust source
files inside `castle-wall-daemon/src/` has an immediately preceding
`// Safety:` comment naming the local invariant that protects it. The gate
exits 0 with a one-line PASS message when the daemon is clean, and exits 1
with a list of unannotated sites otherwise.

Lines inside `#[cfg(test)] mod` blocks are excluded from the scan: test code
uses unwrap/expect idiomatically and converting it to Result-propagation
makes test failures less informative. Files under `castle-wall-daemon/tests/`
are also excluded; they are Cargo integration test crates by convention.

Closes the panic-discipline framework introduced in PR #138 (full-sweep #58
production code pass). Without this gate, future commits could re-introduce
unannotated unwrap/expect in production paths and erode the daemon's
Castle Layer 1 availability under stress.

Usage:
    python3 castle-wall-daemon/scripts/check-panic-discipline.py
    python3 castle-wall-daemon/scripts/check-panic-discipline.py --quiet
    python3 castle-wall-daemon/scripts/check-panic-discipline.py --root <path>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable

UNWRAP_OR_EXPECT_RE = re.compile(r"\.(unwrap|expect)\(")
CFG_TEST_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
MOD_DECL_RE = re.compile(r"^\s*(pub\s+)?mod\s+\w+")
# Match `// Safety: ...` line comments only. Exclude `///` (outer doc) and
# `//!` (inner doc), which are rustdoc syntax and the wrong place for inline
# invariant notes.
SAFETY_COMMENT_RE = re.compile(r"^\s*//[^/!].*\bSafety:")
LOOKBACK_LIMIT = 20


@dataclass(frozen=True)
class Site:
    """A single `.unwrap()` or `.expect(` call site."""

    path: str
    line: int  # 1-based
    text: str


def find_test_mod_lines(lines: list[str]) -> list[bool]:
    """
    Return a list of booleans the same length as `lines`, where True marks a
    line as part of a `#[cfg(test)]` followed by `mod ... { ... }` block. The
    matcher tracks brace depth and ignores braces inside line comments and
    double-quoted strings; it does not parse raw-string literals or character
    literals, both of which are extremely rare for `{`/`}` in real Rust source
    and not present anywhere in the daemon today. Improving precision later
    will not break sites already covered.
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
    comment with placeholder spaces, so brace-counting only sees structural
    `{`/`}` characters. Backslash-escaped quotes inside strings are honored.
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


def find_unwrap_expect_sites(path: str, lines: list[str]) -> list[Site]:
    """Return all production-code `.unwrap()/.expect(` sites in `lines`."""
    in_test = find_test_mod_lines(lines)
    sites: list[Site] = []
    for idx, line in enumerate(lines):
        if in_test[idx]:
            continue
        scrubbed = _strip_comments_and_strings(line)
        if UNWRAP_OR_EXPECT_RE.search(scrubbed):
            sites.append(Site(path=path, line=idx + 1, text=line.rstrip("\n")))
    return sites


def is_annotated(lines: list[str], site_index: int) -> bool:
    """
    Walk back from `site_index` (0-based) up to LOOKBACK_LIMIT lines, looking
    for a `// Safety:` comment. Stop early if we hit a blank line or another
    unwrap/expect site (whose Safety annotation belongs to it, not us).
    """
    start = max(0, site_index - LOOKBACK_LIMIT)
    for j in range(site_index - 1, start - 1, -1):
        line = lines[j]
        if line.strip() == "":
            return False
        scrubbed = _strip_comments_and_strings(line)
        if UNWRAP_OR_EXPECT_RE.search(scrubbed):
            return False
        if SAFETY_COMMENT_RE.match(line):
            return True
    return False


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
        for site in find_unwrap_expect_sites(path, lines):
            if is_annotated(lines, site.line - 1):
                annotated.append(site)
            else:
                unannotated.append(site)
    return annotated, unannotated


def format_failure(unannotated: Iterable[Site], root: str) -> str:
    out = [
        "Castle Wall daemon panic-discipline gate FAILED.",
        "",
        "Each .unwrap() or .expect(...) call in non-test Rust source must",
        "carry an immediately preceding `// Safety:` comment naming the",
        "local invariant that protects it. See:",
        "  castle-wall-daemon/docs/PANIC_DISCIPLINE.md",
        "",
        "Unannotated sites:",
    ]
    for site in unannotated:
        rel = os.path.relpath(site.path, start=root)
        out.append(f"  {rel}:{site.line}: {site.text.strip()}")
    out.append("")
    out.append(
        "Fix by adding a `// Safety: <reason>` comment block above the call site,"
    )
    out.append(
        "or by converting the call to `?`-operator propagation if the failure"
    )
    out.append("can actually occur at runtime.")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Castle Wall daemon panic-discipline gate")
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
            f"Castle Wall daemon panic-discipline gate PASS: "
            f"{len(annotated)} annotated production-code site(s), 0 unannotated."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
