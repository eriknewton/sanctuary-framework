#!/usr/bin/env python3
"""
Castle Wall daemon panic-discipline gate.

Asserts that no unannotated `.unwrap()` or `.expect(...)` calls exist in
non-test Rust source files under castle-wall-daemon/src/.

A call is allowed if either:
  1. It sits inside a `#[cfg(test)] mod <name> { ... }` block, OR
  2. A `// Safety:` comment (case-insensitive) appears in the contiguous
     comment block immediately above the statement containing the call.

Origin: PR #138 closed full-sweep finding #58 by annotating the 5
production-code panic sites with `// Safety:` invariants. This gate
prevents new unannotated panics from landing.

Exit codes:
  0  no violations
  1  one or more unannotated panics found
  2  invalid invocation
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Match exactly `.unwrap()` or `.expect(` — excludes `.unwrap_or(`,
# `.unwrap_or_else(`, `.unwrap_or_default()`, `.unwrap_unchecked()`,
# `.expect_err(`, etc.
CALL_RE = re.compile(r"\.(?:unwrap\(\)|expect\()")
SAFETY_RE = re.compile(r"^\s*//\s*safety\s*:", re.IGNORECASE)
COMMENT_RE = re.compile(r"^\s*//")
CFG_TEST_RE = re.compile(r"#\[cfg\(test\)\]")
MOD_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+\w+")

# Per-line scrub: strip line comments and string/char literals so a
# `.unwrap()` token inside a string or comment, or `{` / `}` characters
# inside a JSON-shaped string literal, do not skew matching.
LINE_COMMENT_RE = re.compile(r"//.*$")
STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
CHAR_RE = re.compile(r"'(?:[^'\\]|\\.)'")


def scrub(line: str) -> str:
    """Strip line comments and single-line string/char literals."""
    line = LINE_COMMENT_RE.sub("", line)
    line = STRING_RE.sub('""', line)
    line = CHAR_RE.sub("'_'", line)
    return line


def find_test_mod_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Return inclusive (start_line, end_line) 0-indexed ranges covering
    every `#[cfg(test)] mod ... { ... }` block."""
    ranges: list[tuple[int, int]] = []
    n = len(lines)
    i = 0
    while i < n:
        if not CFG_TEST_RE.search(lines[i]):
            i += 1
            continue
        # `#[cfg(test)]` may decorate a struct field, fn, or mod. We only
        # care about mod blocks.
        j = i + 1
        while j < n and lines[j].strip() == "":
            j += 1
        if j >= n or not MOD_RE.match(lines[j]):
            i += 1
            continue
        # Find the opening `{` from the mod line forward.
        brace_line = j
        while brace_line < n and "{" not in scrub(lines[brace_line]):
            brace_line += 1
        if brace_line >= n:
            break
        # Walk char-by-char from the first `{` and balance until depth
        # returns to 0.
        depth = 0
        end_line = brace_line
        started = False
        for line_idx in range(brace_line, n):
            normalized = scrub(lines[line_idx])
            pos = normalized.index("{") if line_idx == brace_line else 0
            for c in normalized[pos:]:
                if c == "{":
                    depth += 1
                    started = True
                elif c == "}":
                    depth -= 1
                    if started and depth == 0:
                        end_line = line_idx
                        break
            if started and depth == 0:
                break
        ranges.append((i, end_line))
        i = end_line + 1
    return ranges


def in_any_range(ranges: list[tuple[int, int]], idx: int) -> bool:
    return any(start <= idx <= end for start, end in ranges)


def find_statement_start(lines: list[str], call_idx: int) -> int:
    """Return the line index where the statement containing `call_idx`
    begins. Walks upward, accepting lines as continuations of the same
    statement until it hits a clear statement boundary (blank line,
    line above is a comment, or line above ends with `;` / `{` / `}`)."""
    k = call_idx
    while k > 0:
        prev = lines[k - 1]
        prev_scrub = scrub(prev).rstrip()
        if prev_scrub == "":
            return k
        if COMMENT_RE.match(prev):
            return k
        if prev_scrub.endswith((";", "{", "}")):
            return k
        k -= 1
    return 0


def is_annotated(lines: list[str], call_idx: int) -> bool:
    """True iff a `// Safety:` comment sits in the contiguous comment
    block immediately above the statement containing `call_idx`."""
    start = find_statement_start(lines, call_idx)
    k = start - 1
    while k >= 0 and COMMENT_RE.match(lines[k]):
        if SAFETY_RE.match(lines[k]):
            return True
        k -= 1
    return False


def check_file(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text().splitlines()
    test_ranges = find_test_mod_ranges(lines)
    violations: list[tuple[int, str]] = []
    for i, raw_line in enumerate(lines):
        if not CALL_RE.search(scrub(raw_line)):
            continue
        if in_any_range(test_ranges, i):
            continue
        if is_annotated(lines, i):
            continue
        violations.append((i + 1, raw_line.rstrip()))
    return violations


def main(argv: list[str]) -> int:
    src_dir = Path(argv[1]) if len(argv) > 1 else Path("castle-wall-daemon/src")
    if not src_dir.is_dir():
        print(f"error: {src_dir} is not a directory", file=sys.stderr)
        return 2
    rs_files = sorted(src_dir.rglob("*.rs"))
    if not rs_files:
        print(f"error: no .rs files found under {src_dir}", file=sys.stderr)
        return 2
    total = 0
    for path in rs_files:
        for line_no, text in check_file(path):
            print(f"{path}:{line_no}: {text}")
            total += 1
    if total:
        print("", file=sys.stderr)
        print(
            f"FAIL: {total} unannotated .unwrap()/.expect() call(s) in non-test code under {src_dir}.",
            file=sys.stderr,
        )
        print("Each production-code panic site must either:", file=sys.stderr)
        print(
            "  1. Live inside a `#[cfg(test)] mod <name> { ... }` block, OR",
            file=sys.stderr,
        )
        print(
            "  2. Carry a `// Safety: <invariant>` comment in the contiguous",
            file=sys.stderr,
        )
        print(
            "     comment block immediately above the containing statement, OR",
            file=sys.stderr,
        )
        print(
            "  3. Be converted to `?`-propagation or explicit error handling.",
            file=sys.stderr,
        )
        print(
            "See PR #138 for the annotation pattern and rfcs/RFC-0003 for the",
            file=sys.stderr,
        )
        print("Castle Layer 1 panic-discipline rationale.", file=sys.stderr)
        return 1
    print(
        f"OK: 0 unannotated .unwrap()/.expect() in {len(rs_files)} Rust file(s) under {src_dir}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
