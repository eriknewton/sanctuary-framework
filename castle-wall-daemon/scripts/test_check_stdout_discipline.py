#!/usr/bin/env python3
"""
Unit tests for `check-stdout-discipline.py`. Run with:

    python3 castle-wall-daemon/scripts/test_check_stdout_discipline.py

Tests cover the parser-aware classification logic, the annotation walk-back
heuristic, and the `#[cfg(test)] mod` exclusion path. The negative tests
stage synthetic Rust source trees in tempdirs; they are independent of the
real daemon source and will continue to pass even as production code
evolves.

Mirrors the panic-discipline gate's self-test shape so the two gates remain
auditable as a pair.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import textwrap
import unittest


def _load_gate_module():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "check_stdout_discipline",
        os.path.join(here, "check-stdout-discipline.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate_module()


def _stage(root: str, rel: str, body: str) -> str:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(body).lstrip("\n"))
    return path


class IsAnnotatedTests(unittest.TestCase):
    def test_safety_directly_above(self):
        lines = [
            "    // SAFETY: stdout is the help contract.\n",
            '    println!("usage: ...");\n',
        ]
        self.assertTrue(GATE.is_annotated(lines, 1))

    def test_safety_covers_contiguous_block(self):
        lines = [
            "    // SAFETY: stdout is the help contract; the block below is\n",
            "    // structural CLI output, not log content.\n",
            '    println!("line one");\n',
            '    println!();\n',
            '    println!("line two");\n',
        ]
        # Each println in the contiguous block resolves the same SAFETY
        # annotation by walking back through earlier prints and comments.
        self.assertTrue(GATE.is_annotated(lines, 2))
        self.assertTrue(GATE.is_annotated(lines, 3))
        self.assertTrue(GATE.is_annotated(lines, 4))

    def test_no_safety_at_all(self):
        lines = [
            "    let x = 1;\n",
            '    println!("residual debug: {}", x);\n',
        ]
        self.assertFalse(GATE.is_annotated(lines, 1))

    def test_safety_separated_by_blank_line(self):
        lines = [
            "    // SAFETY: stdout is the help contract.\n",
            "\n",
            '    println!("residual debug");\n',
        ]
        self.assertFalse(GATE.is_annotated(lines, 2))

    def test_safety_separated_by_unrelated_code(self):
        lines = [
            "    // SAFETY: stdout is the help contract.\n",
            '    println!("safe");\n',
            "    let x = compute();\n",
            '    println!("unsafe: {}", x);\n',
        ]
        self.assertTrue(GATE.is_annotated(lines, 1))
        self.assertFalse(
            GATE.is_annotated(lines, 3),
            "annotation cannot leap over a `let` statement",
        )

    def test_safety_in_doc_comment_does_not_count(self):
        lines = [
            "/// SAFETY: docstring uses SAFETY: but is not a //-comment.\n",
            'println!("...");\n',
        ]
        self.assertFalse(
            GATE.is_annotated(lines, 1),
            "doc comments (///) are not honored as SAFETY annotations",
        )

    def test_lowercase_safety_does_not_count(self):
        lines = [
            "    // Safety: lowercase belongs to panic-discipline gate.\n",
            '    println!("...");\n',
        ]
        self.assertFalse(
            GATE.is_annotated(lines, 1),
            "stdout-discipline requires uppercase SAFETY: marker",
        )

    def test_multi_line_macro_continuation_does_not_break_walk(self):
        lines = [
            "    // SAFETY: stderr is the refuse-to-start contract.\n",
            "    eprintln!(\n",
            '        "{}",\n',
            "        format_message()\n",
            "    );\n",
            "    // SAFETY: stdout is the clean-exit contract.\n",
            "    println!(\n",
            '        "exit: {} {}",\n',
            "        a, b\n",
            "    );\n",
        ]
        # The eprintln site is line 1 (index 1, 0-based).
        self.assertTrue(GATE.is_annotated(lines, 1))
        # The println site is line 6 (index 6). Walk-back goes through the
        # multi-line eprintln body and finds the println's own SAFETY.
        self.assertTrue(GATE.is_annotated(lines, 6))


class FindPrintlnEprintlnSitesTests(unittest.TestCase):
    def test_finds_println(self):
        lines = textwrap.dedent(
            """
            pub fn say_hello() {
                println!("hello");
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_println_eprintln_sites("dummy.rs", lines)
        self.assertEqual(len(sites), 1)
        self.assertIn("println!", sites[0].text)

    def test_finds_eprintln(self):
        lines = textwrap.dedent(
            """
            pub fn say_oops() {
                eprintln!("oops");
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_println_eprintln_sites("dummy.rs", lines)
        self.assertEqual(len(sites), 1)
        self.assertIn("eprintln!", sites[0].text)

    def test_does_not_match_println_in_string_literal(self):
        lines = textwrap.dedent(
            '''
            pub fn label() -> &'static str {
                "called println! somewhere"
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_println_eprintln_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "literal println! inside a string is not a real call site",
        )

    def test_does_not_match_println_in_line_comment(self):
        lines = textwrap.dedent(
            """
            pub fn bare() {
                // we do NOT call println! here on purpose
                let _ = 1;
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_println_eprintln_sites("dummy.rs", lines)
        self.assertEqual(sites, [])

    def test_skips_test_mod_sites(self):
        lines = textwrap.dedent(
            """
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }

            #[cfg(test)]
            mod tests {
                #[test]
                fn diag() {
                    println!("test diagnostic");
                    eprintln!("test stderr");
                }
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_println_eprintln_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "println/eprintln in #[cfg(test)] mod blocks are exempt",
        )


class ScanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="cw-stdout-gate-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_clean_tree_passes(self):
        _stage(
            self.root,
            "src/lib.rs",
            """
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }

            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    println!("test ok");
                }
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(annotated, [])
        self.assertEqual(unannotated, [])

    def test_unannotated_site_fails(self):
        _stage(
            self.root,
            "src/danger.rs",
            """
            pub fn debug() {
                println!("residual debug output");
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(annotated, [])
        self.assertEqual(len(unannotated), 1)
        self.assertTrue(unannotated[0].path.endswith("danger.rs"))

    def test_annotated_site_passes(self):
        _stage(
            self.root,
            "src/safe.rs",
            """
            pub fn print_help() {
                // SAFETY: stdout is the CLI --help contract here, not log.
                println!("usage: ...");
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(unannotated, [])
        self.assertEqual(len(annotated), 1)

    def test_test_mod_block_excluded(self):
        _stage(
            self.root,
            "src/lib.rs",
            """
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }

            #[cfg(test)]
            mod tests {
                #[test]
                fn loud() {
                    // diagnostic; no SAFETY needed
                    println!("loud test diagnostic");
                    eprintln!("loud stderr diagnostic");
                }
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(
            annotated,
            [],
            "test-mod println/eprintln must not be reported as annotated",
        )
        self.assertEqual(
            unannotated,
            [],
            "test-mod println/eprintln must not be reported as unannotated",
        )

    def test_excludes_tests_directory(self):
        _stage(
            self.root,
            "tests/integration.rs",
            """
            #[test]
            fn boom() {
                println!("integration diagnostic");
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(annotated, [])
        self.assertEqual(unannotated, [])

    def test_recursive_walk(self):
        _stage(
            self.root,
            "src/nested/inner.rs",
            """
            pub fn inner_print() {
                println!("nested");
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(len(unannotated), 1)
        self.assertTrue(unannotated[0].path.endswith("inner.rs"))

    def test_real_daemon_tree_passes(self):
        """The actual daemon tree must pass the gate after the Sigma-3 sweep."""
        here = os.path.dirname(os.path.abspath(__file__))
        daemon_root = os.path.dirname(here)
        annotated, unannotated = GATE.scan(daemon_root)
        self.assertEqual(
            unannotated,
            [],
            f"Real daemon tree has unannotated sites: {unannotated}",
        )
        self.assertGreaterEqual(
            len(annotated),
            21,
            "Real daemon should have at least the 21 Sigma-3 annotations",
        )


if __name__ == "__main__":
    unittest.main()
