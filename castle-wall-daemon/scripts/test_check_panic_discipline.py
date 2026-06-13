#!/usr/bin/env python3
"""
Unit tests for `check-panic-discipline.py`. Run with:

    python3 castle-wall-daemon/scripts/test_check_panic_discipline.py

Tests cover the parser-aware classification logic and the annotation walk-back
heuristic. The negative tests stage synthetic Rust source trees in tempdirs;
they are independent of the real daemon source and will continue to pass even
as production code evolves.
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
        "check_panic_discipline",
        os.path.join(here, "check-panic-discipline.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass forward-reference lookups succeed.
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


class FindTestModLinesTests(unittest.TestCase):
    def test_no_test_mod(self):
        body = textwrap.dedent(
            """
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }
            """
        ).strip().splitlines(keepends=True)
        flags = GATE.find_test_mod_lines(body)
        self.assertEqual(flags, [False, False, False])

    def test_simple_test_mod(self):
        body = textwrap.dedent(
            """
            pub fn x() {}

            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    assert!(true);
                }
            }
            """
        ).strip().splitlines(keepends=True)
        flags = GATE.find_test_mod_lines(body)
        self.assertFalse(flags[0])  # pub fn x()
        self.assertFalse(flags[1])  # blank
        self.assertTrue(flags[2])   # #[cfg(test)]
        self.assertTrue(flags[3])   # mod tests {
        self.assertTrue(flags[-1])  # closing brace

    def test_two_test_mods(self):
        body = textwrap.dedent(
            """
            pub fn a() {}

            #[cfg(test)]
            mod tests {
                fn x() {}
            }

            pub fn b() {}

            #[cfg(test)]
            mod more_tests {
                fn y() {}
            }
            """
        ).strip().splitlines(keepends=True)
        flags = GATE.find_test_mod_lines(body)
        self.assertFalse(flags[0])  # pub fn a()
        self.assertTrue(flags[2])   # #[cfg(test)]
        # find pub fn b() index. It should be production code.
        for idx, line in enumerate(body):
            if line.strip().startswith("pub fn b"):
                self.assertFalse(flags[idx])
                break
        else:
            self.fail("pub fn b() line not found")

    def test_nested_braces_inside_test_mod(self):
        body = textwrap.dedent(
            """
            pub fn x() {}

            #[cfg(test)]
            mod tests {
                fn helper() {
                    let v = vec![1, 2, 3];
                    if v.len() > 0 {
                        let _y = v[0];
                    }
                }
            }

            pub fn y() {}
            """
        ).strip().splitlines(keepends=True)
        flags = GATE.find_test_mod_lines(body)
        # pub fn y() must be production (the test mod closed before it)
        for idx, line in enumerate(body):
            if line.strip().startswith("pub fn y"):
                self.assertFalse(
                    flags[idx], "pub fn y() should be production code"
                )
                break
        else:
            self.fail("pub fn y() line not found")


class IsAnnotatedTests(unittest.TestCase):
    def test_safety_directly_above(self):
        lines = [
            "let x = vec![1];\n",
            "// Safety: the line above pushes one element.\n",
            "let _y = x.first().unwrap();\n",
        ]
        self.assertTrue(GATE.is_annotated(lines, 2))

    def test_safety_in_block_above_chain(self):
        lines = [
            "// Safety: details was initialized as an object\n",
            "// in the if-block above.\n",
            "let details = entry\n",
            "    .get_mut(\"details\")\n",
            "    .and_then(|d| d.as_object_mut())\n",
            "    .expect(\"details was initialized\");\n",
        ]
        self.assertTrue(GATE.is_annotated(lines, 5))

    def test_no_safety_at_all(self):
        lines = [
            "let x = some_option();\n",
            "let y = x.unwrap();\n",
        ]
        self.assertFalse(GATE.is_annotated(lines, 1))

    def test_safety_separated_by_blank_line(self):
        lines = [
            "// Safety: this annotation is for an unrelated site below.\n",
            "\n",
            "let y = x.unwrap();\n",
        ]
        self.assertFalse(GATE.is_annotated(lines, 2))

    def test_safety_belongs_to_prior_unwrap(self):
        lines = [
            "// Safety: a is non-empty by construction.\n",
            "let _first = a.first().unwrap();\n",
            "let _second = b.first().unwrap();\n",
        ]
        self.assertTrue(GATE.is_annotated(lines, 1))
        self.assertFalse(
            GATE.is_annotated(lines, 2),
            "second unwrap should not borrow the first's Safety annotation",
        )

    def test_safety_in_doc_comment_does_not_count(self):
        lines = [
            "/// Safety: docstring uses Safety: but is not a //-comment.\n",
            "let y = x.unwrap();\n",
        ]
        self.assertFalse(
            GATE.is_annotated(lines, 1),
            "doc comments (///) are not honored as Safety annotations",
        )

    def test_safety_must_say_safety_word(self):
        lines = [
            "// generic comment that does not mention the magic word\n",
            "let y = x.unwrap();\n",
        ]
        self.assertFalse(GATE.is_annotated(lines, 1))


class FindUnwrapExpectSitesTests(unittest.TestCase):
    def test_skips_test_mod_sites(self):
        lines = textwrap.dedent(
            """
            pub fn add(a: i32, b: i32) -> i32 {
                a + b
            }

            #[cfg(test)]
            mod tests {
                #[test]
                fn it_panics_loud() {
                    let v: Vec<i32> = vec![];
                    let _y = v.first().unwrap();
                }
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(sites, [])

    def test_finds_production_sites(self):
        lines = textwrap.dedent(
            """
            pub fn boom(x: Option<i32>) -> i32 {
                x.unwrap()
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(len(sites), 1)
        self.assertIn("unwrap", sites[0].text)

    def test_does_not_match_unwrap_or(self):
        lines = textwrap.dedent(
            """
            pub fn safe(x: Option<i32>) -> i32 {
                x.unwrap_or(0)
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "unwrap_or is fallible-safe; the gate must not match it",
        )

    def test_does_not_match_expect_err(self):
        lines = textwrap.dedent(
            """
            pub fn check(r: Result<i32, String>) -> String {
                r.expect_err("expected an error")
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(sites, [])

    def test_does_not_match_unwrap_in_string_literal(self):
        lines = textwrap.dedent(
            '''
            pub fn label() -> &'static str {
                "called .unwrap() somewhere"
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "literal .unwrap() inside a string is not a real call site",
        )

    def test_does_not_match_unwrap_in_line_comment(self):
        lines = textwrap.dedent(
            """
            pub fn bare(x: Option<i32>) -> i32 {
                // we do NOT call .unwrap() here on purpose
                x.unwrap_or(0)
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(sites, [])


class ScanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="cw-panic-gate-")

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
                    let _v: Vec<i32> = vec![];
                    let _none = _v.first().unwrap_or(&0);
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
            pub fn boom(x: Option<i32>) -> i32 {
                x.unwrap()
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
            pub fn always_safe() -> i32 {
                let x = Some(42);
                // Safety: x is constructed as Some(42) one line above.
                x.unwrap()
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(unannotated, [])
        self.assertEqual(len(annotated), 1)

    def test_recursive_walk(self):
        _stage(
            self.root,
            "src/nested/inner.rs",
            """
            pub fn inner_unwrap() -> i32 {
                let x = Some(1);
                x.unwrap()
            }
            """,
        )
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(len(unannotated), 1)
        self.assertTrue(unannotated[0].path.endswith("inner.rs"))

    def test_excludes_tests_directory(self):
        _stage(
            self.root,
            "tests/integration.rs",
            """
            #[test]
            fn boom() {
                let v: Vec<i32> = vec![];
                let _y = v.first().unwrap();
            }
            """,
        )
        # tests/ is outside src/; the scanner only walks src/.
        annotated, unannotated = GATE.scan(self.root)
        self.assertEqual(annotated, [])
        self.assertEqual(unannotated, [])

    def test_real_daemon_tree_passes(self):
        """The actual daemon tree must pass the gate after PR #138."""
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
            5,
            "Real daemon should have at least the 5 PR #138 annotations",
        )


class RawStringLiteralTests(unittest.TestCase):
    """Regression cases for the raw-string-aware line scanner (PR #500 bug).

    Before the fix, `find_test_mod_lines` counted bare `{`/`}` characters that
    appeared inside a multi-line raw-string fixture, which desynced the brace
    depth, ended the `#[cfg(test)] mod` region early, and false-flagged a
    test-code `.unwrap()` below the fixture as a production site.
    """

    def test_multiline_raw_string_braces_do_not_end_test_region(self):
        # The exact shape that broke tonight: a multi-line `r#"{...}"#` JSON
        # fixture inside #[cfg(test)] mod, with bare braces in the content.
        body = textwrap.dedent(
            '''
            pub fn ok() {}

            #[cfg(test)]
            mod tests {
                #[test]
                fn fixture_test() {
                    let json = r#"{
                        "key": "value",
                        "nested": { "a": 1 },
                        "closing": }
                    }"#;
                    let v: Option<i32> = None;
                    let _y = v.unwrap();
                    let _ = json;
                }
            }
            '''
        ).strip().splitlines(keepends=True)
        flags = GATE.find_test_mod_lines(body)
        # The test-mod region must extend through the unwrap below the fixture.
        for idx, line in enumerate(body):
            if "v.unwrap()" in line:
                self.assertTrue(
                    flags[idx],
                    "unwrap below a multi-line raw-string fixture must stay "
                    "inside the test region",
                )
                break
        else:
            self.fail("v.unwrap() line not found")
        # And that unwrap must NOT be reported as a production site.
        sites = GATE.find_unwrap_expect_sites("dummy.rs", body)
        self.assertEqual(
            sites,
            [],
            "test-mod unwrap below a raw-string fixture must be exempt",
        )

    def test_unbalanced_closing_braces_in_raw_string(self):
        # Raw content with MORE `}` than `{`: previously drove depth below the
        # start and closed the region on the first net-zero crossing.
        body = textwrap.dedent(
            '''
            pub fn ok() {}

            #[cfg(test)]
            mod tests {
                #[test]
                fn fixture_test() {
                    let payload = r#"
                        allow }
                        deny }
                    "#;
                    let v: Option<i32> = None;
                    let _y = v.unwrap();
                    let _ = payload;
                }
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", body)
        self.assertEqual(
            sites, [], "unwrap after an unbalanced-brace raw string is test code"
        )

    def test_single_line_raw_string_with_unwrap_text(self):
        # A single-line raw string containing `.unwrap()` text is not a call.
        lines = textwrap.dedent(
            '''
            pub fn label() -> &'static str {
                let s = r#"call .unwrap() here"#;
                s
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            ".unwrap() inside a single-line raw string is not a call site",
        )

    def test_raw_string_with_nested_quotes_and_braces(self):
        # Nested `"` inside r#"..."# must not terminate the raw string early,
        # so the unwrap-looking text inside stays masked.
        lines = textwrap.dedent(
            '''
            pub fn build() -> i32 {
                let _doc = r#"{ "msg": "x.unwrap() \\" still inside" }"#;
                42
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "nested quotes inside a raw string must not end it early",
        )

    def test_production_unwrap_after_raw_string_still_caught(self):
        # FALSE-NEGATIVE guard: a real production unwrap that follows a
        # multi-line raw string must still be reported.
        lines = textwrap.dedent(
            '''
            pub fn boom() -> i32 {
                let _doc = r#"
                    { "a": 1 }
                "#;
                let x: Option<i32> = None;
                x.unwrap()
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            len(sites),
            1,
            "a production unwrap after a raw string must remain visible",
        )
        self.assertIn("unwrap", sites[0].text)

    def test_multiline_normal_string_brace_tracking(self):
        # A normal (non-raw) string continued across lines via backslash also
        # must not leak braces into the depth counter.
        body = textwrap.dedent(
            '''
            pub fn ok() {}

            #[cfg(test)]
            mod tests {
                #[test]
                fn fixture_test() {
                    let s = "line one with } \\
            still in string }";
                    let v: Option<i32> = None;
                    let _y = v.unwrap();
                    let _ = s;
                }
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", body)
        self.assertEqual(
            sites, [], "unwrap after a continued normal string is test code"
        )

    def test_unterminated_raw_string_does_not_crash(self):
        # Edge: an unterminated raw string (e.g. truncated file) must scan
        # without raising; remaining lines are treated as in-string content.
        lines = textwrap.dedent(
            '''
            pub fn boom() -> i32 {
                let _doc = r#"
                    unterminated { content }
                    x.unwrap()
            '''
        ).strip().splitlines(keepends=True)
        # Should not raise, and the unwrap text inside the open raw string is
        # masked (no production site recorded).
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "text inside an unterminated raw string is not a call site",
        )

    def test_char_literal_double_quote_does_not_hide_later_sites(self):
        # FALSE-NEGATIVE guard (codex review): a char literal containing a
        # double quote, `let c = '"';`, must NOT put the scrubber into a
        # persistent string state that blanks the rest of the file and hides a
        # real production unwrap below it.
        lines = textwrap.dedent(
            """
            pub fn boom(x: Option<i32>) -> i32 {
                let _c = '"';
                x.unwrap()
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            len(sites),
            1,
            "a char literal '\"' must not hide a real unwrap below it",
        )
        self.assertIn("unwrap", sites[0].text)

    def test_escaped_char_literals_do_not_break_scan(self):
        # `'\''` and `'\\'` contain a quote/backslash but are complete char
        # literals; a real unwrap after them must remain visible.
        lines = textwrap.dedent(
            r"""
            pub fn boom(x: Option<i32>) -> i32 {
                let _q = '\'';
                let _b = '\\';
                x.unwrap()
            }
            """
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(len(sites), 1)
        self.assertIn("unwrap", sites[0].text)

    def test_lifetime_tick_not_misread_as_char_literal(self):
        # Lifetimes (`'static`, `'a`) must not be consumed as char literals,
        # and a string literal on the same line must still mask correctly.
        lines = textwrap.dedent(
            '''
            pub fn label() -> &'static str {
                "called .unwrap() somewhere"
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites,
            [],
            "lifetime tick must not desync string masking on the line",
        )

    def test_block_comment_lone_quote_does_not_hide_later_sites(self):
        # FALSE-NEGATIVE guard (codex review round 2): a lone `"` inside a
        # multi-line `/* ... */` block comment must NOT open a persistent
        # string state that masks the rest of the file. Here the unbalanced
        # quote previously extended the test region over `prod`'s unwrap.
        lines = textwrap.dedent(
            '''
            #[cfg(test)]
            mod tests {
                /*
                   lone quote in a valid block comment: "
                */
            }

            pub fn prod(x: Option<i32>) -> i32 {
                x.unwrap()
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            len(sites),
            1,
            "block-comment quote must not hide prod unwrap below the test mod",
        )
        self.assertIn("unwrap", sites[0].text)

    def test_block_comment_braces_excluded_from_depth(self):
        # Braces inside a block comment must not count toward the test-mod
        # brace depth, so the region ends at the real closing brace.
        body = textwrap.dedent(
            '''
            pub fn ok() {}

            #[cfg(test)]
            mod tests {
                /* spurious braces in comment: } } { */
                #[test]
                fn t() {
                    let v: Option<i32> = None;
                    let _y = v.unwrap();
                }
            }

            pub fn after(x: Option<i32>) -> i32 {
                x.unwrap()
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", body)
        # Only `after`'s unwrap is production; the test-mod one is exempt.
        self.assertEqual(len(sites), 1)
        self.assertTrue(
            any("x.unwrap()" in s.text for s in sites),
            "production unwrap after the test mod must be the reported site",
        )

    def test_nested_block_comment(self):
        # Rust block comments nest; the region must reopen only at the outer
        # `*/`, after which production code is visible again.
        lines = textwrap.dedent(
            '''
            pub fn prod(x: Option<i32>) -> i32 {
                /* outer /* inner "unbalanced */ still comment */
                x.unwrap()
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            len(sites),
            1,
            "nested block comment must close fully and expose the unwrap",
        )
        self.assertIn("unwrap", sites[0].text)

    def test_prefixed_raw_strings_cr_br(self):
        # FALSE-NEGATIVE guard (codex review round 3): the C-string raw form
        # `cr#"..."#` and byte-string raw form `br#"..."#` must be recognized
        # as raw strings. A multi-line one containing a `"` previously left a
        # dangling normal-string state that could mask later production code.
        lines = textwrap.dedent(
            '''
            pub fn prod(x: Option<i32>) -> i32 {
                let _c = cr#"
                    c-string with a " quote and } brace
                "#;
                let _b = br#"bytes with " and }"#;
                x.unwrap()
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            len(sites),
            1,
            "cr#/br# raw strings must not leave dangling state hiding unwrap",
        )
        self.assertIn("unwrap", sites[0].text)

    def test_cr_raw_string_masks_inner_unwrap(self):
        # An `.unwrap()` literal inside a cr#"..."# raw string is not a call.
        lines = textwrap.dedent(
            '''
            pub fn build() -> i32 {
                let _c = cr#"text .unwrap() inside"#;
                42
            }
            '''
        ).strip().splitlines(keepends=True)
        sites = GATE.find_unwrap_expect_sites("dummy.rs", lines)
        self.assertEqual(
            sites, [], ".unwrap() inside a cr#-raw string is not a call site"
        )


if __name__ == "__main__":
    unittest.main()
