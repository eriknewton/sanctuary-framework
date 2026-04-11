/**
 * Sanctuary MCP Server — EU AI Act Template Renderer Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  render,
  manualInputMarker,
  countManualInputMarkers,
  extractManualInputHints,
  MANUAL_INPUT_MARKER_PREFIX,
  MANUAL_INPUT_MARKER_SUFFIX,
} from "../../../src/compliance/eu_ai_act/templates/render.js";

describe("EU AI Act template renderer", () => {
  describe("basic interpolation", () => {
    it("substitutes a simple variable", () => {
      expect(render("Hello {{ name }}", { name: "world" })).toBe(
        "Hello world"
      );
    });

    it("substitutes multiple variables", () => {
      expect(
        render("{{ a }} and {{ b }} and {{ c }}", {
          a: "apple",
          b: "banana",
          c: "cherry",
        })
      ).toBe("apple and banana and cherry");
    });

    it("handles variables with surrounding whitespace", () => {
      expect(render("Hello {{  name  }}", { name: "world" })).toBe(
        "Hello world"
      );
    });

    it("coerces numbers to strings", () => {
      expect(render("Count: {{ n }}", { n: 42 })).toBe("Count: 42");
    });

    it("coerces booleans to strings", () => {
      expect(render("Flag: {{ f }}", { f: true })).toBe("Flag: true");
    });

    it("leaves non-template text untouched", () => {
      const template = "# Header\n\nPlain text with no variables.\n";
      expect(render(template, {})).toBe(template);
    });

    it("returns empty string for empty template", () => {
      expect(render("", {})).toBe("");
    });

    it("supports the same variable used multiple times", () => {
      expect(render("{{ x }}-{{ x }}-{{ x }}", { x: "a" })).toBe("a-a-a");
    });
  });

  describe("manual-input fallback", () => {
    it("produces a MANUAL INPUT REQUIRED marker for undefined variables", () => {
      const result = render("Purpose: {{ purpose }}", {});
      expect(result).toContain(MANUAL_INPUT_MARKER_PREFIX);
      expect(result).toContain("purpose");
      expect(result).toContain(MANUAL_INPUT_MARKER_SUFFIX);
    });

    it("produces a marker for null values", () => {
      const result = render("X: {{ v }}", { v: null });
      expect(result).toBe(`X: ${manualInputMarker("v")}`);
    });

    it("produces a marker for empty-string values", () => {
      const result = render("X: {{ v }}", { v: "" });
      expect(result).toBe(`X: ${manualInputMarker("v")}`);
    });

    it("uses a custom hint when provided via | syntax", () => {
      const result = render(
        "Purpose: {{ purpose | the intended business function }}",
        {}
      );
      expect(result).toBe(
        `Purpose: ${manualInputMarker("the intended business function")}`
      );
    });

    it("trims whitespace around the custom hint", () => {
      const result = render("X: {{ v |   some hint   }}", {});
      expect(result).toBe(`X: ${manualInputMarker("some hint")}`);
    });

    it("falls back to variable name if custom hint is empty", () => {
      const result = render("X: {{ v | }}", {});
      expect(result).toBe(`X: ${manualInputMarker("v")}`);
    });

    it("renders zero as a real value, not a marker", () => {
      // zero is a legitimate value for count fields
      const result = render("Count: {{ n }}", { n: 0 });
      expect(result).toBe("Count: 0");
    });

    it("renders false as a real value, not a marker", () => {
      const result = render("Flag: {{ f }}", { f: false });
      expect(result).toBe("Flag: false");
    });
  });

  describe("countManualInputMarkers", () => {
    it("returns 0 for fully rendered string", () => {
      expect(countManualInputMarkers("Hello world")).toBe(0);
    });

    it("counts a single marker", () => {
      const rendered = render("{{ a }}", {});
      expect(countManualInputMarkers(rendered)).toBe(1);
    });

    it("counts multiple markers in order", () => {
      const rendered = render("{{ a }} {{ b }} {{ c }}", {});
      expect(countManualInputMarkers(rendered)).toBe(3);
    });

    it("counts only markers, not literal text that mentions MANUAL INPUT", () => {
      // Only the prefix token counts
      const rendered = `[MANUAL INPUT REQUIRED: first] some text [MANUAL INPUT REQUIRED: second]`;
      expect(countManualInputMarkers(rendered)).toBe(2);
    });
  });

  describe("extractManualInputHints", () => {
    it("returns empty array for no markers", () => {
      expect(extractManualInputHints("plain text")).toEqual([]);
    });

    it("extracts a single hint", () => {
      const rendered = render("{{ x | provider legal name }}", {});
      expect(extractManualInputHints(rendered)).toEqual([
        "provider legal name",
      ]);
    });

    it("extracts multiple hints in order", () => {
      const rendered = render(
        "{{ a | first }} and {{ b | second }} and {{ c }}",
        {}
      );
      expect(extractManualInputHints(rendered)).toEqual([
        "first",
        "second",
        "c",
      ]);
    });
  });

  describe("grammar edge cases", () => {
    it("ignores malformed {{ without closing }}", () => {
      // No match — engine leaves source untouched
      expect(render("{{ broken", {})).toBe("{{ broken");
    });

    it("ignores {} single braces", () => {
      expect(render("{ not a template }", {})).toBe("{ not a template }");
    });

    it("rejects variable names starting with a number", () => {
      // /[a-z_]/i is the first-char class — digit start fails to match
      expect(render("{{ 123abc }}", { "123abc": "x" })).toBe("{{ 123abc }}");
    });

    it("accepts underscored and digit-containing variable names", () => {
      expect(
        render("{{ my_var_2 }}", { my_var_2: "ok" })
      ).toBe("ok");
    });
  });
});
