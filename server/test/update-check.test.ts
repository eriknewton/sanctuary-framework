/**
 * Tests for the startup update check module.
 *
 * Tests version comparison logic and message formatting.
 * Network-dependent tests (fetchLatestVersion) are not included
 * to avoid flaky CI from registry availability.
 */

import { describe, it, expect } from "vitest";
import {
  isNewerVersion,
  formatUpdateMessage,
} from "../src/update-check.js";

describe("update-check", () => {
  describe("isNewerVersion", () => {
    it("detects newer major version", () => {
      expect(isNewerVersion("0.3.1", "1.0.0")).toBe(true);
    });

    it("detects newer minor version", () => {
      expect(isNewerVersion("0.3.1", "0.4.0")).toBe(true);
    });

    it("detects newer patch version", () => {
      expect(isNewerVersion("0.3.1", "0.3.2")).toBe(true);
    });

    it("returns false for same version", () => {
      expect(isNewerVersion("0.3.1", "0.3.1")).toBe(false);
    });

    it("returns false for older version", () => {
      expect(isNewerVersion("0.4.0", "0.3.1")).toBe(false);
    });

    it("returns false when current is newer major", () => {
      expect(isNewerVersion("1.0.0", "0.9.9")).toBe(false);
    });

    it("handles v prefix", () => {
      expect(isNewerVersion("v0.3.1", "v0.4.0")).toBe(true);
    });

    it("handles mixed v prefix", () => {
      expect(isNewerVersion("0.3.1", "v0.4.0")).toBe(true);
      expect(isNewerVersion("v0.3.1", "0.4.0")).toBe(true);
    });
  });

  describe("formatUpdateMessage", () => {
    it("includes current and latest versions", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("0.3.1");
      expect(msg).toContain("0.4.0");
    });

    it("includes an update command pinned to the announced version", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("npx @sanctuary-framework/mcp-server@0.4.0");
      expect(msg).not.toContain("@latest");
    });

    it("uses [Sanctuary] prefix", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toMatch(/^\[Sanctuary\]/);
    });

    it("is a single line", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).not.toContain("\n");
    });
  });
});
