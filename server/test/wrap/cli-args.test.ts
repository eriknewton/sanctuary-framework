/**
 * Wrap CLI argument tests
 *
 * Verifies the CLI argument parser and the wrap profile generation.
 */

import { describe, it, expect } from "vitest";
import { parseWrapArgs, WRAP_GOVERNOR_DEFAULTS } from "../../src/wrap/cli.js";

describe("Wrap CLI", () => {
  // ── Argument parser ─────────────────────────────────────────────

  describe("parseWrapArgs", () => {
    it("parses --openclaw flag", () => {
      const opts = parseWrapArgs(["--openclaw"]);
      expect(opts.openclaw).toBe(true);
    });

    it("parses --claude-code flag", () => {
      const opts = parseWrapArgs(["--claude-code"]);
      expect(opts.claudeCode).toBe(true);
    });

    it("parses --cursor flag", () => {
      const opts = parseWrapArgs(["--cursor"]);
      expect(opts.cursor).toBe(true);
    });

    it("parses --cline flag", () => {
      const opts = parseWrapArgs(["--cline"]);
      expect(opts.cline).toBe(true);
    });

    it("parses --wrap with path", () => {
      const opts = parseWrapArgs(["--wrap", "/path/to/config.json"]);
      expect(opts.wrap).toBe("/path/to/config.json");
    });

    it("parses --unprotect-egress-gate flag (S5-7 unprotect verb)", () => {
      const opts = parseWrapArgs(["--unprotect-egress-gate"]);
      expect(opts.unprotectEgressGate).toBe(true);
      expect(opts.repairEgressGate).toBeUndefined();
    });

    it("parses --repair-egress-gate flag (S5-6 repair verb)", () => {
      const opts = parseWrapArgs(["--repair-egress-gate"]);
      expect(opts.repairEgressGate).toBe(true);
      expect(opts.unprotectEgressGate).toBeUndefined();
    });

    it("parses --stand-down-agent as an explicit repair/unprotect opt-in", () => {
      const opts = parseWrapArgs(["--repair-egress-gate", "--stand-down-agent"]);
      expect(opts.repairEgressGate).toBe(true);
      expect(opts.standDownAgent).toBe(true);
    });

    it("rejects --stand-down-agent without repair or unprotect so it cannot be silently ignored", () => {
      expect(() => parseWrapArgs(["--stand-down-agent"])).toThrow(
        /only valid with --repair-egress-gate or --unprotect-egress-gate/,
      );
    });

    it("parses --unwrap flag", () => {
      const opts = parseWrapArgs(["--unwrap"]);
      expect(opts.unwrap).toBe(true);
    });

    it("parses --passphrase with value", () => {
      const opts = parseWrapArgs(["--passphrase", "my-secret"]);
      expect(opts.passphrase).toBe("my-secret");
    });

    it("parses --port with value", () => {
      const opts = parseWrapArgs(["--port", "8080"]);
      expect(opts.port).toBe(8080);
    });

    it("parses --dry-run flag", () => {
      const opts = parseWrapArgs(["--dry-run"]);
      expect(opts.dryRun).toBe(true);
    });

    it("parses --dev-dist with path (dogfood path)", () => {
      const opts = parseWrapArgs(["--dev-dist", "/abs/path/to/dist/cli.js"]);
      expect(opts.devDist).toBe("/abs/path/to/dist/cli.js");
    });

    it("parses combined flags", () => {
      const opts = parseWrapArgs([
        "--openclaw",
        "--passphrase", "secret",
        "--port", "9000",
        "--dry-run",
      ]);
      expect(opts.openclaw).toBe(true);
      expect(opts.passphrase).toBe("secret");
      expect(opts.port).toBe(9000);
      expect(opts.dryRun).toBe(true);
    });

    it("returns empty options for no arguments", () => {
      const opts = parseWrapArgs([]);
      expect(opts.openclaw).toBeUndefined();
      expect(opts.unwrap).toBeUndefined();
      expect(opts.wrap).toBeUndefined();
    });
  });

  // ── Governor defaults ───────────────────────────────────────────

  describe("governor defaults", () => {
    it("has sensible rate limits", () => {
      expect(WRAP_GOVERNOR_DEFAULTS.volume_limit).toBe(200);
      expect(WRAP_GOVERNOR_DEFAULTS.rate_limit_per_tool).toBe(20);
      expect(WRAP_GOVERNOR_DEFAULTS.lifetime_limit).toBe(1000);
    });
  });
});
