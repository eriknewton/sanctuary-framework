/**
 * Cocoon CLI Tests
 *
 * Verifies the CLI argument parser and the Cocoon profile generation.
 */

import { describe, it, expect } from "vitest";
import { parseCocoonArgs, COCOON_GOVERNOR_DEFAULTS } from "../../src/cocoon/cli.js";

describe("Cocoon CLI", () => {
  // ── Argument parser ─────────────────────────────────────────────

  describe("parseCocoonArgs", () => {
    it("parses --openclaw flag", () => {
      const opts = parseCocoonArgs(["--openclaw"]);
      expect(opts.openclaw).toBe(true);
    });

    it("parses --claude-code flag", () => {
      const opts = parseCocoonArgs(["--claude-code"]);
      expect(opts.claudeCode).toBe(true);
    });

    it("parses --cursor flag", () => {
      const opts = parseCocoonArgs(["--cursor"]);
      expect(opts.cursor).toBe(true);
    });

    it("parses --cline flag", () => {
      const opts = parseCocoonArgs(["--cline"]);
      expect(opts.cline).toBe(true);
    });

    it("parses --wrap with path", () => {
      const opts = parseCocoonArgs(["--wrap", "/path/to/config.json"]);
      expect(opts.wrap).toBe("/path/to/config.json");
    });

    it("parses --unwrap flag", () => {
      const opts = parseCocoonArgs(["--unwrap"]);
      expect(opts.unwrap).toBe(true);
    });

    it("parses --passphrase with value", () => {
      const opts = parseCocoonArgs(["--passphrase", "my-secret"]);
      expect(opts.passphrase).toBe("my-secret");
    });

    it("parses --port with value", () => {
      const opts = parseCocoonArgs(["--port", "8080"]);
      expect(opts.port).toBe(8080);
    });

    it("parses --dry-run flag", () => {
      const opts = parseCocoonArgs(["--dry-run"]);
      expect(opts.dryRun).toBe(true);
    });

    it("parses --dev-dist with path (v1.2.x F9 dogfood path)", () => {
      const opts = parseCocoonArgs(["--dev-dist", "/abs/path/to/dist/cli.js"]);
      expect(opts.devDist).toBe("/abs/path/to/dist/cli.js");
    });

    it("parses combined flags", () => {
      const opts = parseCocoonArgs([
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
      const opts = parseCocoonArgs([]);
      expect(opts.openclaw).toBeUndefined();
      expect(opts.unwrap).toBeUndefined();
      expect(opts.wrap).toBeUndefined();
    });
  });

  // ── Governor defaults ───────────────────────────────────────────

  describe("governor defaults", () => {
    it("has sensible rate limits", () => {
      expect(COCOON_GOVERNOR_DEFAULTS.volume_limit).toBe(200);
      expect(COCOON_GOVERNOR_DEFAULTS.rate_limit_per_tool).toBe(20);
      expect(COCOON_GOVERNOR_DEFAULTS.lifetime_limit).toBe(1000);
    });
  });
});
