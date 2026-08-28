/**
 * IC-30: strict-vs-permissive --fortress behavior parity, verb by verb.
 *
 * Before this fix, roughly half the fortress-scoped CLI verbs read
 * `--fortress` through `flagValue` (permissive: an empty `--fortress=`
 * value, a duplicate occurrence, or a dropped value that silently
 * swallowed the NEXT flag as its own value all passed through unchecked)
 * and the other half through `consumeFlagValue` (strict: all three
 * refuse). This file proves the migrated verbs now refuse the same way,
 * across the different code shapes the migration touched: plain env-var
 * promotion (identity, checkpoint), a hand-rolled multi-flag parser now
 * delegating per-flag (audit search), a sync parse-result object with an
 * `error` field consumed by an async runner (audit-chain export/repair,
 * license), a --fortress/--storage alias pair (restore-attest), and a
 * shared local `parseFlags` helper with --fortress pre-extracted
 * (transparency).
 *
 * `test/cli/fortress-flag-parser-unified.test.ts` is the source-level
 * full-set guard (no file may reintroduce the permissive parser for
 * --fortress); this file is the runtime-behavior companion, proving the
 * strict parser's refusal actually reaches the operator for a
 * representative cross-section of the migrated verbs. Every malformed
 * case below asserts the SAME two properties `consumeFlagValue` itself is
 * tested for in argv.test.ts: a missing value refuses, and a duplicate
 * occurrence refuses. Each existing verb's own test file (identity-show,
 * audit-search, license, audit-chain-repair-plan, etc.) already covers
 * the happy path with a well-formed `--fortress <path>`; that suite
 * staying green after this migration IS the "happy path unchanged"
 * evidence, so it is not duplicated here.
 */

import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import { runIdentityCommand } from "../../src/cli/identity.js";
import { runAuditCommand } from "../../src/cli/audit.js";
import { runCheckpointCommand } from "../../src/cli/checkpoint.js";
import { runLicenseCommand } from "../../src/cli/license.js";
import {
  parseExportArgs,
  runExport as runAuditChainExport,
} from "../../src/cli/audit-chain-export.js";
import { parseRepairPlanArgs } from "../../src/cli/audit-chain-repair-plan.js";
import { runRestoreAttestCommand } from "../../src/cli/restore-attest.js";
import {
  runTransparencyCommand,
  runVerifyTransparencyCommand,
} from "../../src/cli/transparency.js";
import { runIntelligenceCommand } from "../../src/cli/intelligence.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function streams() {
  return { out: new StringWritable(), err: new StringWritable() };
}

const MISSING_VALUE = "--fortress requires a value";
const DUPLICATE = "--fortress may only be provided once";

describe("IC-30: strict --fortress parity across migrated verbs", () => {
  describe("identity show (env-var promotion shape)", () => {
    it("refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runIdentityCommand({ argv: ["show", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("refuses a duplicate occurrence", async () => {
      const { out, err } = streams();
      const code = await runIdentityCommand({
        argv: ["show", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });
  });

  describe("audit search (hand-rolled parser now delegating per-flag)", () => {
    it("refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runAuditCommand({ argv: ["search", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("refuses a duplicate occurrence, while --type still parses normally", async () => {
      const { out, err } = streams();
      const code = await runAuditCommand({
        argv: ["search", "--fortress", "/a", "--type", "x", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });
  });

  describe("checkpoint create (bootstrap-null shape)", () => {
    it("refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runCheckpointCommand({ argv: ["create", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("refuses a duplicate occurrence", async () => {
      const { out, err } = streams();
      const code = await runCheckpointCommand({
        argv: ["create", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });
  });

  describe("license issue / revoke (positional-interaction shape)", () => {
    it("issue refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({ argv: ["issue", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("issue refuses a duplicate occurrence", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({
        argv: ["issue", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });

    it("revoke refuses a missing value before the <licenseId> positional check", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({ argv: ["revoke", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
      // Not the (later, now-unreachable) positional-argument error.
      expect(err.text).not.toContain("<licenseId> argument is required");
    });

    it("revoke refuses a duplicate --fortress occurrence before the <licenseId> positional check", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({
        argv: ["revoke", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
      expect(err.text).not.toContain("<licenseId> argument is required");
    });
  });

  describe("audit-chain export (sync parse-result + async throw shape)", () => {
    it("refuses a missing value", async () => {
      const parsed = parseExportArgs(["--fortress"]);
      expect(parsed.error).toBe(MISSING_VALUE);
      await expect(runAuditChainExport(parsed)).rejects.toThrow(MISSING_VALUE);
    });

    it("refuses a duplicate occurrence", async () => {
      const parsed = parseExportArgs(["--fortress", "/a", "--fortress", "/b"]);
      expect(parsed.error).toBe(DUPLICATE);
      await expect(runAuditChainExport(parsed)).rejects.toThrow(DUPLICATE);
    });

    it("still honors the --fortress-path alias and the well-formed happy path", () => {
      const parsed = parseExportArgs(["--fortress-path=/tmp/somewhere", "--operator-only"]);
      expect(parsed.error).toBeUndefined();
      expect(parsed.fortressPath).toBe("/tmp/somewhere");
      expect(parsed.operatorOnly).toBe(true);
    });
  });

  describe("audit-chain repair-plan (sync Result<T, error> shape)", () => {
    it("refuses a missing value", () => {
      const result = parseRepairPlanArgs(["--fortress"], {});
      expect(result.args).toBeUndefined();
      expect(result.error).toBe(MISSING_VALUE);
    });

    it("refuses a duplicate occurrence", () => {
      const result = parseRepairPlanArgs(["--fortress", "/a", "--fortress", "/b"], {});
      expect(result.args).toBeUndefined();
      expect(result.error).toBe(DUPLICATE);
    });
  });

  describe("restore-attest (--fortress/--storage alias shape)", () => {
    it("refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({ argv: ["--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("refuses a duplicate --fortress occurrence", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({
        argv: ["--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });

    it("refuses a duplicate --storage occurrence (the alias, checked independently)", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({
        argv: ["--storage", "/a", "--storage", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain("--storage may only be provided once");
    });

    it("now also accepts the --fortress=<path> equals form (previously rejected outright)", async () => {
      // Before this fix, restore-attest's hand-rolled parser matched ONLY
      // the bare `--fortress <path>` token form; `--fortress=<path>` fell
      // through to "Unknown flag". consumeFlagValue supports both forms,
      // which is exactly the "--fortress=value vs --fortress value can
      // diverge by verb family" defect this migration closes.
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({
        argv: ["--fortress=/nonexistent/path/for/this/test", "--help"],
        out,
        err,
      });
      expect(err.text).not.toContain("Unknown flag");
      expect(code).toBe(0);
      expect(out.text).toContain("Usage: sanctuary restore-attest");
    });
  });

  describe("transparency export / verify (shared local parseFlags, --fortress pre-extracted)", () => {
    it("export refuses a missing value", async () => {
      const { out, err } = streams();
      const code = await runTransparencyCommand({ argv: ["export", "--fortress"], out, err });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
    });

    it("export refuses a duplicate occurrence", async () => {
      const { out, err } = streams();
      const code = await runTransparencyCommand({
        argv: ["export", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(DUPLICATE);
    });

    it("verify refuses a missing --fortress value before the --input check", async () => {
      const { out, err } = streams();
      const code = await runVerifyTransparencyCommand({
        argv: ["--fortress"],
        out,
        err,
      });
      expect(code).toBe(1);
      expect(err.text).toContain(MISSING_VALUE);
      expect(err.text).not.toContain("--input <path> is required");
    });
  });

  describe("intelligence diagnose (--fortress/--fortress-path alias, no err stream)", () => {
    it("refuses a missing --fortress value", async () => {
      const errSpy: string[] = [];
      const orig = console.error;
      console.error = (...args: unknown[]) => {
        errSpy.push(args.join(" "));
      };
      try {
        const code = await runIntelligenceCommand({ argv: ["diagnose", "--fortress"] });
        expect(code).toBe(1);
        expect(errSpy.join("\n")).toContain(MISSING_VALUE);
      } finally {
        console.error = orig;
      }
    });

    it("refuses a missing --fortress-path value (the alias)", async () => {
      const errSpy: string[] = [];
      const orig = console.error;
      console.error = (...args: unknown[]) => {
        errSpy.push(args.join(" "));
      };
      try {
        const code = await runIntelligenceCommand({ argv: ["diagnose", "--fortress-path"] });
        expect(code).toBe(1);
        expect(errSpy.join("\n")).toContain("--fortress-path requires a value");
      } finally {
        console.error = orig;
      }
    });
  });
});
