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
 * representative cross-section of the migrated verbs. Each existing verb's
 * own test file (identity-show, audit-search, license,
 * audit-chain-repair-plan, etc.) already covers the happy path with a
 * well-formed `--fortress <path>`; that suite staying green after this
 * migration IS the "happy path unchanged" evidence, so it is not
 * duplicated here.
 *
 * IC-30 fix-round finding #4: refusal output used to diverge across verbs
 * (`Error: ...` vs `issue: ...` vs a raw unprefixed message; exit 1 vs 2),
 * and this file used to assert with `toContain`, which cannot enforce a
 * SHAPE (a substring check still passes if the prefix or exit code drifts,
 * as long as the core message text survives somewhere in the output).
 * Every assertion below is now EXACT (`toBe`/`toEqual`), built from the
 * SAME `fortressFlagRefusalText`/`FORTRESS_FLAG_USAGE_EXIT_CODE` exports
 * every migrated verb now renders through, so a future drift in either
 * fails here immediately, by construction, not by coincidence of a
 * substring still matching.
 *
 * IC-30 fix-round finding #1: `consumeFlagValue`'s split-form check widened
 * from rejecting only a `--`-prefixed next token to rejecting ANY
 * dash-leading one (`--fortress -h` used to consume `-h` as the path). A
 * representative sample below exercises that widened boundary end to end.
 *
 * IC-30 fix-round finding #3: `--fortress` and its alias
 * (`--storage`/`--fortress-path`) given TOGETHER in one invocation now
 * refuse instead of one silently winning. Covered per alias-pair shape
 * below (restore-attest's `--storage`, audit-chain-export's/
 * audit-chain-repair-plan's/intelligence's `--fortress-path`).
 */

import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import {
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
  aliasConflictMessage,
} from "../../src/cli/argv.js";
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
import { runCli, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

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

/** Exact expected stderr line (with trailing newline) for a Writable-based verb. */
function expectedLine(message: string): string {
  return `${fortressFlagRefusalText(message)}\n`;
}

describe("IC-30: strict --fortress parity across migrated verbs", () => {
  describe("identity show (env-var promotion shape)", () => {
    it("refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runIdentityCommand({ argv: ["show", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("refuses a duplicate occurrence with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runIdentityCommand({
        argv: ["show", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });

    it("finding #1: refuses a dash-leading split-form value (not just a `--`-prefixed one)", async () => {
      // Not "-h": identity's own dispatcher treats a bare -h/--help as a
      // help request BEFORE cmdShow ever parses --fortress, which would
      // exercise the pre-existing help short-circuit instead of the
      // widened dash check this test targets. "-x" is not a recognized
      // flag anywhere in this dispatch, so it reaches consumeFlagValue.
      const { out, err } = streams();
      const code = await runIdentityCommand({ argv: ["show", "--fortress", "-x"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });
  });

  describe("audit search (hand-rolled parser now delegating per-flag)", () => {
    it("refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runAuditCommand({ argv: ["search", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("refuses a duplicate occurrence, while --type still parses normally", async () => {
      const { out, err } = streams();
      const code = await runAuditCommand({
        argv: ["search", "--fortress", "/a", "--type", "x", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });
  });

  describe("checkpoint create (bootstrap-discriminant shape)", () => {
    it("refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runCheckpointCommand({ argv: ["create", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("refuses a duplicate occurrence with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runCheckpointCommand({
        argv: ["create", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });

    it("an UNRELATED bootstrap failure (no passphrase) still exits 1, not 2", async () => {
      // Regression guard for the bootstrap-discriminant refactor itself: a
      // number return from bootstrap() means "exit with this code", and the
      // fortress-parse case is the ONLY one that should map to
      // FORTRESS_FLAG_USAGE_EXIT_CODE; every other bootstrap failure here
      // must keep its pre-existing exit 1 (an operation that ran and
      // failed, not a malformed invocation).
      const { out, err } = streams();
      const savedPass = process.env.SANCTUARY_PASSPHRASE;
      const savedKey = process.env.SANCTUARY_RECOVERY_KEY;
      delete process.env.SANCTUARY_PASSPHRASE;
      delete process.env.SANCTUARY_RECOVERY_KEY;
      try {
        const code = await runCheckpointCommand({
          argv: ["create"],
          out,
          err,
          env: {},
        });
        expect(code).toBe(1);
        expect(err.text).toContain("requires SANCTUARY_PASSPHRASE");
      } finally {
        if (savedPass !== undefined) process.env.SANCTUARY_PASSPHRASE = savedPass;
        else delete process.env.SANCTUARY_PASSPHRASE;
        if (savedKey !== undefined) process.env.SANCTUARY_RECOVERY_KEY = savedKey;
        else delete process.env.SANCTUARY_RECOVERY_KEY;
      }
    });
  });

  describe("license issue / list / revoke (positional-interaction shape)", () => {
    it("issue refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({ argv: ["issue", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("issue refuses a duplicate occurrence with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({
        argv: ["issue", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });

    it("list refuses a missing value with the exact canonical shape (no more 'list: ' prefix)", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({ argv: ["list", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("revoke refuses a missing value before the <licenseId> positional check", async () => {
      const { out, err } = streams();
      const code = await runLicenseCommand({ argv: ["revoke", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
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
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });
  });

  describe("audit-chain export (sync parse-result + async throw shape)", () => {
    it("parseExportArgs surfaces a missing value as .error; runExport still refuses (defense in depth)", async () => {
      const parsed = parseExportArgs(["--fortress"]);
      expect(parsed.error).toBe(MISSING_VALUE);
      await expect(runAuditChainExport(parsed)).rejects.toThrow(MISSING_VALUE);
    });

    it("parseExportArgs surfaces a duplicate occurrence as .error", async () => {
      const parsed = parseExportArgs(["--fortress", "/a", "--fortress", "/b"]);
      expect(parsed.error).toBe(DUPLICATE);
      await expect(runAuditChainExport(parsed)).rejects.toThrow(DUPLICATE);
    });

    it("finding #3: --fortress and --fortress-path together refuse instead of one silently winning", () => {
      const bothOrders = [
        ["--fortress", "/a", "--fortress-path", "/b"],
        ["--fortress-path", "/b", "--fortress", "/a"],
      ];
      for (const argv of bothOrders) {
        const parsed = parseExportArgs(argv);
        expect(parsed.error).toBe(aliasConflictMessage("--fortress", "--fortress-path"));
      }
    });

    it("still honors the --fortress-path alias alone and the well-formed happy path", () => {
      const parsed = parseExportArgs(["--fortress-path=/tmp/somewhere", "--operator-only"]);
      expect(parsed.error).toBeUndefined();
      expect(parsed.fortressPath).toBe("/tmp/somewhere");
      expect(parsed.operatorOnly).toBe(true);
    });

    it(
      "the real CLI dispatch (cli.ts) renders the canonical shape + exit code for a malformed --fortress, not the generic top-level 'failed to start' message",
      async () => {
        const { code, stdout, stderr } = await runCli(
          "audit-chain",
          "export",
          "--fortress",
        );
        expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
        expect(stdout).toBe("");
        expect(stderr).toBe(`${expectedLine(MISSING_VALUE)}`);
        expect(stderr).not.toContain("Sanctuary MCP Server failed to start");
      },
      CLI_SUBPROCESS_TEST_TIMEOUT_MS,
    );
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

    it("finding #3: --fortress and --fortress-path together refuse instead of one silently winning", () => {
      const bothOrders = [
        ["--fortress", "/a", "--fortress-path", "/b"],
        ["--fortress-path", "/b", "--fortress", "/a"],
      ];
      for (const argv of bothOrders) {
        const result = parseRepairPlanArgs(argv, {});
        expect(result.args).toBeUndefined();
        expect(result.error).toBe(aliasConflictMessage("--fortress", "--fortress-path"));
      }
    });
  });

  describe("restore-attest (--fortress/--storage alias shape)", () => {
    it("refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({ argv: ["--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("refuses a duplicate --fortress occurrence with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({
        argv: ["--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });

    it("refuses a duplicate --storage occurrence (the alias, checked independently)", async () => {
      const { out, err } = streams();
      const code = await runRestoreAttestCommand({
        argv: ["--storage", "/a", "--storage", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine("--storage may only be provided once"));
    });

    it("finding #3: --fortress and --storage TOGETHER refuse, in either order, instead of --storage silently winning", async () => {
      const bothOrders = [
        ["--fortress", "/a", "--storage", "/b"],
        ["--storage", "/b", "--fortress", "/a"],
      ];
      for (const argv of bothOrders) {
        const { out, err } = streams();
        const code = await runRestoreAttestCommand({ argv, out, err });
        expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
        expect(err.text).toBe(
          expectedLine(aliasConflictMessage("--fortress", "--storage")),
        );
      }
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
    it("export refuses a missing value with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runTransparencyCommand({ argv: ["export", "--fortress"], out, err });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
    });

    it("export refuses a duplicate occurrence with the exact canonical shape", async () => {
      const { out, err } = streams();
      const code = await runTransparencyCommand({
        argv: ["export", "--fortress", "/a", "--fortress", "/b"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(DUPLICATE));
    });

    it("verify refuses a missing --fortress value before the --input check", async () => {
      const { out, err } = streams();
      const code = await runVerifyTransparencyCommand({
        argv: ["--fortress"],
        out,
        err,
      });
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(err.text).toBe(expectedLine(MISSING_VALUE));
      expect(err.text).not.toContain("--input <path> is required");
    });
  });

  describe("intelligence diagnose (--fortress/--fortress-path alias, no err stream)", () => {
    async function runDiagnoseCapturingConsoleError(
      argv: string[],
    ): Promise<{ code: number; text: string }> {
      const errSpy: string[] = [];
      const orig = console.error;
      console.error = (...args: unknown[]) => {
        errSpy.push(args.join(" "));
      };
      try {
        const code = await runIntelligenceCommand({ argv });
        return { code, text: errSpy.join("\n") };
      } finally {
        console.error = orig;
      }
    }

    it("refuses a missing --fortress value with the exact canonical shape", async () => {
      const { code, text } = await runDiagnoseCapturingConsoleError(["diagnose", "--fortress"]);
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(text).toBe(fortressFlagRefusalText(MISSING_VALUE));
    });

    it("refuses a missing --fortress-path value (the alias) with the exact canonical shape", async () => {
      const { code, text } = await runDiagnoseCapturingConsoleError([
        "diagnose",
        "--fortress-path",
      ]);
      expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
      expect(text).toBe(fortressFlagRefusalText("--fortress-path requires a value"));
    });

    it("finding #3: --fortress and --fortress-path TOGETHER refuse, in either order", async () => {
      const bothOrders = [
        ["diagnose", "--fortress", "/a", "--fortress-path", "/b"],
        ["diagnose", "--fortress-path", "/b", "--fortress", "/a"],
      ];
      for (const argv of bothOrders) {
        const { code, text } = await runDiagnoseCapturingConsoleError(argv);
        expect(code).toBe(FORTRESS_FLAG_USAGE_EXIT_CODE);
        expect(text).toBe(
          fortressFlagRefusalText(aliasConflictMessage("--fortress", "--fortress-path")),
        );
      }
    });
  });
});
