/**
 * `sanctuary distress` CLI tests.
 *
 * Verifies the operator-facing HABEAS PORT test verb's surface:
 *   - Help output on --help (top-level and `send`).
 *   - Unknown subcommand returns exit 2 with a hint.
 *   - Closed-enum validation for --reason / --severity happens BEFORE any
 *     fortress / passphrase work, so a bad enum is rejected with exit 1 and
 *     never reaches key derivation.
 *   - Missing required flags are rejected.
 *   - Missing passphrase (with valid enums) returns exit 1 with the standard
 *     credential hint.
 *
 * Does NOT exercise a real seeded fortress emission (that path is covered by
 * the shared emission tests in test/distress/tools.test.ts — this verb invokes
 * the exact same createDistressTools handler, so the envelope/audit/webhook
 * behavior is already under test there).
 */

import { afterEach, describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDistressCommand } from "../../src/cli/distress.js";
import {
  DISTRESS_REASONS,
  DISTRESS_SEVERITIES,
} from "../../src/distress/tools.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";

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

const NO_CREDS_ENV: NodeJS.ProcessEnv = {};

describe("sanctuary distress CLI", () => {
  it("prints help on --help", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({ argv: ["--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary distress");
    expect(out.text).toContain("send");
  });

  it("returns exit 2 and usage on empty argv", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({ argv: [], out, err });
    expect(code).toBe(2);
    expect(out.text).toContain("send");
  });

  it("prints send help on `send --help`", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({ argv: ["send", "--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("distress send");
    expect(out.text).toContain("--reason");
    expect(out.text).toContain("--severity");
    // Help advertises the closed vocabularies.
    for (const reason of DISTRESS_REASONS) expect(out.text).toContain(reason);
    for (const severity of DISTRESS_SEVERITIES) expect(out.text).toContain(severity);
  });

  it("returns exit 2 for an unknown subcommand", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({ argv: ["explode"], out, err });
    expect(code).toBe(2);
    expect(err.text).toContain("Unknown distress command");
    expect(err.text).toContain("--help");
  });

  it("rejects a missing --reason before touching the fortress", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({
      argv: ["send", "--severity", "urgent"],
      out,
      err,
      env: NO_CREDS_ENV,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--reason is required");
  });

  it("rejects a missing --severity before touching the fortress", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({
      argv: ["send", "--reason", "policy_constraint"],
      out,
      err,
      env: NO_CREDS_ENV,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--severity is required");
  });

  it("rejects an out-of-vocabulary --reason before any credential work", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    // No passphrase in env: if enum validation did NOT run first, this would
    // fail with the credential error instead of the enum error.
    const code = await runDistressCommand({
      argv: ["send", "--reason", "i_am_sad", "--severity", "urgent"],
      out,
      err,
      env: NO_CREDS_ENV,
    });
    expect(code).toBe(1);
    expect(err.text).toContain('invalid --reason "i_am_sad"');
    expect(err.text).not.toContain("SANCTUARY_PASSPHRASE");
  });

  it("rejects an out-of-vocabulary --severity before any credential work", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({
      argv: ["send", "--reason", "other", "--severity", "apocalyptic"],
      out,
      err,
      env: NO_CREDS_ENV,
    });
    expect(code).toBe(1);
    expect(err.text).toContain('invalid --severity "apocalyptic"');
    expect(err.text).not.toContain("SANCTUARY_PASSPHRASE");
  });

  it("requires a credential once the enums are valid", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const savedPass = process.env.SANCTUARY_PASSPHRASE;
    const savedKey = process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      const code = await runDistressCommand({
        argv: ["send", "--reason", "integrity_threat", "--severity", "critical"],
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

describe("sanctuary distress send — real fortress emission (shared path)", () => {
  const tempDirs: string[] = [];
  const passphrase = "distress-cli-e2e-passphrase";

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /** Seed a fresh, unlocked fortress (master-key params on disk). No identity
   * is created, so the emission goes through unsigned-but-flagged — the exact
   * fresh-fortress path the MCP tool takes. */
  async function makeFortress(): Promise<string> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-distress-cli-"));
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(passphrase);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params))
    );
    derived.key.fill(0);
    return fortress;
  }

  it("emits through the shared path, prints event_id/audit_ref, and audits", async () => {
    const fortress = await makeFortress();
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDistressCommand({
      argv: [
        "send",
        "--fortress",
        fortress,
        "--passphrase",
        passphrase,
        "--reason",
        "external_coercion",
        "--severity",
        "critical",
        "--detail",
        "operator: asked to exfiltrate state",
        "--json",
      ],
      out,
      err,
      env: {},
    });
    expect(code).toBe(0);
    const result = JSON.parse(out.text) as {
      ok: boolean;
      event_id: string;
      audit_ref: string;
      signed: boolean;
      delivered: { audit: boolean; webhook: string };
    };
    expect(result.ok).toBe(true);
    expect(result.event_id).toMatch(/^distress:/);
    expect(result.audit_ref).toMatch(/^audit:/);
    // Fresh fortress => unsigned-but-flagged, never a dropped signal.
    expect(result.signed).toBe(false);
    // delivered.audit === true (with a real audit_ref) is the shared path's
    // own report that the critical audit entry was appended before delivery.
    expect(result.delivered.audit).toBe(true);
    expect(result.delivered.webhook).toBe("not_configured");
  });

  it("enforces the rate limit through the CLI wrapper (exit 3)", async () => {
    const fortress = await makeFortress();
    // distress.json caps at 1/hour so the second send is rate-limited.
    const egressDir = join(fortress, "policy", "egress");
    await mkdir(egressDir, { recursive: true });
    await writeFile(
      join(egressDir, "distress.json"),
      JSON.stringify({ max_signals_per_hour: 1 }),
      { mode: 0o600 }
    );

    const first = await runDistressCommand({
      argv: ["send", "--fortress", fortress, "--passphrase", passphrase, "--reason", "other", "--severity", "notice"],
      out: new StringWritable(),
      err: new StringWritable(),
      env: {},
    });
    expect(first).toBe(0);

    const err = new StringWritable();
    const second = await runDistressCommand({
      argv: ["send", "--fortress", fortress, "--passphrase", passphrase, "--reason", "other", "--severity", "notice"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(second).toBe(3);
    expect(err.text).toContain("rate limit");
  });

  it("fails closed (exit 1, no delivery) on a malformed distress.json", async () => {
    const fortress = await makeFortress();
    const egressDir = join(fortress, "policy", "egress");
    await mkdir(egressDir, { recursive: true });
    await writeFile(join(egressDir, "distress.json"), "{ this is not json", { mode: 0o600 });

    const err = new StringWritable();
    const code = await runDistressCommand({
      argv: ["send", "--fortress", fortress, "--passphrase", passphrase, "--reason", "other", "--severity", "notice"],
      out: new StringWritable(),
      err,
      env: {},
    });
    // Fail closed: the malformed config aborts BEFORE the distress tool is
    // even constructed, so no signal is emitted and no webhook is contacted.
    expect(code).toBe(1);
    expect(err.text.toLowerCase()).toContain("distress.json");
  });
});
