/**
 * Coverage for the `sanctuary cortex-export` CLI verb wiring
 * (`runCortexExportCommand` / `cmdRun`) and its loud-audit factory
 * (`buildExportAudit`). The injectable core (`runExportPipeline`) is already
 * covered in `test/castle-wall/export/cli-pipeline.test.ts`; THIS file covers
 * the arg-parse + fortress + gate-construction WIRING that only the CLI does.
 *
 * Hermetic:
 *   - Arg-parse + the fail-closed passphrase gate need no fortress at all.
 *   - The fortress-backed paths (file-sink default vs http-sink gate) run
 *     against a real temp fortress bootstrapped once with a known passphrase;
 *     host state is isolated via the `--fortress` flag and a snapshot/restore
 *     of `process.env.SANCTUARY_STORAGE_PATH` (the flag mutates it globally).
 *   - The http-sink path NEVER touches the network: a non-interactive stdin
 *     makes the Tier-1 approval channel deny, so `enable()` refuses before it
 *     ever arms the outbound push.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runCortexExportCommand,
  buildExportAudit,
} from "../../src/cli/cortex-export.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import type { AuditEntryInput } from "../../src/operational/audit-log.js";

/** A Writable that accumulates everything written, for assertion. */
function makeSink(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return { stream, text: () => chunks.join("") };
}

const PASSPHRASE = "cortex-export-test-passphrase-123";

describe("runCortexExportCommand: arg-parse (no fortress touched)", () => {
  it("no args prints usage and exits 2 (nothing to run)", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({ argv: [], out: out.stream, err: err.stream, env: {} });
    expect(code).toBe(2);
    expect(out.text()).toMatch(/Usage: sanctuary cortex-export/);
  });

  it("--help prints usage and exits 0", async () => {
    const out = makeSink();
    const code = await runCortexExportCommand({ argv: ["--help"], out: out.stream, env: {} });
    expect(code).toBe(0);
    expect(out.text()).toMatch(/Deliver Castle Wall's enforcement decisions/);
  });

  it("run --help prints the run usage and exits 0", async () => {
    const out = makeSink();
    const code = await runCortexExportCommand({ argv: ["run", "--help"], out: out.stream, env: {} });
    expect(code).toBe(0);
    expect(out.text()).toMatch(/cortex-export run\. Export new enforcement events/);
  });

  it("an unknown subcommand is rejected with exit 2", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({
      argv: ["frobnicate"],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toMatch(/Unknown cortex-export command: frobnicate/);
  });
});

describe("runCortexExportCommand: fail-closed passphrase gate (security carve-out)", () => {
  // The gate (:300-307) fires BEFORE any fortress access, so no temp dir needed.
  let prevStoragePath: string | undefined;

  beforeEach(() => {
    prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  });

  afterEach(() => {
    if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
  });

  it("refuses (exit 1) when NONE of passphrase / --passphrase / recovery-key is set", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({ argv: ["run"], out: out.stream, err: err.stream, env: {} });
    expect(code).toBe(1);
    expect(err.text()).toMatch(/requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY/);
    // Fail-closed: nothing was exported, no summary line.
    expect(out.text()).toBe("");
  });

  it("the --fortress flag still mutates the global storage path even on the refusal path (:297)", async () => {
    // The flag mutation happens before the passphrase gate; assert BOTH the
    // env mutation (finding #3) and that we still fail closed (no passphrase).
    const marker = join(tmpdir(), "cortex-fortress-marker-xyz");
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({
      argv: ["run", "--fortress", marker],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(1);
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe(marker);
  });
});

describe("runCortexExportCommand: fortress-backed sink wiring", () => {
  let base: string;
  let fortress: string;
  let prevStoragePath: string | undefined;

  beforeEach(async () => {
    prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    base = await mkdtemp(join(tmpdir(), "cortex-cli-"));
    fortress = join(base, ".sanctuary");
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    // Bootstrap a real passphrase-mode fortress so the CLI's unbootstrapped
    // `resolveCliMasterKey` unlocks the existing custody envelope.
    const storage = new FilesystemStorage(join(fortress, "state"));
    await resolveCliMasterKey(storage, {
      passphrase: PASSPHRASE,
      bootstrap: true,
      storagePathHint: fortress,
    });
  });

  afterEach(() => {
    if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
  });

  async function writeExportConfig(config: Record<string, unknown>): Promise<void> {
    const dir = join(fortress, "policy", "egress");
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await writeFile(join(dir, "cortex-export.json"), JSON.stringify(config));
  }

  it("the default (missing config) uses the file sink: local, no network, exit 0", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({
      argv: ["run", "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(0);
    expect(out.text()).toMatch(/via the file sink \(local, no network\)/);
    // The best-effort audit append succeeded, so no drop-warning was emitted.
    expect(err.text()).not.toMatch(/audit append .* was dropped/);
  }, 30_000);

  it("an http sink fails CLOSED on a non-interactive stream: refused, exit 1, no push", async () => {
    await writeExportConfig({
      sink: "http",
      enabled: true,
      destination_url: "https://collector.example/xsiam",
    });
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({
      argv: ["run", "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    // The ApprovalGate construction path (:352-388) ran, the Tier-1 gate denied
    // on the non-TTY stream, and the outbound push was refused before arming.
    expect(code).toBe(1);
    expect(err.text()).toMatch(/Refused: the outbound push was not armed/);
    expect(err.text()).toMatch(/Nothing was exported over the network/);
  }, 30_000);

  it("an http sink refusal reported as JSON still exits 1 with ok:false", async () => {
    await writeExportConfig({
      sink: "http",
      enabled: true,
      destination_url: "https://collector.example/xsiam",
    });
    const out = makeSink();
    const err = makeSink();
    const code = await runCortexExportCommand({
      argv: ["run", "--fortress", fortress, "--json"],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(1);
    const parsed = JSON.parse(out.text());
    expect(parsed.ok).toBe(false);
    expect(typeof parsed.refused).toBe("string");
  }, 30_000);
});

describe("buildExportAudit: a dropped audit append is LOUD, never silent (#946 class)", () => {
  it("emits a stderr warning naming the operation when appendCritical throws", async () => {
    const err = makeSink();
    const audit = buildExportAudit(
      {
        appendCritical: async (_entry: AuditEntryInput) => {
          throw new Error("audit store unavailable");
        },
      },
      err.stream,
    );

    // Must NOT throw: a dropped audit never blocks the export op.
    await expect(audit("enforcement_export_enabled", { sink: "http" }, "success")).resolves.toBeUndefined();

    const text = err.text();
    expect(text).toMatch(/audit append for "enforcement_export_enabled" was dropped/);
    expect(text).toMatch(/audit store unavailable/);
    expect(text).toMatch(/has no audit record/);
  });

  it("stays silent and forwards the entry unchanged when the append succeeds", async () => {
    const err = makeSink();
    const seen: AuditEntryInput[] = [];
    const audit = buildExportAudit(
      {
        appendCritical: async (entry: AuditEntryInput) => {
          seen.push(entry);
        },
      },
      err.stream,
    );

    await audit("enforcement_export_run", { delivered: 3 }, "success");

    expect(err.text()).toBe("");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      layer: "l1",
      operation: "enforcement_export_run",
      identity_id: "operator",
      result: "success",
      details: { delivered: 3 },
    });
  });
});
