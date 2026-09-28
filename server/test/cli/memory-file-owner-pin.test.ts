/**
 * STEP1-F1: a CLI `memory_ingest` on a fresh fortress must establish the SDW
 * owner pin under the same rule the MCP persistent guard applies, so a
 * CLI-first write never leaves the store established with no pin — and the
 * pin is written only AFTER Tier-1 approval, under a real wrap-time agent id,
 * never before the approval gate and never under a synthetic fallback
 * principal (fix round 1: Claude F1/F2/F3, Grok findings 1/2).
 *
 * Drives the real CLI ingest entry point (`runMemoryIngestCommand`) against a
 * temp fortress, then reads through the real persistent guard the MCP server
 * constructs (`createPersistentMultiAgentIsolationGuard`), never a mock of
 * either. Isolation: every run points at a throwaway fortress created in a
 * temp dir, unlocked via SANCTUARY_PASSPHRASE, so the operator's real login
 * keychain and real ~/.sanctuary are never touched (AGENTS.md test isolation).
 *
 * Fail-before witnesses, stated plainly per revision (fix round 2, Claude
 * fail-before note): (a), (b), (c), (e), (f) fail against the pre-STEP1-F1
 * base tree `e7e09d65` (no CLI owner-pin logic existed at all — the MCP
 * guard's own read in (a) returns `owner_pin_missing_after_establishment`
 * instead of `{allowed:true}`, and (e)/(f) accept the request and leave a
 * nonzero corpus). Test (d) is different: it passes on `e7e09d65` (a denied
 * dialog there never wrote anything, because there was no pin logic to run
 * at all) and fails only on round 1's head `2ca3fa0e`, which is the correct
 * witness for THIS fix — `2ca3fa0e` established the pin before the Tier-1
 * gate ran, so a denied dialog there still left a pin behind.
 */

import { mkdir, readdir, readFile, rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Writable } from "node:stream";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runMemoryIngestCommand as runMemoryIngestCommandProduction,
  runMemoryEmitCommand as runMemoryEmitCommandProduction,
  runMemoryTranscodeCommand as runMemoryTranscodeCommandProduction,
  runMemoryTranscodeRestoreCommand as runMemoryTranscodeRestoreCommandProduction,
} from "../../src/cli/memory-file.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  claimSdwOwnerForOperator,
  createPersistentMultiAgentIsolationGuard,
  readSdwOwnerPin,
} from "../../src/sdw/memory-isolation.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { createSdwOwnerPinIfAbsent, writeReplayAnchor } from "../../src/sdw/write-gate.js";
import { AuditLog } from "../../src/operational/audit-log.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const PASSPHRASE = "memory-file-owner-pin-test-passphrase-v1";
const APPROVE_DIALOG = () => ({
  status: 0,
  signal: null,
  stdout: Buffer.from("approve\n"),
});
const DENY_DIALOG = () => ({
  status: 0,
  signal: null,
  stdout: Buffer.from("deny\n"),
});

// memory_ingest is Tier-1 by default; approve the local dialog unless a test
// supplies its own (parity with server/test/cli/memory-file.test.ts).
const runMemoryIngestCommand: typeof runMemoryIngestCommandProduction = (args) =>
  runMemoryIngestCommandProduction({
    ...args,
    dialogRunner: args.dialogRunner ?? APPROVE_DIALOG,
  });

function makeSink(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = {
    write: (chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    },
  } as unknown as Writable;
  return { stream, text: () => chunks.join("") };
}

const cleanupTasks: Array<() => Promise<void>> = [];
// Every master-key buffer this file resolves via resolveCliMasterKey, zeroed
// in afterEach so a raw key never outlives its test (AGENTS.md #6: never
// expose a key in a log or diagnostic; the same discipline applies here to a
// key a test itself materialized).
const liveMasterKeys: Uint8Array[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function copyFixtureSet(name: string, prefix: string): Promise<string> {
  const source = join(FIXTURE_ROOT, name);
  const target = await tempDir(prefix);
  for (const filename of (await readdir(source)).filter((f) => f.endsWith(".md"))) {
    await writeFile(join(target, filename), await readFile(join(source, filename)));
  }
  return target;
}

describe("CLI memory_ingest owner-pin establishment (STEP1-F1)", () => {
  let fortress: string;
  let prevStoragePath: string | undefined;

  beforeEach(async () => {
    prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    fortress = join(await tempDir("memfile-owner-pin"), ".sanctuary");
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    // Bootstrap a real passphrase-mode fortress so the CLI's resolveCliMasterKey
    // unlocks an existing custody envelope (parity with memory-file.test.ts).
    const storage = new FilesystemStorage(join(fortress, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      passphrase: PASSPHRASE,
      bootstrap: true,
      storagePathHint: fortress,
    });
    liveMasterKeys.push(masterKey);
    const identities = new IdentityManager(storage, masterKey);
    const { storedIdentity } = createIdentity(
      "memory-file-owner-pin-test",
      derivePurposeKey(masterKey, "identity-encryption"),
      "passphrase",
    );
    await identities.save(storedIdentity);
  });

  afterEach(async () => {
    if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
    while (liveMasterKeys.length > 0) liveMasterKeys.pop()!.fill(0);
    while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
  });

  /** Real backend + real master key, exactly what the CLI and the MCP server
   * both construct their guard/adapter over, never a copy or a mock. Tracked
   * in `liveMasterKeys` so afterEach zeroes it. */
  async function realStorageAndMasterKey(): Promise<{
    storage: FilesystemStorage;
    masterKey: Uint8Array;
  }> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      passphrase: PASSPHRASE,
      storagePathHint: fortress,
    });
    liveMasterKeys.push(masterKey);
    return { storage, masterKey };
  }

  async function corpusEntryCount(): Promise<number> {
    const { storage } = await realStorageAndMasterKey();
    return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).length;
  }

  async function pinIsAbsent(): Promise<boolean> {
    const { storage, masterKey } = await realStorageAndMasterKey();
    return (await readSdwOwnerPin(storage, masterKey)).status === "absent";
  }

  /** The REAL persistent guard the MCP server constructs (index.ts wiring),
   * built over the same storage/masterKey/fortressId/ownerRef the CLI used. */
  async function mcpReadGuardAllows(agentId: string | undefined): Promise<
    { readonly allowed: true } | { readonly allowed: false; readonly reason: string }
  > {
    const { storage, masterKey } = await realStorageAndMasterKey();
    const guard = createPersistentMultiAgentIsolationGuard({
      storage,
      masterKey,
      fortressId: fortressIdFromStoragePath(fortress),
      ownerRef: "fleet-self",
      ownerIdentity: () => agentId,
    });
    return guard("memory_search");
  }

  it("(a) a CLI ingest on a fresh store establishes the pin: the same agent id reads through the MCP guard, a different one is refused", async () => {
    const source = await copyFixtureSet("basic", "memfile-owner-pin-fresh");
    const agentId = "claude_code:fortress-00000000000a1000";
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: agentId },
    });
    expect(code, err.text()).toBe(0);
    expect(await corpusEntryCount()).toBeGreaterThan(0);

    expect(await mcpReadGuardAllows(agentId)).toEqual({ allowed: true });
    expect(await mcpReadGuardAllows("cursor:fortress-0000000000000e15")).toEqual({
      allowed: false,
      reason: "owner_scope_conflict",
    });
  });

  it("(b) established and pinned to another agent: CLI ingest is refused and writes no passage", async () => {
    const { storage, masterKey } = await realStorageAndMasterKey();
    const claim = await claimSdwOwnerForOperator({
      storage,
      masterKey,
      fortressId: fortressIdFromStoragePath(fortress),
      ownerRef: "fleet-self",
      agentId: "claude_code:fortress-0000000000000e01",
    });
    expect(claim).toEqual({ status: "claimed" });
    const before = await corpusEntryCount();
    const pinBefore = await readSdwOwnerPin(storage, masterKey);
    expect(pinBefore.status).toBe("valid");

    const source = await copyFixtureSet("basic", "memfile-owner-pin-conflict");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: "claude_code:fortress-0000000000000d1f" },
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("owner_scope_conflict");
    expect(await corpusEntryCount()).toBe(before);
    // fix round 2 (Claude N6): the refused ingest must not just fail to
    // ADVANCE the pin (a status check alone would miss a read-modify-write
    // that happened to round-trip the same agent id) — it must never touch
    // the record at all, proven by the raw ciphertext bytes being identical.
    const pinAfter = await readSdwOwnerPin(storage, masterKey);
    expect(pinAfter.status).toBe("valid");
    if (pinBefore.status === "valid" && pinAfter.status === "valid") {
      expect(Buffer.from(pinAfter.raw)).toEqual(Buffer.from(pinBefore.raw));
    }
  });

  it("(c) established with passages but no pin (the F1-drifted state): CLI ingest refuses with owner_pin_missing_after_establishment and prints the claim command; no passage written", async () => {
    // Simulate the drifted state F1 describes: the store carries established
    // security metadata (a real replay anchor, written through the real gated
    // path, mirroring the "never lets the first process silently inherit an
    // existing unpinned SDW" case in memory-isolation-persistent.test.ts) and
    // no owner pin exists — exactly what a pre-fix CLI-first ingest could
    // leave behind on an already-used legacy store.
    const { storage, masterKey } = await realStorageAndMasterKey();
    await writeReplayAnchor(storage, masterKey, {
      catalog: 0,
      chain_head: [],
      manifests: [],
      tombstones: [],
      export_state: 0,
    });
    const before = await corpusEntryCount();
    expect(before).toBe(0);

    const source = await copyFixtureSet("basic", "memfile-owner-pin-drifted");
    const agentId = "claude_code:fortress-00000000000c3000";
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: agentId },
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("owner_pin_missing_after_establishment");
    // fix round 2: the printed command shell-quotes its arguments.
    expect(err.text()).toContain(`sdw-owner claim --agent-id '${agentId}'`);
    expect(await corpusEntryCount()).toBe(before);
  });

  it("(d) fix round 1: a denied dialog on a fresh store leaves NO owner pin and NO passage (the pin is established only after Tier-1 approval)", async () => {
    const source = await copyFixtureSet("basic", "memfile-owner-pin-denied");
    const agentId = "claude_code:fortress-00000000000f6000";
    let dialogs = 0;
    const countingDeny = () => {
      dialogs += 1;
      return DENY_DIALOG();
    };
    const before = await corpusEntryCount();
    expect(before).toBe(0);
    expect(await pinIsAbsent()).toBe(true);

    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: agentId },
      dialogRunner: countingDeny,
    });
    expect(code).toBe(1);
    // The run must have REACHED the Tier-1 dialog and been denied there, not
    // been refused earlier (for example by the agent-id shape rule, which
    // also leaves no pin): exactly one dialog, and the policy-denied text.
    expect(dialogs).toBe(1);
    expect(err.text()).toContain("not permitted by the local policy");
    expect(await corpusEntryCount()).toBe(before);
    // The invariant this proves: `checkOrEstablishSdwOwnerPin` runs only
    // inside the `authorize` success branch in `runMemoryIngestCommand`, so a
    // denial never reaches it. Fails on 2ca3fa0e, where the pin was written
    // unconditionally before the Tier-1 gate ran at all.
    expect(await pinIsAbsent()).toBe(true);
  });

  it("(g) SDW-OWNER-PIN-AGENT-ID-SHAPE-01: a store already pinned to a LEGACY (pre-rule) id keeps working for that id, with a stderr note and a legacy audit row", async () => {
    const { storage, masterKey } = await realStorageAndMasterKey();
    expect(
      await createSdwOwnerPinIfAbsent(storage, masterKey, {
        version: 1,
        fortress_id: fortressIdFromStoragePath(fortress),
        owner_ref: "fleet-self",
        agent_id: "cli-ingest",
        pinned_at: "2026-01-01T00:00:00.000Z",
      }),
    ).not.toBe("unsupported");
    const source = await copyFixtureSet("basic", "memfile-owner-pin-legacy");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: "cli-ingest" },
    });
    expect(code, err.text()).toBe(0);
    expect(await corpusEntryCount()).toBeGreaterThan(0);
    expect(err.text()).toContain("LEGACY SDW owner pin");
    const reread = await realStorageAndMasterKey();
    const audit = new AuditLog(reread.storage, reread.masterKey);
    const { entries } = await audit.query({ operation_type: "memory_ingest_owner_pin_legacy", limit: 10 });
    expect(entries).toHaveLength(1);
    expect(String(entries[0]!.details?.reason)).toContain("LEGACY SDW owner pin");
  });

  it("(e) fix round 1: a non-default --owner-ref refuses outright, before any bootstrap or write", async () => {
    const before = await corpusEntryCount();
    expect(before).toBe(0);
    expect(await pinIsAbsent()).toBe(true);

    const source = await copyFixtureSet("basic", "memfile-owner-pin-other-scope");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: [
        "--harness", "claude-code",
        "--dir", source,
        "--fortress", fortress,
        "--owner-ref", "some-other-scope",
      ],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: "claude_code:fortress-0000000000000ef7" },
    });
    expect(code).not.toBe(0);
    expect(err.text()).toContain("fleet-self");
    expect(await corpusEntryCount()).toBe(before);
    expect(await pinIsAbsent()).toBe(true);
  });

  it("(f) fix round 1: with no SANCTUARY_AGENT_ID, a fresh store refuses instead of pinning a synthetic principal", async () => {
    const before = await corpusEntryCount();
    expect(before).toBe(0);
    expect(await pinIsAbsent()).toBe(true);

    const source = await copyFixtureSet("basic", "memfile-owner-pin-no-identity");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).not.toBe(0);
    expect(err.text()).toContain("SANCTUARY_AGENT_ID");
    expect(err.text()).not.toContain("cli-ingest");
    expect(await corpusEntryCount()).toBe(before);
    // Fails on 2ca3fa0e: that revision pinned the fortress to the synthetic
    // "cli-ingest" principal here instead of refusing.
    expect(await pinIsAbsent()).toBe(true);
  });
});

/**
 * STEP1-F2: the same owner-pin rule STEP1-F1 wired into `memory_ingest`
 * extended to the three sibling CLI verbs that also materialize SDW vault
 * content onto disk or read the shared scope: `memory_emit`,
 * `memory_transcode`, `memory_transcode_restore`. Each block below drives the
 * REAL CLI entry point for its verb against a temp fortress with a real
 * injected keychain-free unlock (never the login keychain), then reads
 * through the same real persistent guard the MCP server constructs, exactly
 * as the STEP1-F1 block above does for `memory_ingest`.
 *
 * Fail-before witness: every (a)/(b)/(c) test in these three blocks fails on
 * the pre-STEP1-F2 tree (the commit immediately before this change) because
 * none of `memory_emit`/`memory_transcode`/`memory_transcode_restore` ran any
 * owner-pin check at all: a "different agent" run that should refuse with
 * `owner_scope_conflict` instead proceeds and produces output, and a
 * "drifted" store that should refuse with
 * `owner_pin_missing_after_establishment` instead proceeds silently.
 *
 * STEP1-F2 fix round 1 added (d)/(e)/(f) to each block, for the non-default
 * `--owner-ref` lockout the adversarial code gate on commit `0f0db45d` found.
 * Of those three, only (d) is a fail-before witness of that round: it fails
 * on `0f0db45d` for all three verbs. (e) and (f) already passed on
 * `0f0db45d` — the protections they check (missing-identity refusal, and
 * establishment happening only after approval) already existed there via
 * `precheckOwnerPinOrRefuse` / `establishOwnerPinAfterApproval`; they are
 * regression guards closing a prior test gap, not proof of that round's fix.
 */
for (const verbName of ["memory_emit", "memory_transcode", "memory_transcode_restore"] as const) {
  // Every agent id below is in the wrapped form `sanctuary wrap` mints
  // (`<harness-kind>:fortress-<16 hex>`, SDW-OWNER-PIN-AGENT-ID-SHAPE-01), so
  // each test reaches the check it names instead of the shape refusal; the
  // last two hex characters keep the three verbs' ids distinct.
  const verbHex = { memory_emit: "e1", memory_transcode: "e2", memory_transcode_restore: "e3" }[verbName];
  describe(`CLI ${verbName} owner-pin establishment (STEP1-F2)`, () => {
    let fortress: string;
    let prevStoragePath: string | undefined;

    beforeEach(async () => {
      prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
      fortress = join(await tempDir(`memfile-owner-pin-${verbName}`), ".sanctuary");
      await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
      const storage = new FilesystemStorage(join(fortress, "state"));
      const masterKey = await resolveCliMasterKey(storage, {
        passphrase: PASSPHRASE,
        bootstrap: true,
        storagePathHint: fortress,
      });
      liveMasterKeys.push(masterKey);
      const identities = new IdentityManager(storage, masterKey);
      const { storedIdentity } = createIdentity(
        `memory-file-owner-pin-${verbName}-test`,
        derivePurposeKey(masterKey, "identity-encryption"),
        "passphrase",
      );
      await identities.save(storedIdentity);
    });

    afterEach(async () => {
      if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
      while (liveMasterKeys.length > 0) liveMasterKeys.pop()!.fill(0);
      while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
    });

    async function realStorageAndMasterKey(): Promise<{
      storage: FilesystemStorage;
      masterKey: Uint8Array;
    }> {
      const storage = new FilesystemStorage(join(fortress, "state"));
      const masterKey = await resolveCliMasterKey(storage, {
        passphrase: PASSPHRASE,
        storagePathHint: fortress,
      });
      liveMasterKeys.push(masterKey);
      return { storage, masterKey };
    }

    async function mcpReadGuardAllows(agentId: string | undefined): Promise<
      { readonly allowed: true } | { readonly allowed: false; readonly reason: string }
    > {
      const { storage, masterKey } = await realStorageAndMasterKey();
      const guard = createPersistentMultiAgentIsolationGuard({
        storage,
        masterKey,
        fortressId: fortressIdFromStoragePath(fortress),
        ownerRef: "fleet-self",
        ownerIdentity: () => agentId,
      });
      return guard("memory_search");
    }

    /** Runs the verb under test with the given agent id and dialog, against a
     * fresh output/restore/projection directory this test owns. */
    async function runVerb(options: {
      readonly agentId: string | undefined;
      readonly dialogRunner?: () => { status: number; signal: null; stdout: Buffer };
      readonly archiveId?: string;
      /** STEP1-F2 fix round 1: an explicit --owner-ref override, to drive the
       * pre-bootstrap owner-ref refusal in `refuseOwnerRefOrIdentityBeforeBootstrap`. */
      readonly ownerRef?: string;
    }): Promise<{ code: number; out: string; err: string; outputDir: string }> {
      const outputDir = join(await tempDir(`memfile-owner-pin-${verbName}-out`), "materialized");
      const out = makeSink();
      const err = makeSink();
      const env = options.agentId === undefined
        ? { SANCTUARY_PASSPHRASE: PASSPHRASE }
        : { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: options.agentId };
      const dialogRunner = options.dialogRunner ?? APPROVE_DIALOG;
      const ownerRefFlags = options.ownerRef !== undefined ? ["--owner-ref", options.ownerRef] : [];
      let code: number;
      if (verbName === "memory_emit") {
        code = await runMemoryEmitCommandProduction({
          argv: ["--harness", "claude-code", "--dir", outputDir, "--fortress", fortress, ...ownerRefFlags],
          out: out.stream,
          err: err.stream,
          env,
          dialogRunner,
        });
      } else if (verbName === "memory_transcode") {
        code = await runMemoryTranscodeCommandProduction({
          argv: [
            "--from-harness", "claude-code",
            "--to-harness", "codex",
            "--mode", "reversible",
            "--dir", outputDir,
            "--fortress", fortress,
            ...ownerRefFlags,
          ],
          out: out.stream,
          err: err.stream,
          env,
          dialogRunner,
        });
      } else {
        code = await runMemoryTranscodeRestoreCommandProduction({
          argv: [
            "--archive-id", options.archiveId ?? "0".repeat(32),
            "--dir", outputDir,
            "--fortress", fortress,
            ...ownerRefFlags,
          ],
          out: out.stream,
          err: err.stream,
          env,
          dialogRunner,
        });
      }
      return { code, out: out.text(), err: err.text(), outputDir };
    }

    it("(a) a fresh store establishes the pin on the first run: a same-agent re-run never sees owner_scope_conflict, a different agent's run does, and the MCP guard agrees", async () => {
      const agentId = `claude_code:fortress-00000000000a10${verbHex}`;
      // The verb's own business outcome does not matter here (an empty vault
      // has nothing to transcode/restore/emit, so transcode/restore commonly
      // fail after establishing the pin) — what this proves, driven entirely
      // through two REAL CLI invocations (never the MCP guard doing the
      // establishing itself, which would pass this assertion even on the
      // unpatched base tree since the guard establishes on its own first
      // call), is that the FIRST invocation's precheck/establish step, which
      // runs strictly before that business logic, already committed the pin
      // under this agent id.
      const first = await runVerb({ agentId });
      expect(first.err).not.toContain("owner_scope_conflict");
      expect(first.err).not.toContain("owner_identity_missing");

      const sameAgentAgain = await runVerb({ agentId });
      expect(sameAgentAgain.err).not.toContain("owner_scope_conflict");

      const differentAgent = await runVerb({ agentId: "cursor:fortress-0000000000000e15" });
      expect(differentAgent.code).toBe(1);
      expect(differentAgent.err).toContain("owner_scope_conflict");
      await expect(readdir(differentAgent.outputDir)).rejects.toMatchObject({ code: "ENOENT" });

      // The MCP persistent guard, reading the SAME real record the CLI wrote,
      // agrees: this agent id reads through, a different one is refused.
      expect(await mcpReadGuardAllows(agentId)).toEqual({ allowed: true });
      expect(await mcpReadGuardAllows("cursor:fortress-0000000000000e15")).toEqual({
        allowed: false,
        reason: "owner_scope_conflict",
      });
    });

    it("(b) established and pinned to another agent: the verb is refused with owner_scope_conflict and writes no output", async () => {
      const { storage, masterKey } = await realStorageAndMasterKey();
      const claim = await claimSdwOwnerForOperator({
        storage,
        masterKey,
        fortressId: fortressIdFromStoragePath(fortress),
        ownerRef: "fleet-self",
        agentId: "claude_code:fortress-0000000000000e01",
      });
      expect(claim).toEqual({ status: "claimed" });

      const result = await runVerb({ agentId: "claude_code:fortress-0000000000000d1f" });
      expect(result.code).toBe(1);
      expect(result.err).toContain("owner_scope_conflict");
      await expect(readdir(result.outputDir)).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("(c) established with content but no pin (the drifted state): the verb refuses with owner_pin_missing_after_establishment and prints the claim command; no output written", async () => {
      const { storage, masterKey } = await realStorageAndMasterKey();
      await writeReplayAnchor(storage, masterKey, {
        catalog: 0,
        chain_head: [],
        manifests: [],
        tombstones: [],
        export_state: 0,
      });
      const agentId = `claude_code:fortress-00000000000c30${verbHex}`;
      const result = await runVerb({ agentId });
      expect(result.code).toBe(1);
      expect(result.err).toContain("owner_pin_missing_after_establishment");
      expect(result.err).toContain(`sdw-owner claim --agent-id '${agentId}'`);
      await expect(readdir(result.outputDir)).rejects.toMatchObject({ code: "ENOENT" });
      expect(await pinIsAbsentIn(storage, masterKey)).toBe(true);
    });

    it("(d) STEP1-F2 fix round 1: a non-default --owner-ref on a fresh store is refused before the dialog and leaves NO pin", async () => {
      let dialogs = 0;
      const countingApprove = () => {
        dialogs += 1;
        return APPROVE_DIALOG();
      };
      const { storage, masterKey } = await realStorageAndMasterKey();
      const result = await runVerb({
        agentId: `claude_code:fortress-00000000000d40${verbHex}`,
        ownerRef: "some-other-scope",
        dialogRunner: countingApprove,
      });
      expect(result.code).not.toBe(0);
      expect(result.err).toContain("fleet-self");
      // The fortress's owner pin is ONE record, never keyed by owner_ref: a
      // fresh store's precheck would report "fresh" for ANY owner_ref (scope
      // is compared only once a pin exists), so without this pre-bootstrap
      // refusal the verb would establish the fortress's only pin slot under
      // a scope nothing else can ever read, claim, or transfer back.
      expect(dialogs).toBe(0);
      expect(await pinIsAbsentIn(storage, masterKey)).toBe(true);
      await expect(readdir(result.outputDir)).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("(e) regression guard, not a fail-before witness of this round: with no SANCTUARY_AGENT_ID, a fresh store refuses instead of pinning an unwrapped principal (this protection already existed via precheckOwnerPinOrRefuse before STEP1-F2 fix round 1; this case just was not tested for the three sibling verbs until now)", async () => {
      let dialogs = 0;
      const countingApprove = () => {
        dialogs += 1;
        return APPROVE_DIALOG();
      };
      const { storage, masterKey } = await realStorageAndMasterKey();
      const result = await runVerb({ agentId: undefined, dialogRunner: countingApprove });
      expect(result.code).not.toBe(0);
      expect(result.err).toContain("SANCTUARY_AGENT_ID");
      expect(dialogs).toBe(0);
      expect(await pinIsAbsentIn(storage, masterKey)).toBe(true);
      await expect(readdir(result.outputDir)).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("(f) regression guard, not a fail-before witness of this round: a denied dialog on a fresh store leaves NO owner pin and writes nothing (this protection already existed via establishOwnerPinAfterApproval running only after ApprovalGate approval, before STEP1-F2 fix round 1; this case just was not tested for the three sibling verbs until now)", async () => {
      const { storage, masterKey } = await realStorageAndMasterKey();
      const agentId = `claude_code:fortress-00000000000f60${verbHex}`;
      const result = await runVerb({ agentId, dialogRunner: DENY_DIALOG });
      expect(result.code).not.toBe(0);
      expect(result.err).toContain("not approved");
      await expect(readdir(result.outputDir)).rejects.toMatchObject({ code: "ENOENT" });
      // The invariant this proves: `establishOwnerPinAfterApproval` runs only
      // after the ApprovalGate allows the request, so a denial never reaches
      // it. Same discipline as memory_ingest's own authorize-branch
      // establishment (STEP1-F1 fix round 1).
      expect(await pinIsAbsentIn(storage, masterKey)).toBe(true);
    });
  });
}

async function pinIsAbsentIn(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
): Promise<boolean> {
  return (await readSdwOwnerPin(storage, masterKey)).status === "absent";
}
