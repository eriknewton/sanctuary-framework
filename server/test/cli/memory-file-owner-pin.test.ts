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
 */

import { mkdir, readdir, readFile, rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Writable } from "node:stream";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runMemoryIngestCommand as runMemoryIngestCommandProduction,
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
import { writeReplayAnchor } from "../../src/sdw/write-gate.js";

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
    const agentId = "claude_code:owner-pin-fresh";
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
    expect(await mcpReadGuardAllows("codex:someone-else")).toEqual({
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
      agentId: "claude_code:existing-owner",
    });
    expect(claim).toEqual({ status: "claimed" });
    const before = await corpusEntryCount();

    const source = await copyFixtureSet("basic", "memfile-owner-pin-conflict");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: "claude_code:different-agent" },
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("owner_scope_conflict");
    expect(await corpusEntryCount()).toBe(before);
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
    const agentId = "claude_code:drifted-run";
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
    expect(err.text()).toContain(`sdw-owner claim --agent-id ${agentId}`);
    expect(await corpusEntryCount()).toBe(before);
  });

  it("(d) fix round 1: a denied dialog on a fresh store leaves NO owner pin and NO passage (the pin is established only after Tier-1 approval)", async () => {
    const source = await copyFixtureSet("basic", "memfile-owner-pin-denied");
    const agentId = "claude_code:owner-pin-denied";
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
      dialogRunner: DENY_DIALOG,
    });
    expect(code).toBe(1);
    expect(await corpusEntryCount()).toBe(before);
    // The invariant this proves: `checkOrEstablishSdwOwnerPin` runs only
    // inside the `authorize` success branch in `runMemoryIngestCommand`, so a
    // denial never reaches it. Fails on 2ca3fa0e, where the pin was written
    // unconditionally before the Tier-1 gate ran at all.
    expect(await pinIsAbsent()).toBe(true);
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
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_AGENT_ID: "claude_code:owner-ref-test" },
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
