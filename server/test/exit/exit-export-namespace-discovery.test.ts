/**
 * `sanctuary exit export` state-namespace resolution + zero-state honesty.
 *
 * Regression suite for the silent-empty-export defect: `--state-namespace` is
 * repeatable and optional, but the CLI forwarded the parser's empty array
 * verbatim, and `exportEncryptedState` resolved namespaces with `??`, which
 * falls back only on null/undefined. An empty array is neither, so the
 * discover-every-namespace fallback was dead on the CLI path and an operator
 * who omitted the flag got a signed, well-formed, completely empty bundle that
 * exited 0. Exit is one of the seven sovereignty principles; an exit bundle
 * that looks correct and carries none of the operator's state is the worst
 * outcome this path has.
 *
 * Coverage:
 *   - No --state-namespace → every discoverable namespace is exported (the
 *     defect: this asserted total_keys 0 before the fix).
 *   - --state-namespace still restricts the export (the fix did not turn the
 *     flag into a no-op).
 *   - A genuinely zero-state export is allowed but never reads as a clean
 *     success: loud stderr WARNING, a result warning, state_entry_count 0, and
 *     no minted re-key key.
 *   - A supplied-but-empty `stateNamespaces` array is rejected at the exporter
 *     boundary, so the ambiguous shape cannot be re-introduced by a future
 *     caller rather than merely being unused today.
 *
 * Test discipline: real FilesystemStorage, real Argon2id derivation, real
 * Ed25519 identity, real state writes through the L1 tools. No mocks. Each
 * test isolates its own tmp fortress and restores SANCTUARY_STORAGE_PATH.
 */
// fail-before-exempt: the "an uncurated underscore namespace is excluded"
// test below (RESERVED-NS-DIVERGE-01) asserts behavior that was already
// correct against origin/main - the exit-bundle exporter's namespace checks
// each OR'd a redundant underscore-prefix check before the consolidation, so
// an uncurated underscore namespace was already excluded pre-PR. It cannot
// fail against pre-fix source by construction. It exists to give the
// consolidated reserved-namespace predicate a wired-consumer test at this
// call site (AGENTS.md rule 4), not to catch a regression from a behavior
// change.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runExitCommand } from "../../src/exit/cli.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { exportExitBundle } from "../../src/exit/index.js";
import type { ExitEncryptedStateBundle } from "../../src/exit/bundle.js";

// ── Test scaffolding ─────────────────────────────────────────────────

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

const TEST_PASSPHRASE = "correct-horse-battery-staple-exit-discovery";

interface ToolLike {
  name: string;
  handler: (
    args: Record<string, unknown>,
  ) => Promise<{ content: Array<{ type: string; text: string }> }>;
}

async function callTool(
  tools: ToolLike[],
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

/**
 * A real on-disk fortress the exit CLI can reopen from its passphrase.
 *
 * Failure mode if this drifts: the CLI derives its master key from the
 * persisted `_meta/key-params`, so seeding state under a DIFFERENT key would
 * still produce namespace directories that discovery finds, and the export
 * would report entries the operator could never decrypt. Seed through the same
 * key the CLI will re-derive.
 */
async function bootstrapFortress(): Promise<{
  storagePath: string;
  identityId: string;
  tools: ToolLike[];
  /**
   * A reader over the SAME storage and master key the CLI will use, so a test
   * can query the audit chain the export actually wrote. Constructed fresh
   * rather than reusing the bootstrap instance so the read goes to disk.
   */
  readAuditOperations: () => Promise<string[]>;
}> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-exit-disc-"));
  const stateStoragePath = join(storagePath, "state");
  await mkdir(stateStoragePath, { recursive: true, mode: 0o700 });

  const storage = new FilesystemStorage(stateStoragePath);
  const { key: masterKey, params } = await deriveMasterKey(TEST_PASSPHRASE);
  await storage.write(
    "_meta",
    "key-params",
    stringToBytes(JSON.stringify(params)),
  );

  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog,
  );
  await identityManager.load();
  const created = await callTool(tools as ToolLike[], "identity_create", {
    label: "fortress-default",
  });
  await auditLog.flush();

  return {
    storagePath,
    identityId: created.identity_id as string,
    tools: tools as ToolLike[],
    readAuditOperations: async () => {
      const reader = new AuditLog(new FilesystemStorage(stateStoragePath), masterKey);
      const { entries } = await reader.query({ limit: 500 });
      return entries.map((entry) => entry.operation);
    },
  };
}

async function readEncryptedState(
  bundleDir: string,
): Promise<ExitEncryptedStateBundle> {
  const raw = await readFile(
    join(bundleDir, "artifacts", "encrypted_state.json"),
    "utf8",
  );
  return JSON.parse(raw) as ExitEncryptedStateBundle;
}

// ── Tests ───────────────────────────────────────────────────────────

describe("sanctuary exit export: state-namespace resolution", () => {
  let originalEnvStoragePath: string | undefined;
  const cleanup: string[] = [];

  beforeEach(() => {
    originalEnvStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  });

  afterEach(async () => {
    if (originalEnvStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalEnvStoragePath;
    }
    for (const path of cleanup.splice(0)) {
      await rm(path, { recursive: true, force: true });
    }
  });

  async function seededFortress(): Promise<
    Awaited<ReturnType<typeof bootstrapFortress>>
  > {
    const fortress = await bootstrapFortress();
    cleanup.push(fortress.storagePath);
    for (const [namespace, key] of [
      ["agent-memory", "handoff"],
      ["agent-memory", "preferences"],
      ["project-notes", "roadmap"],
    ] as const) {
      await callTool(fortress.tools, "state_write", {
        namespace,
        key,
        value: `${namespace}/${key} must survive exit`,
        identity_id: fortress.identityId,
      });
    }
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;
    return fortress;
  }

  it("exports EVERY discoverable namespace when no --state-namespace is passed", async () => {
    await seededFortress();
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-all-"));
    cleanup.push(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["export", "--out", bundleDir, "--yes"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);

    // The defect: omitting the flag exported nothing while still exiting 0.
    const state = await readEncryptedState(bundleDir);
    expect(state.total_keys).toBe(3);
    expect(state.namespaces).toEqual(["agent-memory", "project-notes"]);

    // The operator-visible half: the count is printed, a re-key key IS minted
    // (there is state to re-key), and no zero-state warning fires.
    expect(out.text).toContain("state_entries: 3");
    expect(out.text).toContain("BUNDLE RE-KEY KEY");
    expect(out.text).not.toContain("NO STATE EXPORTED");
    expect(err.text).not.toContain("NO STATE was exported");
  });

  it("still restricts the export to the namespaces --state-namespace names", async () => {
    await seededFortress();
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-one-"));
    cleanup.push(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "export",
        "--out",
        bundleDir,
        "--yes",
        "--state-namespace",
        "agent-memory",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    const state = await readEncryptedState(bundleDir);
    expect(state.total_keys).toBe(2);
    expect(state.namespaces).toEqual(["agent-memory"]);
    expect(out.text).toContain("state_entries: 2");
  });

  it("declares a zero-state export loudly instead of reporting a clean success", async () => {
    // A fresh fortress with no state is a LEGITIMATE export (identity, policy,
    // and audit receipts still travel), so this must not be a hard failure. It
    // must, however, be impossible to mistake for a successful state export.
    const fortress = await bootstrapFortress();
    cleanup.push(fortress.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-zero-"));
    cleanup.push(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["export", "--out", bundleDir, "--yes", "--json"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);

    const result = JSON.parse(out.text) as {
      state_entry_count: number;
      state_rekey_key?: string;
      warnings?: string[];
    };
    expect(result.state_entry_count).toBe(0);
    // Nothing to re-key, so no secret is handed to the operator.
    expect(result.state_rekey_key).toBeUndefined();
    expect(result.warnings ?? []).toContainEqual(
      expect.stringContaining("NO STATE EXPORTED"),
    );

    // On stderr so it survives `--json > bundle.json`, which is exactly how a
    // drill script captures the export.
    expect(err.text).toContain("WARNING: NO STATE was exported");
    expect(err.text).toContain("zero state entries");

    const state = await readEncryptedState(bundleDir);
    expect(state.total_keys).toBe(0);
  });

  it("records exit_bundle_export_no_state on the source fortress, and only when the export really was empty", async () => {
    // The audit marker is what an exit-drill operator queries after the fact,
    // so "the bundle was empty" is provable from the source fortress and not
    // only inferable from the bundle. Both directions are asserted: a marker
    // that fired unconditionally would carry no information, so presence alone
    // is not enough to call this tested.
    const empty = await bootstrapFortress();
    cleanup.push(empty.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = empty.storagePath;
    const emptyBundle = await mkdtemp(join(tmpdir(), "sanctuary-bundle-audit0-"));
    cleanup.push(emptyBundle);

    expect(
      await runExitCommand({
        argv: ["export", "--out", emptyBundle, "--yes"],
        out: new StringWritable(),
        err: new StringWritable(),
        env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
      }),
    ).toBe(0);

    const emptyOps = await empty.readAuditOperations();
    expect(emptyOps).toContain("exit_bundle_export_no_state");
    // The export itself was still audited; the marker is additive, not a
    // replacement for the normal export entry.
    expect(emptyOps).toContain("exit_bundle_export");

    // Same command against a fortress that HAS state must not claim emptiness.
    const seeded = await seededFortress();
    const seededBundle = await mkdtemp(join(tmpdir(), "sanctuary-bundle-audit3-"));
    cleanup.push(seededBundle);

    expect(
      await runExitCommand({
        argv: ["export", "--out", seededBundle, "--yes"],
        out: new StringWritable(),
        err: new StringWritable(),
        env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
      }),
    ).toBe(0);

    const seededOps = await seeded.readAuditOperations();
    expect(seededOps).toContain("exit_bundle_export");
    expect(seededOps).not.toContain("exit_bundle_export_no_state");
  });
});

describe("exportExitBundle: empty stateNamespaces is rejected, not honored", () => {
  it("throws rather than silently exporting zero state", async () => {
    // The by-construction guard: the CLI now omits the option, but any future
    // caller that forwards a flag parser's empty array must fail loudly rather
    // than re-introduce a silently-empty bundle.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
    );
    await identityManager.load();
    const { reputationStore } = createL4Tools(
      storage,
      masterKey,
      identityManager,
      auditLog,
    );
    await callTool(tools as ToolLike[], "identity_create", { label: "agent" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-empty-"));
    try {
      await expect(
        exportExitBundle({
          unpartitionedLegacyExport: true,
          bundleDir,
          storage,
          masterKey,
          identityManager,
          auditLog,
          reputationStore,
          policy: DEFAULT_POLICY,
          config: defaultConfig(),
          stateNamespaces: [],
          keySource: "recovery-key",
        }),
      ).rejects.toThrow(/stateNamespaces was supplied but empty/);
    } finally {
      await rm(bundleDir, { recursive: true, force: true });
    }
  });
});

describe("exportExitBundle: an uncurated underscore namespace is excluded even when explicitly named", () => {
  it("skips a namespace only isReservedNamespace's blanket rule catches, not the curated list", async () => {
    // RESERVED-NS-DIVERGE-01 wired-consumer coverage: consolidating
    // exportEncryptedState's four call sites onto the shared
    // `isReservedNamespace` predicate stripped their own inline
    // `namespace.startsWith("_")` check, and no existing exit-bundle suite
    // ever named a namespace outside `RESERVED_NAMESPACE_PREFIXES` here - an
    // independent gate on this PR found all 25 pre-existing exit-bundle tests
    // stayed green when `isReservedNamespace` was narrowed back to
    // curated-list-only membership. This is that witness: an underscore
    // namespace the curated list has never heard of must still be excluded
    // from the export.
    //
    // Discovery (no --state-namespace) already filters `_`-prefixed
    // directories before they reach exportEncryptedState (see
    // `discoverFilesystemStateNamespaces`), so the only way to reach the
    // in-loop `isReservedNamespace` check with such a namespace is to name it
    // explicitly, the same way `--state-namespace` lets an operator do.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
    );
    await identityManager.load();
    const { reputationStore } = createL4Tools(
      storage,
      masterKey,
      identityManager,
      auditLog,
    );
    const created = await callTool(tools as ToolLike[], "identity_create", {
      label: "agent",
    });

    // Written directly to storage: `state_write` already refuses every
    // underscore-prefixed namespace at the tools-layer firewall this same
    // predicate guards, so an uncurated `_`-namespace can only exist on disk
    // from an internal subsystem or a pre-curation fortress, never from an
    // agent-facing write. That is exactly the case the export-time check
    // defends against.
    // A bare unquoted string is not valid JSON, and exportEncryptedState
    // silently drops anything that fails `JSON.parse` (corrupt state is
    // omitted, never trusted into the exit bundle) - so the entry must
    // parse successfully or this test would pass for the wrong reason (a
    // parse failure) regardless of the reserved-namespace check.
    await storage.write(
      "_uncurated_internal",
      "secret",
      stringToBytes(JSON.stringify({ payload: "must never leave the fortress" })),
    );
    await callTool(tools as ToolLike[], "state_write", {
      namespace: "agent-memory",
      key: "note",
      value: "ordinary state",
      identity_id: created.identity_id as string,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-reserved-"));
    try {
      const result = await exportExitBundle({
        unpartitionedLegacyExport: true,
        bundleDir,
        storage,
        masterKey,
        identityManager,
        auditLog,
        reputationStore,
        policy: DEFAULT_POLICY,
        config: defaultConfig(),
        stateNamespaces: ["_uncurated_internal", "agent-memory"],
        keySource: "recovery-key",
      });

      expect(result.state_entry_count).toBe(1);
      const state = await readEncryptedState(bundleDir);
      expect(state.namespaces).toEqual(["agent-memory"]);
      expect(
        state.entries.some((entry) => entry.namespace === "_uncurated_internal"),
      ).toBe(false);
    } finally {
      await rm(bundleDir, { recursive: true, force: true });
    }
  });
});
