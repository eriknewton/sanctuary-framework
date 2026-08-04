/**
 * Memory Checkpoint tests.
 *
 * Proves local checkpoint creation, encryption, retention, auditing, atomic
 * cleanup, and the no-network/no-federation import boundary.
 */

import { readdirSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, afterEach } from "vitest";

import { StateStore } from "../../src/cognitive/state-store.js";
import { bytesToString, fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hashToString } from "../../src/core/hashing.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  CHECKPOINT_INTERVAL_ENV,
  MemoryCheckpointStore,
  buildMemoryCheckpointId,
  computeRetentionExpiresAt,
  createCheckpoint,
  nodeMemoryCheckpointFsOps,
  parseCheckpointInterval,
  parseRetention,
  pruneExpired,
  pruneExpiredCheckpoints,
  startMemoryCheckpointSchedulerFromEnv,
  type MemoryCheckpointRecord,
} from "../../src/memory-checkpoint/index.js";

type AuditAppend = Pick<AuditLog, "append">["append"];
type AuditCall = Parameters<AuditAppend>;

interface Fixture {
  fortressPath: string;
  storage: MemoryStorage;
  stateStore: StateStore;
  checkpointStore: MemoryCheckpointStore;
  masterKey: Uint8Array;
  identity: ReturnType<typeof createIdentity>;
  identityEncKey: Uint8Array;
}

const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function makeTempFortress(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-memory-checkpoint-"));
  tempDirs.push(dir);
  return dir;
}

async function makeFixture(now = "2026-08-03T10:00:00.000Z"): Promise<Fixture> {
  const fortressPath = await makeTempFortress();
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity = createIdentity("checkpoint-test", identityEncKey, "recovery-key");
  const checkpointStore = new MemoryCheckpointStore({
    fortressPath,
    clock: { now: () => new Date(now) },
  });
  return {
    fortressPath,
    storage,
    stateStore,
    checkpointStore,
    masterKey,
    identity,
    identityEncKey,
  };
}

async function writeEntry(
  fixture: Fixture,
  namespace: string,
  key: string,
  value: string,
): Promise<void> {
  await fixture.stateStore.write(
    namespace,
    key,
    value,
    fixture.identity.storedIdentity.identity_id,
    fixture.identity.storedIdentity.encrypted_private_key,
    fixture.identityEncKey,
  );
}

function makeAuditLog(): { auditLog: Pick<AuditLog, "append">; calls: AuditCall[] } {
  const calls: AuditCall[] = [];
  return {
    calls,
    auditLog: {
      append: async (...args: AuditCall): Promise<void> => {
        calls.push(args);
      },
    },
  };
}

function makeRecord(
  createdAt: string,
  bundle: string,
  overrides: Partial<MemoryCheckpointRecord> = {},
): MemoryCheckpointRecord {
  const bundleHash = hashToString(stringToBytes(bundle));
  const namespaces = overrides.namespaces ?? ["mem"];
  const perNamespace =
    overrides.completeness_summary?.per_namespace ??
    Object.fromEntries(
      namespaces.map((namespace) => [
        namespace,
        { content_sha256: hashToString(stringToBytes(namespace)), item_count: 1 },
      ]),
    );
  return {
    id: buildMemoryCheckpointId(createdAt, bundleHash),
    created_at: createdAt,
    source: overrides.source ?? "on_demand",
    namespaces,
    total_keys: overrides.total_keys ?? namespaces.length,
    bundle_hash: bundleHash,
    completeness_summary: {
      namespace_count:
        overrides.completeness_summary?.namespace_count ?? namespaces.length,
      total_keys: overrides.completeness_summary?.total_keys ?? namespaces.length,
      per_namespace: perNamespace,
    },
    retention_expires_at:
      overrides.retention_expires_at === undefined
        ? "2026-09-02T10:00:00.000Z"
        : overrides.retention_expires_at,
    format_version: 1,
  };
}

describe("memory checkpoint creation", () => {
  it("captures exportable namespaces and excludes every underscore-prefixed namespace", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "a", "remember-alpha");
    await writeEntry(fixture, "plans", "b", "plan-bravo");
    await writeEntry(fixture, "_audit", "internal-audit", "reserved-audit");
    await writeEntry(fixture, "_identities", "internal-id", "reserved-identity");
    const { auditLog } = makeAuditLog();

    const record = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      source: "on_demand",
      retentionValue: "off",
    });

    expect(record.namespaces).toEqual(["mem", "plans"]);
    expect(Object.keys(record.completeness_summary.per_namespace)).toEqual([
      "mem",
      "plans",
    ]);
    expect(record.namespaces.some((namespace) => namespace.startsWith("_"))).toBe(false);

    const bundle = await fixture.checkpointStore.readBundle(
      record.id,
      fixture.masterKey,
    );
    const decoded = JSON.parse(bytesToString(fromBase64url(bundle))) as {
      namespaces: string[];
      data: Record<string, unknown>;
    };
    expect(decoded.namespaces).toEqual(["mem", "plans"]);
    expect(Object.keys(decoded.data).some((namespace) => namespace.startsWith("_"))).toBe(false);
  });

  it("encrypts bundle.enc at rest and readBundle round-trips the bundle string", async () => {
    const fixture = await makeFixture();
    const knownPlaintext = "known checkpoint plaintext value";
    const createdAt = "2026-08-03T11:00:00.000Z";
    const record = makeRecord(createdAt, knownPlaintext, {
      retention_expires_at: null,
    });

    await fixture.checkpointStore.create({
      record,
      bundle: knownPlaintext,
      masterKey: fixture.masterKey,
    });

    const encryptedBytes = await readFile(
      join(fixture.fortressPath, "checkpoints", record.id, "bundle.enc"),
    );
    expect(Buffer.from(encryptedBytes).includes(knownPlaintext)).toBe(false);
    await expect(
      fixture.checkpointStore.readBundle(record.id, fixture.masterKey),
    ).resolves.toBe(knownPlaintext);
  });
});

describe("memory checkpoint scheduler and retention", () => {
  it("throws on invalid interval values and does not start when interval is off", () => {
    expect(() => parseCheckpointInterval("foo")).toThrow(/invalid/);

    let started = false;
    const handle = startMemoryCheckpointSchedulerFromEnv({
      env: { [CHECKPOINT_INTERVAL_ENV]: "off" } as NodeJS.ProcessEnv,
      stateStore: {} as never,
      store: {} as never,
      masterKey: new Uint8Array(32),
      auditLog: { append: async () => undefined },
      identityId: "operator",
      onError: () => undefined,
      setIntervalFn: (() => {
        started = true;
        return { unref: () => undefined } as NodeJS.Timeout;
      }) as typeof setInterval,
    });

    expect(handle).toBeNull();
    expect(started).toBe(false);
  });

  it("atomic create removes the temp directory after a mid-create write failure", async () => {
    const fixture = await makeFixture();
    const bundle = "bundle that fails after encryption";
    const record = makeRecord("2026-08-03T12:00:00.000Z", bundle);
    let writes = 0;
    const fsOps = {
      ...nodeMemoryCheckpointFsOps,
      writeFile: async (
        path: string,
        data: string | Uint8Array,
        options: { mode?: number },
      ): Promise<void> => {
        writes++;
        if (writes === 2) throw new Error("injected write failure");
        await nodeMemoryCheckpointFsOps.writeFile(path, data, options);
      },
    };
    const failingStore = new MemoryCheckpointStore({
      fortressPath: fixture.fortressPath,
      fsOps,
    });

    await expect(
      failingStore.create({
        record,
        bundle,
        masterKey: fixture.masterKey,
      }),
    ).rejects.toMatchObject({ reason: "write_failed" });

    const checkpointEntries = await readdir(
      join(fixture.fortressPath, "checkpoints"),
    ).catch((err: unknown) => {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return [] as string[];
      }
      throw err;
    });
    expect(checkpointEntries).toEqual([]);
  });

  it("prunes only expired records and never prunes retention-off records", async () => {
    const fixture = await makeFixture();
    const expired = makeRecord("2026-08-01T00:00:00.000Z", "expired", {
      retention_expires_at: "2026-08-02T00:00:00.000Z",
    });
    const future = makeRecord("2026-08-02T00:00:00.000Z", "future", {
      retention_expires_at: "2026-08-04T00:00:00.000Z",
    });
    const noExpiry = makeRecord("2026-08-02T01:00:00.000Z", "no-expiry", {
      retention_expires_at: computeRetentionExpiresAt(
        "2026-08-02T01:00:00.000Z",
        parseRetention("off"),
      ),
    });
    const forensic = makeRecord("2026-08-02T02:00:00.000Z", "forensic", {
      source: "forensic_quarantine",
      retention_expires_at: "2026-08-02T03:00:00.000Z",
    });
    for (const [record, bundle] of [
      [expired, "expired"],
      [future, "future"],
      [noExpiry, "no-expiry"],
      [forensic, "forensic"],
    ] as const) {
      await fixture.checkpointStore.create({
        record,
        bundle,
        masterKey: fixture.masterKey,
      });
    }

    const pruned = await pruneExpired(
      fixture.checkpointStore,
      new Date("2026-08-03T00:00:00.000Z"),
    );

    expect(pruned).toEqual([expired.id]);
    const remaining = (await fixture.checkpointStore.list()).map((record) => record.id).sort();
    expect(remaining).toEqual([future.id, noExpiry.id, forensic.id].sort());
  });

  it("emits exact audit op strings on create and prune", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "a", "audit-me");
    const audit = makeAuditLog();
    const identityId = fixture.identity.storedIdentity.identity_id;

    const created = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: audit.auditLog,
      identityId,
      source: "on_demand",
      retentionValue: "off",
    });

    expect(audit.calls[0]).toEqual([
      "l1",
      "memory_checkpoint_created",
      identityId,
      {
        id: created.id,
        namespaces: created.namespaces,
        total_keys: created.total_keys,
        bundle_hash: created.bundle_hash,
        source: "on_demand",
      },
    ]);

    const expired = makeRecord("2026-08-01T00:00:00.000Z", "prune-me", {
      retention_expires_at: "2026-08-02T00:00:00.000Z",
    });
    await fixture.checkpointStore.create({
      record: expired,
      bundle: "prune-me",
      masterKey: fixture.masterKey,
    });

    const prunedIds = await pruneExpiredCheckpoints({
      store: fixture.checkpointStore,
      auditLog: audit.auditLog,
      identityId,
      now: new Date("2026-08-03T00:00:00.000Z"),
    });

    expect(prunedIds).toEqual([expired.id]);
    expect(audit.calls.at(-1)).toEqual([
      "l1",
      "memory_checkpoint_pruned",
      identityId,
      { pruned_ids: [expired.id], reason: "retention_expired" },
    ]);
  });
});

describe("memory checkpoint import boundary", () => {
  it("does not import network, federation, or mesh modules", () => {
    const here = fileURLToPath(import.meta.url);
    const serverDir = resolve(here, "..", "..", "..");
    const srcDir = join(serverDir, "src", "memory-checkpoint");
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile() && entry.name.endsWith(".ts")) files.push(full);
      }
    };
    walk(srcDir);

    const specifiers: Array<{ file: string; spec: string }> = [];
    const fromRe = /\b(?:import|export)\b[^;]*?\bfrom\s*["'`]([^"'`]+)["'`]/g;
    const bareRe = /\bimport\s*["'`]([^"'`]+)["'`]/g;
    const dynamicRe = /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g;
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const re of [fromRe, bareRe, dynamicRe]) {
        re.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = re.exec(source)) !== null) {
          specifiers.push({
            file: relative(srcDir, file),
            spec: match[1]!,
          });
        }
      }
    }
    const banned = specifiers.filter(({ spec }) =>
      /(^|[/.-])(network|federation|mesh)([/.-]|$)/i.test(spec),
    );

    expect(banned).toEqual([]);
  });
});
