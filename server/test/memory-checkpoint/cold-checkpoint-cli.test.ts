/**
 * Checkpoint commands capture durable state across restarts.
 * LEGACY-BUG-001
 * CHECKPOINT-RESTORE-COLD-VERSION-FLOOR-01
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runCheckpointCommand } from "../../src/cli/checkpoint.js";
import { StateStore, STATE_ENVELOPE_VERSION_ANCHORS_KEY } from "../../src/cognitive/state-store.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createIdentity, rotateKeys, sign } from "../../src/core/identity.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, fromBase64url, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { hashToString } from "../../src/core/hashing.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryCheckpointStore, buildMemoryCheckpointId } from "../../src/memory-checkpoint/index.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

// Only host custody and host liveness are replaced; CLI composition, encrypted
// filesystem state, namespace discovery, snapshotting are real.
vi.mock("../../src/core/master-custody.js", async (original) => ({
  ...await original<typeof import("../../src/core/master-custody.js")>(),
  resolveCliMasterKey: vi.fn(),
}));
vi.mock("../../src/egress-gate/parked-claim.js", async (original) => ({
  ...await original<typeof import("../../src/egress-gate/parked-claim.js")>(),
  assessHarnessParked: vi.fn(),
}));
vi.mock("../../src/egress-gate/harness-daemon.js", async (original) => ({
  ...await original<typeof import("../../src/egress-gate/harness-daemon.js")>(),
  AGENT_HARNESS_DAEMON_PLIST_PATH: "/nonexistent-cold-checkpoint-test/harness.plist",
}));

// Must match CHECKPOINT_RESTORE_VERSION_FLOOR_REFUSAL in memory-checkpoint/restore.ts.
const refusal = "memory checkpoint restore refused: checkpoint versions cannot be safely restored (CHECKPOINT-RESTORE-COLD-VERSION-FLOOR-01). State is unchanged.";
const HMAC_SHA256_BYTE_LENGTH = 32;
const tempDirs: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const path of tempDirs.splice(0)) await rm(path, { recursive: true, force: true });
});

function capture() {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += chunk.toString(); done(); } });
  return { stream, text: () => text };
}

async function fixture() {
  const path = await mkdtemp(join(tmpdir(), "cold-checkpoint-"));
  tempDirs.push(path);
  vi.stubEnv("SANCTUARY_STORAGE_PATH", path);
  const masterKey = generateRandomKey();
  vi.mocked(resolveCliMasterKey).mockResolvedValue(masterKey);
  const storage = new FilesystemStorage(join(path, "state"));
  const stateStore = new StateStore(storage, masterKey);
  const encKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity: identity } = createIdentity("checkpoint", encKey, "recovery-key");
  await persistStoredIdentity(storage, masterKey, identity);
  const write = (ns: string, value: string, key = "note") => stateStore.write(
    ns, key, value, identity.identity_id, identity.encrypted_private_key, encKey,
  );
  await write("alpha", "original");
  await write("beta", "original");
  const checkpoints = new MemoryCheckpointStore({ fortressPath: path });
  const call = async (argv: string[]) => {
    const out = capture();
    const err = capture();
    const code = await runCheckpointCommand({
      argv: [...argv, "--fortress", path], out: out.stream, err: err.stream,
      env: { SANCTUARY_PASSPHRASE: "isolated-test-custody" },
    });
    expect(code, err.text()).toBe(0);
    return out.text();
  };
  return { path, storage, stateStore, masterKey, identity, write, checkpoints, call };
}


async function durableBytes(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function walk(path: string, relative: string) {
    for (const item of await readdir(path, { withFileTypes: true })) {
      const name = join(relative, item.name);
      if (item.isDirectory()) await walk(join(path, item.name), name);
      else result[name] = (await readFile(join(path, item.name))).toString("hex");
    }
  }
  await walk(root, "");
  return result;
}

function withoutAuditAndPolicy(bytes: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(bytes).filter(([path]) =>
      path !== "principal-policy.yaml" &&
      !path.startsWith("state/_audit/") &&
      !path.startsWith("state/_audit_checkpoints/")
    ),
  );
}

function decodeBundle(bundle: string): Record<string, unknown> {
  return JSON.parse(bytesToString(fromBase64url(bundle))) as Record<string, unknown>;
}

function encodeBundle(bundle: Record<string, unknown>): string {
  return toBase64url(stringToBytes(JSON.stringify(bundle)));
}

function stripCompleteness(bundle: string): string {
  const decoded = decodeBundle(bundle);
  delete decoded.completeness_manifest;
  delete decoded.bundle_integrity;
  return encodeBundle(decoded);
}

function replaceBundleIntegrityMac(bundle: string): string {
  const decoded = decodeBundle(bundle);
  const integrity = decoded.bundle_integrity;
  if (!integrity || typeof integrity !== "object" || Array.isArray(integrity)) {
    throw new Error("missing bundle integrity");
  }
  (integrity as Record<string, unknown>).mac = toBase64url(
    new Uint8Array(HMAC_SHA256_BYTE_LENGTH),
  );
  return encodeBundle(decoded);
}

async function createCheckpointFromBundle(
  f: Awaited<ReturnType<typeof fixture>>,
  bundle: string,
  createdAt: string,
): Promise<string> {
  const decoded = decodeBundle(bundle);
  const data = decoded.data as Record<string, Array<{ key: string }>>;
  const namespaces = Array.isArray(decoded.namespaces)
    ? decoded.namespaces.filter((item): item is string => typeof item === "string")
    : Object.keys(data);
  const bundleHash = hashToString(fromBase64url(bundle));
  const id = buildMemoryCheckpointId(createdAt, bundleHash);
  const perNamespace: Record<string, { item_count: number; content_sha256: string }> = {};
  let totalKeys = 0;
  for (const namespace of namespaces) {
    const entries = Array.isArray(data[namespace]) ? data[namespace] : [];
    perNamespace[namespace] = {
      item_count: entries.length,
      content_sha256: hashToString(stringToBytes(JSON.stringify(entries))),
    };
    totalKeys += entries.length;
  }
  await f.checkpoints.create({
    record: {
      id,
      created_at: createdAt,
      source: "on_demand",
      namespaces,
      total_keys: totalKeys,
      bundle_hash: bundleHash,
      completeness_summary: {
        namespace_count: namespaces.length,
        total_keys: totalKeys,
        per_namespace: perNamespace,
      },
      retention_expires_at: null,
      format_version: 1,
    },
    bundle,
    masterKey: f.masterKey,
  });
  return id;
}

async function coldRestore(f: Awaited<ReturnType<typeof fixture>>, id: string) {
  const child = fileURLToPath(new URL("./fixtures/cold-restore-cli.mjs", import.meta.url));
  const args = ["--import", "tsx", "--experimental-test-module-mocks", child,
    "restore", id, "--fortress", f.path];
  try {
    const output = await promisify(execFile)(process.execPath, args, {
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
      env: { ...process.env, SANCTUARY_STORAGE_PATH: f.path,
        SANCTUARY_PASSPHRASE: "isolated-test-custody",
        CHECKPOINT_TEST_MASTER_KEY: Buffer.from(f.masterKey).toString("hex") },
      timeout: 20_000, // Bound child lifetime below Vitest's 30-second test timeout.
    });
    return { code: 0, ...output };
  } catch (error) {
    const failure = error as Error & { code: number; stdout: string; stderr: string };
    return { code: failure.code, stdout: failure.stdout, stderr: failure.stderr };
  }
}

describe("cold checkpoint CLI", () => {
  it("creates a complete checkpoint from a newly bootstrapped store", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const records = await f.checkpoints.list();
    expect(records).toHaveLength(1);
    expect(records[0]!.namespaces).toEqual(["alpha", "beta"]);
    expect(records[0]!.total_keys).toBe(2);
    const raw = await f.checkpoints.readBundle(records[0]!.id, f.masterKey);
    expect(Object.keys(JSON.parse(bytesToString(fromBase64url(raw))).data).sort()).toEqual(["alpha", "beta"]);
  });

  it("writes a critical failure audit for a tampered checkpoint in the cold CLI", async () => {
    const f = await fixture();
    const createdAt = "2026-10-02T12:00:00.000Z";
    const declaredBundle = toBase64url(stringToBytes(JSON.stringify({ namespaces: [], data: {} })));
    const declaredHash = hashToString(fromBase64url(declaredBundle));
    const tamperedBundle = toBase64url(stringToBytes(JSON.stringify({ namespaces: ["alpha"], data: { alpha: [] } })));
    const id = buildMemoryCheckpointId(createdAt, declaredHash);
    await f.checkpoints.create({
      record: {
        id, created_at: createdAt, source: "on_demand", namespaces: [], total_keys: 0,
        bundle_hash: declaredHash,
        completeness_summary: { namespace_count: 0, total_keys: 0, per_namespace: {} },
        retention_expires_at: null, format_version: 1,
      },
      bundle: tamperedBundle,
      masterKey: f.masterKey,
    });
    const result = await coldRestore(f, id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain("does not match the recorded bundle_hash");
    const audit = new AuditLog(f.storage, f.masterKey);
    const { entries } = await audit.query({ operation_type: "memory_checkpoint_restore" });
    expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({
      result: "failure",
      details: expect.objectContaining({ checkpoint_id: id, error_reason: "bundle_hash_mismatch" }),
    })]));
    expect((await f.checkpoints.list()).map((record) => record.id)).toEqual([id]);
  });

  it("refuses a cold restore below a durable anchor without changing any durable bytes", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    // Keep alpha eligible, then advance beta: preflight must cover the whole bundle.
    await f.write("beta", "advanced");
    await f.write("alpha", "added key", "post-checkpoint");
    await f.write("gamma", "added namespace");
    const before = await durableBytes(f.path);
    const result = await coldRestore(f, checkpoint!.id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain(`Error: checkpoint restore failed. ${refusal}\n`);
    expect(result.stdout).not.toContain("Checkpoint restored:");
    expect(await durableBytes(f.path)).toEqual(before);
  });

  it("restores checkpoint entries signed before an identity rotation", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    const identityEncKey = derivePurposeKey(f.masterKey, "identity-encryption");
    const { updatedIdentity } = rotateKeys(
      f.identity,
      identityEncKey,
      "cold checkpoint restore rotation-chain test",
    );
    await persistStoredIdentity(f.storage, f.masterKey, updatedIdentity);
    await f.stateStore.delete("alpha", "note");
    await f.stateStore.write(
      "gamma",
      "note",
      "post-rotation-added",
      updatedIdentity.identity_id,
      updatedIdentity.encrypted_private_key,
      identityEncKey,
    );

    const result = await coldRestore(f, checkpoint!.id);

    expect(result.code, JSON.stringify(result)).toBe(0);
    expect(result.stdout).toContain(`Checkpoint restored: ${checkpoint!.id}\n`);
    await expect(f.stateStore.read("alpha", "note")).resolves.toMatchObject({
      value: "original",
    });
    await expect(f.stateStore.read("beta", "note")).resolves.toMatchObject({
      value: "original",
    });
    expect(await f.storage.read("gamma", "note")).toBeNull();
  });

  it("refuses a cold restore when the local rotation chain is not verified", async () => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    const identityEncKey = derivePurposeKey(f.masterKey, "identity-encryption");
    const { updatedIdentity } = rotateKeys(
      f.identity,
      identityEncKey,
      "cold checkpoint restore broken-chain test",
    );
    const [firstHop] = updatedIdentity.rotation_history;
    if (!firstHop) throw new Error("missing rotation hop");
    await persistStoredIdentity(f.storage, f.masterKey, {
      ...updatedIdentity,
      rotation_history: [
        {
          ...firstHop,
          rotation_event: toBase64url(stringToBytes("{}")),
        },
      ],
    });
    await f.stateStore.delete("alpha", "note");
    await f.write("gamma", "post-checkpoint");
    const before = withoutAuditAndPolicy(await durableBytes(f.path));

    const result = await coldRestore(f, checkpoint!.id);

    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain(
      "2 checkpoint entries are signed by an identity this fortress does not hold and 0 checkpoint entries do not verify",
    );
    expect(result.stderr).not.toContain(
      "0 checkpoint entries are signed by an identity this fortress does not hold and 2 checkpoint entries do not verify",
    );
    expect(result.stdout).not.toContain("Checkpoint restored:");
    expect(withoutAuditAndPolicy(await durableBytes(f.path))).toEqual(before);
  });

  it.each(["read failure", "invalid MAC"])("refuses a cold restore on anchor %s without changing durable bytes", async (failure) => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    const raw = await f.storage.read("_meta", STATE_ENVELOPE_VERSION_ANCHORS_KEY);
    expect(raw).not.toBeNull();
    // A malformed durable record exercises the real parser's read failure;
    // a valid envelope with changed data exercises MAC authentication.
    const record = JSON.parse(bytesToString(raw!));
    record.data["untrusted"] = 1;
    await f.storage.write("_meta", STATE_ENVELOPE_VERSION_ANCHORS_KEY,
      Buffer.from(failure === "read failure" ? "{" : JSON.stringify(record)));
    const before = await durableBytes(f.path);
    const result = await coldRestore(f, checkpoint!.id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    if (failure === "read failure") {
      expect(result.stderr).toContain("State metadata record is corrupted");
    } else {
      expect(result.stderr).toContain("Version-anchor record failed authentication");
    }
    expect(withoutAuditAndPolicy(await durableBytes(f.path))).toEqual(
      withoutAuditAndPolicy(before),
    );
    const audit = new AuditLog(f.storage, f.masterKey);
    const { entries } = await audit.query({ operation_type: "memory_checkpoint_restore" });
    expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({
      result: "failure",
      details: expect.objectContaining({
        checkpoint_id: checkpoint!.id,
        error_reason: failure === "read failure" ? "schema_mismatch" : "integrity_hash_mismatch",
      }),
    })]));
  });

  it.each([
    {
      name: "missing completeness",
      mutate: stripCompleteness,
      reason: "integrity_hash_mismatch",
      message: "allow_unverified_legacy",
      createdAt: "2026-10-02T12:01:00.000Z",
    },
    {
      name: "bundle integrity MAC",
      mutate: replaceBundleIntegrityMac,
      reason: "integrity_hash_mismatch",
      message: "integrity",
      createdAt: "2026-10-02T12:02:00.000Z",
    },
  ])("writes a critical failure audit for a cold restore with $name", async ({ mutate, reason, message, createdAt }) => {
    const f = await fixture();
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    const bundle = await f.checkpoints.readBundle(checkpoint!.id, f.masterKey);
    const id = await createCheckpointFromBundle(f, mutate(bundle), createdAt);
    const result = await coldRestore(f, id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain(message);
    expect(result.stderr).not.toContain(refusal);
    const audit = new AuditLog(f.storage, f.masterKey);
    const { entries } = await audit.query({ operation_type: "memory_checkpoint_restore" });
    expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({
      result: "failure",
      details: expect.objectContaining({ checkpoint_id: id, error_reason: reason }),
    })]));
  });

  it("writes a critical failure audit for a cold restore with a legacy ceiling refusal", async () => {
    const f = await fixture();
    const namespace = "legacy";
    const key = "above-anchor";
    const plaintext = stringToBytes("legacy value");
    const payload = encrypt(plaintext, deriveNamespaceKey(f.masterKey, namespace));
    await f.storage.write(namespace, key, stringToBytes(JSON.stringify({
      v: 1,
      payload,
      ver: 2,
      sig: toBase64url(sign(
        fromBase64url(payload.ct),
        f.identity.encrypted_private_key,
        derivePurposeKey(f.masterKey, "identity-encryption"),
      )),
      kid: f.identity.identity_id,
      integrity_hash: hashToString(plaintext),
      metadata: { written_at: "2026-10-02T12:00:00.000Z" },
    })));
    await f.call(["create"]);
    const [checkpoint] = await f.checkpoints.list();
    await f.stateStore.delete(namespace, key);
    await f.write(namespace, "recreated", key);
    const result = await coldRestore(f, checkpoint!.id);
    expect(result.code, JSON.stringify(result)).toBe(1);
    expect(result.stderr).toContain("legacy (v1)");
    expect(result.stderr).not.toContain(refusal);
    const audit = new AuditLog(f.storage, f.masterKey);
    const { entries } = await audit.query({ operation_type: "memory_checkpoint_restore" });
    expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({
      result: "failure",
      details: expect.objectContaining({
        checkpoint_id: checkpoint!.id,
        error_reason: "rollback_detected",
      }),
    })]));
  });

});
