/**
 * `sanctuary file-grant revoke` CLI: the operator's revoke always gets a
 * verdict (R3-3; extended under FG-RECONCILE-SIBLINGS-01).
 *
 * CAPABILITIES ASSERTED HERE, end to end against a real keychain-free fortress.
 *
 *   1. `revokeFileGrant` propagates a tree-scrub failure by design (see its own
 *      doc comment: the record is marked revoked BEFORE the scrub is attempted,
 *      so the caller must learn the tree entry may still be present). The CLI
 *      turns that into a clean operator-facing line and a non-zero exit code,
 *      never a raw stack trace, matching the pattern `cmdMint` already uses.
 *
 *   2. The reconcile pass that runs before the revoke gets its OWN handler, and
 *      a failure there does not cancel the revoke. A reconcile failure concerns
 *      some OTHER grant, and a revoke is the operator's explicit,
 *      access-reducing instruction; it must not be withheld because an
 *      unrelated grant could not be converged. The operator gets a notice about
 *      the reconcile AND the revoke's own verdict.
 *
 *   3. Mint is the opposite call: it is the one file-grant touch that EXPANDS
 *      access, so a reconcile failure refuses it rather than proceeding.
 *
 * The fixtures seed a real fortress and identity, write grant records directly
 * (the interactive Tier-1 mint approval auto-denies in a non-interactive test
 * process), and force a scrub failure with a genuine ENOTDIR, the same real
 * error class `test/file-grant/fs-ops.test.ts` uses, rather than an ENOENT that
 * the idempotent scrub treats as a no-op.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runFileGrantCommand } from "../../src/cli/file-grant.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { FileGrantStore } from "../../src/file-grant/store.js";
import { FILE_GRANT_SCHEMA_VERSION, type FileGrant } from "../../src/file-grant/types.js";
import {
  runInit as runInitRaw,
  type InitOptions,
} from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

// ── Keychain-free fortress seeding (mirrors test/cli/identity-create.test.ts) ──

type ExecCall = { cmd: string; args: string[]; input?: string };

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`)
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}

function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (account: string, service: string): string =>
    `${account}:${service}`;

  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      const account = readSecurityToken(input, "-a");
      const service = readSecurityToken(input, "-s");
      const value = readSecurityToken(input, "-w");
      stored.set(keyFor(account, service), value);
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };

  return { exec };
}

async function runInit(
  options: InitOptions
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}

function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}

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

describe("sanctuary file-grant revoke: clean error on a scrub failure (R3-3)", () => {
  let tmp: string;
  let fortressPath: string;
  let recoveryKey: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-revoke-test-"));
    fortressPath = join(tmp, "fortress");
    const { readFile } = await import("node:fs/promises");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });
    const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
    recoveryKey = extractRecoveryKey(recoveryFile);
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  it("resolves with a non-zero exit and a clean message instead of throwing", async () => {
    // Seed a primary identity directly against the fortress on-disk storage
    // (same construction `bootstrap()` in cli/file-grant.ts uses), so we can
    // also build a matching FileGrantStore write identity without going
    // through the interactive Tier-1 mint approval prompt (which auto-denies
    // in this non-interactive test process).
    const stateStoragePath = join(fortressPath, "state");
    const storage = new FilesystemStorage(stateStoragePath);
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const { createIdentity } = await import("../../src/core/identity.js");
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity("operator", identityEncKey, "recovery-key");
    await identityManager.save(storedIdentity);
    // `save()` fires-and-forgets the primary-pointer persist; await it
    // explicitly (setPrimary awaits the same write) so a FRESH
    // IdentityManager (the one `bootstrap()` constructs inside
    // `runFileGrantCommand` below) is guaranteed to see this identity as
    // primary rather than racing an un-awaited background write.
    await identityManager.setPrimary(storedIdentity.identity_id);

    const stateStore = new StateStore(storage, masterKey);
    const grantStore = new FileGrantStore(stateStore, {
      identityId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      identityEncryptionKey: identityEncKey,
    });

    // Seed an ACTIVE grant whose tree_entry points under an "agent-1"
    // directory we deliberately replace with a plain FILE, so the real
    // PosixFileGrantFsOps.removeEntry's lstat() fails with ENOTDIR (a
    // genuine filesystem error, not ENOENT) when revoke tries to scrub it.
    const grantId = "fg_revoke_err01";
    const grant: FileGrant = {
      grant_id: grantId,
      schema_version: FILE_GRANT_SCHEMA_VERSION,
      subject_agent_id: "agent-1",
      scope: { kind: "file", path: "/tmp/does-not-matter.txt" },
      mode: "read",
      created_by: storedIdentity.identity_id,
      created_at: new Date().toISOString(),
      expires_at: null,
      status: "active",
      revoked_at: null,
      tree_entry: `agent-1/${grantId}`,
      audit_refs: [],
    };
    await grantStore.put(grant);

    const grantsRoot = join(fortressPath, "grants");
    await mkdir(grantsRoot, { recursive: true, mode: 0o711 });
    // A FILE where the per-agent subdirectory must be a directory.
    await writeFile(join(grantsRoot, "agent-1"), "not a directory");

    const out = new StringWritable();
    const err = new StringWritable();

    // Must resolve (never reject) with a non-zero code and a clean message.
    const code = await runFileGrantCommand({
      argv: ["revoke", "--grant", grantId, "--fortress", fortressPath],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });

    expect(code).toBe(1);
    expect(err.text).toContain("Error: revoke did not complete cleanly.");
    // No raw Node stack-trace leakage (a thrown, unhandled error's message
    // would otherwise include the bare ENOTDIR errno text with no operator
    // framing at all).
    expect(err.text).not.toContain("at process.processTicksAndRejections");
  });

  it("a reconcile-time scrub error on an UNRELATED expired grant does not cancel the revoke (FG-RECONCILE-SIBLINGS-01)", async () => {
    // Same fortress/identity seeding as the previous test.
    const stateStoragePath = join(fortressPath, "state");
    const storage = new FilesystemStorage(stateStoragePath);
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const { createIdentity } = await import("../../src/core/identity.js");
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity("operator", identityEncKey, "recovery-key");
    await identityManager.save(storedIdentity);
    await identityManager.setPrimary(storedIdentity.identity_id);

    const stateStore = new StateStore(storage, masterKey);
    const grantStore = new FileGrantStore(stateStore, {
      identityId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      identityEncryptionKey: identityEncKey,
    });

    // Grant A: EXPIRED (active status, but expires_at already in the past),
    // so `reconcileFileGrantTree`'s plan puts its tree entry in `toScrub`.
    // This is the reconcile call `cmdRevoke` makes BEFORE it ever touches the
    // grant the operator actually asked to revoke.
    const expiredGrantId = "fg_expired_scrub01";
    const expiredGrant: FileGrant = {
      grant_id: expiredGrantId,
      schema_version: FILE_GRANT_SCHEMA_VERSION,
      subject_agent_id: "agent-expired",
      scope: { kind: "file", path: "/tmp/does-not-matter-either.txt" },
      mode: "read",
      created_by: storedIdentity.identity_id,
      created_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() - 30_000).toISOString(),
      status: "active",
      revoked_at: null,
      tree_entry: `agent-expired/${expiredGrantId}`,
      audit_refs: [],
    };
    await grantStore.put(expiredGrant);

    // Grant B: the operator's actual revoke TARGET -- unrelated and unexpired.
    // Its own tree entry is absent, so its scrub is the idempotent no-op case
    // and the revoke itself has nothing to fail on. The only thing that could
    // stop it is the reconcile above, which is exactly what is under test.
    const targetGrantId = "fg_revoke_target01";
    const targetGrant: FileGrant = {
      grant_id: targetGrantId,
      schema_version: FILE_GRANT_SCHEMA_VERSION,
      subject_agent_id: "agent-target",
      scope: { kind: "file", path: "/tmp/also-does-not-matter.txt" },
      mode: "read",
      created_by: storedIdentity.identity_id,
      created_at: new Date().toISOString(),
      expires_at: null,
      status: "active",
      revoked_at: null,
      tree_entry: `agent-target/${targetGrantId}`,
      audit_refs: [],
    };
    await grantStore.put(targetGrant);

    const grantsRoot = join(fortressPath, "grants");
    await mkdir(grantsRoot, { recursive: true, mode: 0o711 });
    // A FILE where the EXPIRED grant's per-agent subdirectory must be a
    // directory, so `reconcileFileGrantTree`'s own scrub (removeEntry on the
    // expired entry) fails with a genuine ENOTDIR -- unrelated to the grant
    // actually being revoked.
    await writeFile(join(grantsRoot, "agent-expired"), "not a directory");

    const out = new StringWritable();
    const err = new StringWritable();

    // The reconcile this triggers fails while scrubbing a completely different
    // grant's tree entry. The operator asked to revoke THIS grant, and a revoke
    // reduces access, so it must still happen and must still get its verdict.
    const code = await runFileGrantCommand({
      argv: ["revoke", "--grant", targetGrantId, "--fortress", fortressPath],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });

    expect(code).toBe(0);
    expect(out.text).toContain(`Grant ${targetGrantId} revoked.`);
    // The reconcile failure is reported, not swallowed: the operator is told
    // the sweep did not fully converge, and is told it separately from the
    // revoke's own verdict so the two are never confused.
    expect(err.text).toContain("Notice: the tree reconcile that runs before a revoke");
    expect(err.text).not.toContain("Error: revoke did not complete cleanly.");
    expect(err.text).not.toContain("at process.processTicksAndRejections");

    // The revoke actually landed on the record, not merely in the message.
    expect((await grantStore.get(targetGrantId))!.status).toBe("revoked");
  });

  it("refuses a mint when the reconcile that precedes it does not converge (FG-RECONCILE-SIBLINGS-01)", async () => {
    const stateStoragePath = join(fortressPath, "state");
    const storage = new FilesystemStorage(stateStoragePath);
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const { createIdentity } = await import("../../src/core/identity.js");
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity("operator", identityEncKey, "recovery-key");
    await identityManager.save(storedIdentity);
    await identityManager.setPrimary(storedIdentity.identity_id);

    const stateStore = new StateStore(storage, masterKey);
    const grantStore = new FileGrantStore(stateStore, {
      identityId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      identityEncryptionKey: identityEncKey,
    });

    const expiredGrantId = "fg_expired_scrub02";
    await grantStore.put({
      grant_id: expiredGrantId,
      schema_version: FILE_GRANT_SCHEMA_VERSION,
      subject_agent_id: "agent-expired",
      scope: { kind: "file", path: "/tmp/does-not-matter-either.txt" },
      mode: "read",
      created_by: storedIdentity.identity_id,
      created_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() - 30_000).toISOString(),
      status: "active",
      revoked_at: null,
      tree_entry: `agent-expired/${expiredGrantId}`,
      audit_refs: [],
    });

    const grantsRoot = join(fortressPath, "grants");
    await mkdir(grantsRoot, { recursive: true, mode: 0o711 });
    await writeFile(join(grantsRoot, "agent-expired"), "not a directory");

    const out = new StringWritable();
    const err = new StringWritable();

    // Mint is the one touch that EXPANDS access, so an unconverged tree refuses
    // it. Fail-closed here is the opposite policy from the revoke above, and
    // deliberately so: the direction of the operation is what decides.
    const code = await runFileGrantCommand({
      argv: [
        "mint",
        "--agent",
        "agent-new",
        "--path",
        "/tmp/does-not-matter-at-all.txt",
        "--fortress",
        fortressPath,
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });

    expect(code).toBe(1);
    expect(err.text).toContain("no new grant");
    expect(err.text).not.toContain("at process.processTicksAndRejections");
  });
});
