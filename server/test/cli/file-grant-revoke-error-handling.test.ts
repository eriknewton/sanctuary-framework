/**
 * `sanctuary file-grant revoke` CLI error-handling test (R3-3).
 *
 * `revokeFileGrant` (src/file-grant/revoke.ts) deliberately PROPAGATES a tree
 * scrub failure (see its own doc comment: the persisted record is marked
 * revoked BEFORE the scrub is attempted, and if the scrub throws the error
 * propagates so the caller learns the tree entry may still be present).
 * Before R3-3, `cmdRevoke` in src/cli/file-grant.ts called `revokeFileGrant`
 * with no try/catch, so that propagated error surfaced to the CLI's caller as
 * an unhandled rejection / raw stack trace instead of a clean operator-facing
 * message and a non-zero exit code -- unlike `cmdMint`, which already wraps
 * `mintFileGrant` in exactly this pattern.
 *
 * This test proves the fix end-to-end: seed a real (keychain-free) fortress
 * and identity, seed an ACTIVE file-grant record directly (bypassing the
 * interactive Tier-1 mint approval prompt, which auto-denies in a
 * non-interactive test process), force the tree scrub to fail with a genuine
 * filesystem error (ENOTDIR, not ENOENT -- the same real-error class
 * `test/file-grant/fs-ops.test.ts` uses), and assert `runFileGrantCommand`
 * resolves (never rejects) with a non-zero code and a clean error line.
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
});
