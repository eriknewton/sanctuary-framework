/**
 * `sanctuary federation revoke-push` + `downgrade-log` CLI tests (PR-3).
 *
 * Verifies the operator-gated, issuer-LOCAL revocation-list surface end to end
 * against a real keychain-free fortress seeded WITH a default operator identity:
 *   - revoke-push SIGNS a revocation list with the operator identity and PERSISTS
 *     a master-MAC'd record that verifies against the fortress issuer key; the
 *     stored list is independently readable + authentic.
 *   - MONOTONIC: a second push at an equal/lower --version is refused (exit 3);
 *     a strictly-greater version advances the stored list.
 *   - Arg validation: a missing/invalid --version → exit 1; no secret leaks.
 *   - downgrade-log prints the operator-visible log (empty is exit 0, readable).
 *
 * The fortress is seeded keychain-free (mocked `security` exec) so the real
 * macOS login keychain is never touched — the pattern in license.test.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { runFederationCommand } from "../../src/cli/federation.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { readRevocationList } from "../../src/entitlement/index.js";

// ── Keychain-free fortress seeding (mirrors license.test.ts) ──────────────────
type ExecCall = { cmd: string; args: string[]; input?: string };
function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}
function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`));
  return match ? unescapeSecurityToken(match[1]!) : "";
}
function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (a: string, s: string): string => `${a}:${s}`;
  const exec = async (cmd: string, args: string[], input?: string): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        keyFor(readSecurityToken(input, "-a"), readSecurityToken(input, "-s")),
        readSecurityToken(input, "-w"),
      );
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
async function runInit(options: InitOptions): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
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
  override _write(chunk: Buffer | string, _enc: BufferEncoding, cb: (err?: Error) => void): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}
async function seedFortressWithIdentity(fortressPath: string): Promise<string> {
  const result = await runInit({
    fortress: fortressPath,
    noConfirm: true,
    noPin: true,
    noIdentity: false,
  });
  const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
  return extractRecoveryKey(recoveryFile);
}
/** Recover the fortress master key to independently read the stored list. */
async function fortressMasterKey(fortressPath: string, recoveryKey: string): Promise<Uint8Array> {
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  return resolveCliMasterKey(storage, { recoveryKey, storagePathHint: fortressPath });
}

describe("sanctuary federation revoke-push / downgrade-log — arg validation (no fortress)", () => {
  it("help lists revoke-push + downgrade-log", async () => {
    const out = new StringWritable();
    const code = await runFederationCommand({ argv: ["--help"], out, err: new StringWritable(), env: {} });
    expect(code).toBe(0);
    expect(out.text).toContain("revoke-push");
    expect(out.text).toContain("downgrade-log");
  });

  it("revoke-push without --version → exit 1", async () => {
    const err = new StringWritable();
    const code = await runFederationCommand({
      argv: ["revoke-push", "--license-id", "lic-a"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--version");
  });

  it("revoke-push with a non-positive --version → exit 1", async () => {
    const err = new StringWritable();
    const code = await runFederationCommand({
      argv: ["revoke-push", "--version", "0", "--license-id", "lic-a"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("positive integer");
  });
});

describe("sanctuary federation revoke-push / downgrade-log — end-to-end (keychain-free)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-revoke-push-test-"));
  });
  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it("signs + persists a revocation list that authenticates under the fortress master; no secret leaks", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runFederationCommand({
      argv: [
        "revoke-push", "--fortress", fortressPath,
        "--version", "1",
        "--license-id", "lic-killed-a",
        "--license-id", "lic-killed-b",
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");
    expect(out.text).toContain("revocation_list_pushed");
    expect(out.text).toContain('"revoked_count": 2');
    expect(out.text).not.toMatch(/private/i);

    // Independently read the persisted, MAC'd list under the recovered master.
    const master = await fortressMasterKey(fortressPath, recoveryKey);
    try {
      const stored = await readRevocationList(new FilesystemStorage(join(fortressPath, "state")), master);
      expect(stored.status).toBe("valid");
      if (stored.status === "valid") {
        expect(stored.payload.version).toBe(1);
        expect(stored.payload.revokedLicenseIds).toEqual(["lic-killed-a", "lic-killed-b"]);
      }
    } finally {
      master.fill(0);
    }
  });

  it("MONOTONIC: a second push at an equal version is refused (exit 3); a higher version advances", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    expect(
      await runFederationCommand({
        argv: ["revoke-push", "--fortress", fortressPath, "--version", "5", "--license-id", "lic-a"],
        out: new StringWritable(),
        err: new StringWritable(),
        env,
      }),
    ).toBe(0);

    // Equal version → refused.
    const err = new StringWritable();
    const equal = await runFederationCommand({
      argv: ["revoke-push", "--fortress", fortressPath, "--version", "5", "--license-id", "lic-a"],
      out: new StringWritable(),
      err,
      env,
    });
    expect(equal).toBe(3);
    expect(err.text).toContain("not_newer");

    // Higher version → advances.
    expect(
      await runFederationCommand({
        argv: ["revoke-push", "--fortress", fortressPath, "--version", "6", "--license-id", "lic-a", "--license-id", "lic-b"],
        out: new StringWritable(),
        err: new StringWritable(),
        env,
      }),
    ).toBe(0);

    const master = await fortressMasterKey(fortressPath, recoveryKey);
    try {
      const stored = await readRevocationList(new FilesystemStorage(join(fortressPath, "state")), master);
      expect(stored.status === "valid" && stored.payload.version).toBe(6);
    } finally {
      master.fill(0);
    }
  });

  it("downgrade-log prints a readable (initially empty) log (exit 0)", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const code = await runFederationCommand({
      argv: ["downgrade-log", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    expect(out.text).toContain('"readable": true');
    expect(out.text).toContain('"entry_count": 0');
  });
});
