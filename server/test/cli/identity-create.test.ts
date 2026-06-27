/**
 * `sanctuary identity create` CLI tests.
 *
 * Verifies (Findings 3 + 4 from the 2026-06-24 stock-CLI seed-gaps drill):
 *   - Help output on `create --help`.
 *   - Error exit when no passphrase / recovery key is provided.
 *   - `create` mints a default operator identity in a fresh keychain-free
 *     fortress, sets it as primary, and `show` then reports it.
 *   - `create` on a fortress that already has a default identity adds an
 *     ADDITIONAL identity without changing the primary (never clobbers).
 *
 * Fortresses are seeded keychain-free (headless `runInit` with --no-identity
 * and a mocked recovery keychain) so the real macOS login keychain is never
 * touched — exactly the pattern in test/wrap/init.test.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { runIdentityCommand } from "../../src/cli/identity.js";
import {
  runInit as runInitRaw,
  type InitOptions,
} from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

// ── Keychain-free fortress seeding ──────────────────────────────────────
// Mirrors test/wrap/init.test.ts: a mocked `security` exec so init never
// touches the real macOS login keychain (which pops a blocking modal).

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

/** Seed a keychain-free fortress and return its plaintext recovery key. */
async function seedFortress(fortressPath: string): Promise<string> {
  const result = await runInit({
    fortress: fortressPath,
    noConfirm: true,
    noPin: true,
    noIdentity: true,
  });
  const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
  return extractRecoveryKey(recoveryFile);
}

describe("sanctuary identity create CLI surface", () => {
  it("prints help on create --help", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({ argv: ["create", "--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary identity create");
    expect(out.text).toContain("--label");
  });

  it("lists create alongside show in the top-level help", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({ argv: ["--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("show");
    expect(out.text).toContain("create");
  });

  it("returns exit 1 when no passphrase or recovery key is provided", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({
      argv: ["create"],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("requires SANCTUARY_PASSPHRASE");
  });
});

describe("sanctuary identity create (end-to-end, keychain-free)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-identity-create-test-"));
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

  it("mints a default operator identity that `show` then reports", async () => {
    const fortressPath = join(tmp, "fresh-fortress");
    const recoveryKey = await seedFortress(fortressPath);

    // Create against the identity-less fortress.
    const createOut = new StringWritable();
    const createErr = new StringWritable();
    const createCode = await runIdentityCommand({
      argv: ["create", "--fortress", fortressPath, "--json"],
      out: createOut,
      err: createErr,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(createCode).toBe(0);
    const created = JSON.parse(createOut.text) as {
      identity_id: string;
      did: string;
      label: string;
      is_primary: boolean;
    };
    expect(created.label).toBe("operator");
    expect(created.did).toMatch(/^did:key:z/);
    // First identity in the fortress is the primary/default.
    expect(created.is_primary).toBe(true);

    // `show` reports the same identity as the active (primary) one.
    delete process.env.SANCTUARY_STORAGE_PATH;
    const showOut = new StringWritable();
    const showErr = new StringWritable();
    const showCode = await runIdentityCommand({
      argv: ["show", "--fortress", fortressPath, "--json"],
      out: showOut,
      err: showErr,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(showCode).toBe(0);
    const shown = JSON.parse(showOut.text) as { identity_id: string };
    expect(shown.identity_id).toBe(created.identity_id);
  });

  it("honors --label for the created identity", async () => {
    const fortressPath = join(tmp, "labeled-fortress");
    const recoveryKey = await seedFortress(fortressPath);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({
      argv: ["create", "--fortress", fortressPath, "--label", "fleet-signer", "--json"],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const created = JSON.parse(out.text) as { label: string };
    expect(created.label).toBe("fleet-signer");
  });

  it("adds an additional identity without changing the primary when one exists", async () => {
    const fortressPath = join(tmp, "two-identity-fortress");
    const recoveryKey = await seedFortress(fortressPath);

    // First create -> becomes primary.
    const firstOut = new StringWritable();
    const firstCode = await runIdentityCommand({
      argv: ["create", "--fortress", fortressPath, "--json"],
      out: firstOut,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(firstCode).toBe(0);
    const first = JSON.parse(firstOut.text) as { identity_id: string };

    // Second create -> additional, NOT primary.
    delete process.env.SANCTUARY_STORAGE_PATH;
    const secondOut = new StringWritable();
    const secondCode = await runIdentityCommand({
      argv: ["create", "--fortress", fortressPath, "--label", "second", "--json"],
      out: secondOut,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(secondCode).toBe(0);
    const second = JSON.parse(secondOut.text) as {
      identity_id: string;
      is_primary: boolean;
    };
    expect(second.identity_id).not.toBe(first.identity_id);
    expect(second.is_primary).toBe(false);

    // `show` still reports the FIRST identity as the active (primary) one.
    delete process.env.SANCTUARY_STORAGE_PATH;
    const showOut = new StringWritable();
    const showCode = await runIdentityCommand({
      argv: ["show", "--fortress", fortressPath, "--json"],
      out: showOut,
      err: new StringWritable(),
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(showCode).toBe(0);
    const shown = JSON.parse(showOut.text) as {
      identity_id: string;
      total_identities: number;
    };
    expect(shown.identity_id).toBe(first.identity_id);
    expect(shown.total_identities).toBe(2);
  });
});
