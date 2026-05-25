/**
 * Passphrase multi-tenancy tests.
 *
 * Covers the per-tenant isolation surfaces added in v0.10.0 WP1:
 *   - `keychainServiceFor(storagePath)` namespaces the Keychain item by path.
 *   - `fallbackFilePath(home, storagePath)` lands under the explicit storage path.
 *   - `getOrCreatePassphrase({ storagePath })` routes through both of the above
 *     so two agents with different storage paths cannot see each other's
 *     stored passphrases on either macOS Keychain or the Linux fallback file.
 *
 * These tests complement `passphrase.test.ts`, which covers single-tenant
 * behaviour and backward compatibility for the default storage path.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  fallbackFilePath,
  keychainServiceFor,
  type ExecResult,
} from "../../src/wrap/passphrase.js";

// Simulate a Keychain where each (account, service) pair is an isolated cell —
// mirroring how the real `security` CLI behaves. Two instances with distinct
// service names must not clobber each other.
function makeExec(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  stored: Map<string, string>;
} {
  const stored = new Map<string, string>();

  function keyFor(args: string[]): string {
    const account = args[args.indexOf("-a") + 1] ?? "";
    const service = args[args.indexOf("-s") + 1] ?? "";
    return `${account}:${service}`;
  }

  const exec = async (
    cmd: string,
    args: string[]
  ): Promise<ExecResult> => {
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    const key = keyFor(args);
    if (args[0] === "find-generic-password") {
      const value = stored.get(key);
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    if (args[0] === "add-generic-password") {
      const wIdx = args.indexOf("-w");
      if (wIdx < 0 || !args[wIdx + 1]) {
        return { stdout: "", stderr: "missing -w", code: 1 };
      }
      stored.set(key, args[wIdx + 1]!);
      return { stdout: "", stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };

  return { exec, stored };
}

describe("keychainServiceFor", () => {
  const home = "/home/test";

  it("returns the legacy service name for the default storage path", () => {
    expect(keychainServiceFor(join(home, ".sanctuary"), home)).toBe(
      "sanctuary-passphrase"
    );
  });

  it("returns a namespaced service name for a custom storage path", () => {
    const name = keychainServiceFor("/srv/agent-a", home);
    expect(name).toMatch(/^sanctuary-passphrase-[0-9a-f]{16}$/);
  });

  it("derives distinct service names for distinct storage paths", () => {
    const a = keychainServiceFor("/srv/agent-a", home);
    const b = keychainServiceFor("/srv/agent-b", home);
    expect(a).not.toBe(b);
  });

  it("is deterministic — same storage path always yields the same service name", () => {
    const first = keychainServiceFor("/srv/agent-a", home);
    const second = keychainServiceFor("/srv/agent-a", home);
    expect(first).toBe(second);
  });
});

describe("fallbackFilePath (multi-tenant)", () => {
  it("returns the legacy <home>/.sanctuary path when no storage path is supplied", () => {
    expect(fallbackFilePath("/home/test")).toBe(
      "/home/test/.sanctuary/passphrase.enc"
    );
  });

  it("uses the supplied storage path when provided", () => {
    expect(fallbackFilePath("/home/test", "/srv/agent-a")).toBe(
      "/srv/agent-a/passphrase.enc"
    );
  });

  it("returns distinct files for two tenants on one host", () => {
    const a = fallbackFilePath("/home/test", "/srv/agent-a");
    const b = fallbackFilePath("/home/test", "/srv/agent-b");
    expect(a).not.toBe(b);
  });
});

describe("getOrCreatePassphrase — per-tenant isolation", () => {
  let home: string;
  let tenantA: string;
  let tenantB: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-multi-"));
    tenantA = join(home, "tenant-a");
    tenantB = join(home, "tenant-b");
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("stores two different passphrases in two different Keychain items on darwin", async () => {
    const { exec, stored } = makeExec();

    const first = await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "darwin",
      exec,
    });
    const second = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "darwin",
      exec,
    });

    // Two Keychain items, not one shared.
    expect(stored.size).toBe(2);
    // Different tenants → different generated passphrases.
    expect(first.value).not.toBe(second.value);

    // Reading tenant A back must not surface tenant B's value, and vice versa.
    const reReadA = await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "darwin",
      exec,
    });
    expect(reReadA.value).toBe(first.value);
    expect(reReadA.source).toBe("keychain");

    const reReadB = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "darwin",
      exec,
    });
    expect(reReadB.value).toBe(second.value);
    expect(reReadB.source).toBe("keychain");
  });

  it("writes two isolated fallback files on linux", async () => {
    const { exec } = makeExec();

    const first = await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "linux",
      exec,
    });
    const second = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "linux",
      exec,
    });

    expect(first.location).toBe(join(tenantA, "passphrase.enc"));
    expect(second.location).toBe(join(tenantB, "passphrase.enc"));
    await access(first.location);
    await access(second.location);

    // Each fallback file encrypts its own tenant's passphrase — not the
    // sibling's.
    const rawA = await readFile(first.location);
    const rawB = await readFile(second.location);
    expect(rawA.toString("utf-8")).not.toContain(first.value);
    expect(rawB.toString("utf-8")).not.toContain(second.value);
    expect(Buffer.compare(rawA, rawB)).not.toBe(0);

    expect(first.value).not.toBe(second.value);
  });

  it("rejects a fallback ciphertext copied into another tenant path before identity decrypt", async () => {
    const { exec } = makeExec();

    const first = await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "linux",
      exec,
    });
    await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "linux",
      exec,
    });

    const rawA = await readFile(first.location);
    await writeFile(fallbackFilePath(home, tenantB), rawA);

    await expect(
      getOrCreatePassphrase({
        home,
        storagePath: tenantB,
        platformOverride: "linux",
        exec,
      }),
    ).rejects.toThrow(/could not be decrypted/);
  });

  it("a tenant reading another tenant's Keychain service gets nothing back", async () => {
    const { exec } = makeExec();

    // Tenant A generates + stores.
    await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "darwin",
      exec,
    });

    // Tenant B looks up its own service — no entry yet, so it generates a
    // fresh passphrase rather than inheriting A's.
    const b = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "darwin",
      exec,
    });
    expect(b.source).toBe("generated");
  });
});
