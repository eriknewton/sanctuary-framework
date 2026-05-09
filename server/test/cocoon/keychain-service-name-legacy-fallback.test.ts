/**
 * Legacy keychain fallback tests (Option A migration).
 *
 * Full-sweep finding #62 extended the suffix from 12 to 16 hex chars.
 * Existing operators on non-default paths have keychain entries under the
 * old 12-hex suffix. The read path tries the new 16-hex name first, then
 * falls back to the legacy 12-hex name.
 *
 * Writes always go to the new 16-hex name, so operators are auto-migrated
 * on next write (e.g., next passphrase rotation or next wrap).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  readStoredPassphrase,
  legacyKeychainServiceFor,
  keychainServiceFor,
  type ExecResult,
} from "../../src/cocoon/passphrase.js";

/**
 * Build a mock exec that simulates macOS Keychain with per-(account,service) isolation.
 */
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

describe("legacy 12-hex keychain fallback (Option A migration)", () => {
  let home: string;
  const tenantPath = "/srv/agent-legacy";

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-legacy-fallback-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("reads a passphrase stored under the legacy 12-hex service name", async () => {
    const { exec, stored } = makeExec();
    const legacyService = legacyKeychainServiceFor(tenantPath, home);
    const currentService = keychainServiceFor(tenantPath, home);

    // Simulate a pre-v1.2.3 entry: passphrase stored under the old 12-hex name.
    stored.set(`sanctuary:${legacyService}`, "legacy-passphrase-value");

    // The new 16-hex name should NOT have an entry.
    expect(stored.has(`sanctuary:${currentService}`)).toBe(false);

    // readStoredPassphrase should find it via the fallback path.
    const result = await readStoredPassphrase({
      home,
      storagePath: tenantPath,
      platformOverride: "darwin",
      exec,
    });
    expect(result).not.toBeNull();
    expect(result!.value).toBe("legacy-passphrase-value");
    expect(result!.source).toBe("keychain");
  });

  it("getOrCreatePassphrase finds a legacy entry and returns it without regenerating", async () => {
    const { exec, stored } = makeExec();
    const legacyService = legacyKeychainServiceFor(tenantPath, home);

    // Pre-seed under the legacy name.
    stored.set(`sanctuary:${legacyService}`, "old-passphrase");

    const result = await getOrCreatePassphrase({
      home,
      storagePath: tenantPath,
      platformOverride: "darwin",
      exec,
    });
    expect(result.value).toBe("old-passphrase");
    expect(result.source).toBe("keychain");
  });

  it("prefers the new 16-hex entry over the legacy 12-hex entry when both exist", async () => {
    const { exec, stored } = makeExec();
    const legacyService = legacyKeychainServiceFor(tenantPath, home);
    const currentService = keychainServiceFor(tenantPath, home);

    stored.set(`sanctuary:${legacyService}`, "old-passphrase");
    stored.set(`sanctuary:${currentService}`, "new-passphrase");

    const result = await readStoredPassphrase({
      home,
      storagePath: tenantPath,
      platformOverride: "darwin",
      exec,
    });
    expect(result!.value).toBe("new-passphrase");
  });

  it("new writes go to the 16-hex service name (auto-migration on generate)", async () => {
    const { exec, stored } = makeExec();
    const currentService = keychainServiceFor(tenantPath, home);

    // No pre-existing entry; getOrCreatePassphrase generates fresh.
    const result = await getOrCreatePassphrase({
      home,
      storagePath: tenantPath,
      platformOverride: "darwin",
      exec,
    });
    expect(result.source).toBe("generated");

    // The new entry is stored under the 16-hex service name.
    expect(stored.has(`sanctuary:${currentService}`)).toBe(true);
  });

  it("legacy fallback does not fire for the default path (both map to the same legacy name)", () => {
    const defaultService = keychainServiceFor(join(home, ".sanctuary"), home);
    const defaultLegacy = legacyKeychainServiceFor(join(home, ".sanctuary"), home);
    // Both return the un-suffixed legacy name; no fallback needed.
    expect(defaultService).toBe("sanctuary-passphrase");
    expect(defaultLegacy).toBe("sanctuary-passphrase");
  });
});
