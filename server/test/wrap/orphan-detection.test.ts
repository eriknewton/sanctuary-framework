/**
 * Custody-factor orphan detection tests (element 5): warn before lockout.
 *
 * The detector compares the factors the live envelope expects against what is
 * actually in the OS keyring, and warns when an enrolled keychain factor is
 * GONE (reachable keyring, missing item) — before the operator is locked out.
 * A locked/unreachable keyring is inconclusive (no false alarm); no enrolled
 * keychain factor is "no-factor".
 */

import { describe, it, expect } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  writeCustodyEnvelope,
  wrapMasterWithPassphrase,
  wrapMasterWithKeychainKey,
  type CustodyWrap,
} from "../../src/core/master-custody.js";
import { generateRandomKey } from "../../src/core/random.js";
import { detectCustodyFactorOrphan } from "../../src/wrap/orphan-detection.js";
import { custodyServiceFor } from "../../src/wrap/keychain-custody.js";
import type { KeychainCustodyOptions } from "../../src/wrap/keychain-custody.js";

const STORAGE_PATH = "/tmp/sanctuary-orphan-test-fortress";
const HOME = "/tmp/sanctuary-orphan-test-home";

async function fortressWithKeychainFactor(): Promise<MemoryStorage> {
  const storage = new MemoryStorage();
  const master = generateRandomKey();
  const wraps: CustodyWrap[] = [
    await wrapMasterWithPassphrase(master, "pw", { verified: true }),
    wrapMasterWithKeychainKey(master, generateRandomKey(), { verified: true }),
  ];
  await writeCustodyEnvelope(
    storage,
    { v: 1, install_mode: "interactive", wraps, created_at: new Date().toISOString() },
    master,
  );
  return storage;
}

async function passphraseOnlyFortress(): Promise<MemoryStorage> {
  const storage = new MemoryStorage();
  const master = generateRandomKey();
  const wraps: CustodyWrap[] = [
    await wrapMasterWithPassphrase(master, "pw", { verified: true }),
    await wrapMasterWithPassphrase(master, "pw2", { verified: true }),
  ];
  await writeCustodyEnvelope(
    storage,
    { v: 1, install_mode: "interactive", wraps, created_at: new Date().toISOString() },
    master,
  );
  return storage;
}

function keyring(
  status: "present" | "missing" | "locked",
): KeychainCustodyOptions {
  const custodyService = custodyServiceFor(STORAGE_PATH, HOME);
  return {
    home: HOME,
    platformOverride: "linux",
    exec: async (cmd, args) => {
      if (cmd !== "secret-tool" || args[0] !== "lookup") {
        return { stdout: "", stderr: "", code: 1 };
      }
      const svc = args[args.indexOf("service") + 1];
      if (status === "locked") {
        return { stdout: "", stderr: "Cannot autolaunch D-Bus", code: 1 };
      }
      if (status === "present" && svc === custodyService) {
        // 32-byte base64url value
        return {
          stdout: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n",
          stderr: "",
          code: 0,
        };
      }
      // missing (reachable, empty)
      return { stdout: "", stderr: "", code: 1 };
    },
  };
}

describe("detectCustodyFactorOrphan — element 5", () => {
  it("warns 'orphaned' when an enrolled keychain factor is missing from a reachable keyring", async () => {
    const storage = await fortressWithKeychainFactor();
    const result = await detectCustodyFactorOrphan(
      storage,
      STORAGE_PATH,
      keyring("missing"),
    );
    expect(result.verdict).toBe("orphaned");
    expect(result.message).toContain("MISSING");
    expect(result.message).toContain("recovery key");
  });

  it("reports 'ok' when the enrolled keychain factor is present", async () => {
    const storage = await fortressWithKeychainFactor();
    const result = await detectCustodyFactorOrphan(
      storage,
      STORAGE_PATH,
      keyring("present"),
    );
    expect(result.verdict).toBe("ok");
  });

  it("reports 'inconclusive' (no false alarm) when the keyring is locked/unreachable", async () => {
    const storage = await fortressWithKeychainFactor();
    const result = await detectCustodyFactorOrphan(
      storage,
      STORAGE_PATH,
      keyring("locked"),
    );
    expect(result.verdict).toBe("inconclusive");
  });

  it("reports 'no-factor' when no keychain factor is enrolled", async () => {
    const storage = await passphraseOnlyFortress();
    const result = await detectCustodyFactorOrphan(
      storage,
      STORAGE_PATH,
      keyring("missing"),
    );
    expect(result.verdict).toBe("no-factor");
  });
});
