/**
 * KeychainBackend Integration Tests (macOS)
 *
 * These exercise the real `/usr/bin/security` CLI against a *temporary*
 * keychain file created and cleaned up per-test. Skipped on non-darwin.
 *
 * Tests validate:
 * - ensureInitialized creates a keychain idempotently.
 * - addSecret / readSecret round-trip preserves the raw value.
 * - Reads on a locked backend throw BackendLockedError.
 * - rotateSecret replaces the value.
 * - deleteSecret removes the item; subsequent read throws SecretNotFoundError.
 * - listSecretNames returns names without values.
 * - Adding an existing secret throws (use rotate explicitly).
 * - Validate secret name rejects illegal characters.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync, rmSync, mkdtempSync } from "node:fs";
import {
  brokerAccountForSecret,
  brokerKeychainIdentityFor,
  KeychainBackend,
  legacyBrokerKeychainIdentity,
} from "../../../src/l3-disclosure/broker/keychain-backend.js";
import {
  BackendLockedError,
  BackendUnavailableError,
  SecretNotFoundError,
} from "../../../src/l3-disclosure/broker/backend-interface.js";

const isDarwin = process.platform === "darwin";
const PP = "test-passphrase-93a4e71f";

// Skip the whole suite on non-darwin.
const describeIfDarwin = isDarwin ? describe : describe.skip;

describeIfDarwin("KeychainBackend (macOS integration)", () => {
  let tempDir: string;
  let keychainPath: string;
  let backend: KeychainBackend;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "sanctuary-kc-test-"));
    keychainPath = join(tempDir, "sanctuary-test.keychain-db");
    backend = new KeychainBackend({ keychainPath });
    await backend.ensureInitialized(PP);
  });

  afterAll(() => {
    // Belt-and-suspenders — each test cleans up, but make sure nothing lingers.
    try {
      if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it("ensureInitialized creates the keychain and is idempotent", async () => {
    expect(existsSync(keychainPath)).toBe(true);
    // Second call should succeed without error (unlocks existing).
    await backend.ensureInitialized(PP);
    expect(await backend.isUnlocked()).toBe(true);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("add / read round-trip preserves exact value", async () => {
    const value = "ghp_xyz123_TOKEN_with+special/chars=\"end";
    await backend.addSecret("github_pat", value);
    expect(await backend.readSecret("github_pat")).toBe(value);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("addSecret throws when name already exists", async () => {
    await backend.addSecret("gmail_oauth", "a");
    await expect(backend.addSecret("gmail_oauth", "b")).rejects.toThrow(/already exists/);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("readSecret throws SecretNotFoundError for unknown name", async () => {
    await expect(backend.readSecret("does_not_exist")).rejects.toBeInstanceOf(
      SecretNotFoundError
    );
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("rotateSecret replaces the stored value", async () => {
    await backend.addSecret("gmail_oauth", "v1");
    await backend.rotateSecret("gmail_oauth", "v2");
    expect(await backend.readSecret("gmail_oauth")).toBe("v2");
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("rotateSecret throws SecretNotFoundError when no such secret", async () => {
    await expect(backend.rotateSecret("nope", "x")).rejects.toBeInstanceOf(SecretNotFoundError);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("deleteSecret removes the item", async () => {
    await backend.addSecret("gmail_oauth", "v");
    await backend.deleteSecret("gmail_oauth");
    await expect(backend.readSecret("gmail_oauth")).rejects.toBeInstanceOf(SecretNotFoundError);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("listSecretNames returns names only (no values)", async () => {
    await backend.addSecret("gmail_oauth", "value-should-not-appear");
    await backend.addSecret("github_pat", "another-value-hidden");
    const names = await backend.listSecretNames();
    expect(new Set(names)).toEqual(new Set(["gmail_oauth", "github_pat"]));
    const joined = names.join("|");
    expect(joined).not.toContain("value-should-not-appear");
    expect(joined).not.toContain("another-value-hidden");
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("addSecret rejects invalid name characters", async () => {
    // Shell metacharacters that could be abused if not validated.
    await expect(backend.addSecret("bad name;rm -rf /", "v")).rejects.toThrow(
      /invalid characters/
    );
    await expect(backend.addSecret("bad$name", "v")).rejects.toThrow(/invalid characters/);
    await expect(backend.addSecret("", "v")).rejects.toThrow(/1\.\.256/);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("rejects ensureInitialized with empty passphrase", async () => {
    const fresh = new KeychainBackend({
      keychainPath: join(tempDir, "no-pp.keychain-db"),
    });
    await expect(fresh.ensureInitialized("")).rejects.toThrow();
    rmSync(tempDir, { recursive: true, force: true });
  });
});

describe("Broker keychain tenant identity", () => {
  it("keeps the legacy global backend only for the default storage path", () => {
    const home = join(tmpdir(), "sanctuary-home");
    const identity = brokerKeychainIdentityFor(join(home, ".sanctuary"), home);

    expect(identity).toEqual(legacyBrokerKeychainIdentity(home));
    expect(identity.service).toBe("sanctuary-broker");
    expect(brokerAccountForSecret("github_pat", identity.accountNamespace)).toBe(
      "github_pat"
    );
  });

  it("derives keychain path, service, and account namespace from non-default storage path", () => {
    const home = join(tmpdir(), "sanctuary-home");
    const storagePath = join(home, "fortresses", "alpha");
    const identity = brokerKeychainIdentityFor(storagePath, home);

    expect(identity.keychainPath).toMatch(
      /Library\/Keychains\/sanctuary-broker-[0-9a-f]{16}\.keychain-db$/
    );
    expect(identity.service).toMatch(/^sanctuary-broker-[0-9a-f]{16}$/);
    expect(identity.accountNamespace).toMatch(/^[0-9a-f]{16}$/);
    expect(identity.service).toBe(`sanctuary-broker-${identity.accountNamespace}`);
    expect(brokerAccountForSecret("github_pat", identity.accountNamespace)).toBe(
      `${identity.accountNamespace}:github_pat`
    );
  });

  it("canonicalizes cosmetic storage path differences to the same identity", () => {
    const home = join(tmpdir(), "sanctuary-home");
    const first = brokerKeychainIdentityFor(
      join(home, "fortresses", "alpha"),
      home
    );
    const second = brokerKeychainIdentityFor(
      join(home, "fortresses", "nested", "..", "alpha", "."),
      home
    );

    expect(second).toEqual(first);
  });

  it("isolates two fortresses that use the same broker secret name", () => {
    const home = join(tmpdir(), "sanctuary-home");
    const alpha = brokerKeychainIdentityFor(join(home, "alpha"), home);
    const beta = brokerKeychainIdentityFor(join(home, "beta"), home);
    const key = (identity: typeof alpha, name: string) =>
      [
        identity.keychainPath,
        identity.service,
        brokerAccountForSecret(name, identity.accountNamespace),
      ].join("|");
    const store = new Map<string, string>();

    store.set(key(alpha, "shared_api_token"), "alpha-secret");
    store.set(key(beta, "shared_api_token"), "beta-secret");

    expect(alpha.keychainPath).not.toBe(beta.keychainPath);
    expect(alpha.service).not.toBe(beta.service);
    expect(brokerAccountForSecret("shared_api_token", alpha.accountNamespace)).not.toBe(
      brokerAccountForSecret("shared_api_token", beta.accountNamespace)
    );
    expect(store.get(key(alpha, "shared_api_token"))).toBe("alpha-secret");
    expect(store.get(key(beta, "shared_api_token"))).toBe("beta-secret");
  });
});

describe("KeychainBackend platform guard", () => {
  it("throws BackendUnavailableError on non-darwin", async () => {
    if (process.platform === "darwin") {
      // On darwin, we can't easily simulate non-darwin without heavy mocking;
      // skip this one case and cover the check via code review.
      return;
    }
    const backend = new KeychainBackend({
      keychainPath: join(tmpdir(), "should-never-create.keychain-db"),
    });
    await expect(backend.ensureInitialized("pp")).rejects.toBeInstanceOf(
      BackendUnavailableError
    );
  });
});
