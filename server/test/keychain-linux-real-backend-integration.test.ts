/**
 * Linux Secret Service real-backend integration test.
 *
 * Exercises the production Secret Service shell-out path in
 * server/src/wrap/passphrase.ts against a real `secret-tool` CLI plus a
 * real gnome-keyring-daemon running on a dbus-run-session-managed session
 * bus. Closes full-sweep finding #45 (P1) and v0.10.1 / v1.0.2 backlog
 * item (b): mock-only coverage, carried since v0.10.1 PR #60, did not
 * exercise the actual D-Bus + libsecret stack.
 *
 * Runs in CI via `.github/workflows/keychain-linux-real-backend.yml`. The
 * `describe.skipIf` guard at the top of this file skips cleanly on macOS,
 * Windows, and any Linux host without `secret-tool` or a session bus, so
 * developer-local `npm test` runs are unaffected.
 *
 * The mock test at `server/test/keychain-linux-secret-service.test.ts`
 * remains authoritative for unit-level behavior; this file catches
 * regressions in the shell-out shape (binary path, exit-code semantics,
 * stdin handling, attribute serialization) that mocks cannot see.
 *
 * ── Why this file opts out of the credential-CLI chokepoint ─────────
 *
 * Every test file gets an in-memory credential store installed by
 * `test/setup/keychain-fake.ts`, so nothing can write to an operator's
 * real keyring (see `src/wrap/keychain-exec.ts` for the full rationale).
 * That store is exactly wrong here: served by the fake, this file stops
 * being a real-backend test at all, and its four happy-path cases keep
 * passing while proving nothing about libsecret. The degrade case below
 * is the one that notices: it makes the session bus unreachable and
 * expects the encrypted fallback file, but an in-memory fake answers
 * cheerfully regardless of D-Bus, so a DEAD backend reports as alive.
 * A test seam that fails open is the precise defect the chokepoint was
 * built to prevent, so this file removes the store for its own duration
 * (`beforeAll`) and puts it back (`afterAll`).
 *
 * Removing the store is safe ONLY against a throwaway keyring, so the
 * skip guard below additionally requires PROOF that the keyring on this
 * host was provisioned by this CI run: a nonce that round-trips through
 * the Secret Service on this exact bus. On a developer's Linux desktop
 * `secret-tool` and a session bus are both present, and without that
 * fourth condition this file would shell out to their personal keyring.
 * The predicate lives in `test/support/real-backend-guard.ts` so its
 * truth table can be tested directly rather than asserted about.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { execSync, spawnSync } from "node:child_process";
import { mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  readStoredPassphrase,
  persistUserProvidedPassphrase,
  fallbackFilePath,
  keychainServiceFor,
  isOsKeyringLocation,
  OS_KEYRING_LOCATION_LINUX,
} from "../src/wrap/passphrase.js";
import {
  probeDisposableKeyring,
  shouldSkipRealBackend,
  enterRealBackendMode,
  leaveRealBackendMode,
  type RealBackendModeState,
} from "./support/real-backend-guard.js";

// ── Skip-unless-real-backend guard ──────────────────────────────────

const isLinux = process.platform === "linux";

const hasSecretTool = (() => {
  try {
    execSync("command -v secret-tool", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const hasDbus = !!process.env.DBUS_SESSION_BUS_ADDRESS;

/**
 * Only probe the keyring when the cheap conditions already hold: the probe
 * spawns `secret-tool`, which is pointless on macOS and would be one more
 * process for every worker on a host that is going to skip anyway.
 */
const disposableVerdict =
  isLinux && hasSecretTool && hasDbus
    ? probeDisposableKeyring()
    : { disposable: false, reason: "not a Linux host with a session bus" };

const realBackendProbe = {
  isLinux,
  hasSecretTool,
  hasDbus,
  keyringIsDisposable: disposableVerdict.disposable,
};

const skipUnlessRealBackend = shouldSkipRealBackend(realBackendProbe);

// A silent skip cost a full CI cycle to diagnose: the workflow's count guard
// fired, correctly, but the log said only "5 skipped" and the guard's own reason
// had been computed and thrown away. On a host that looks like it SHOULD have
// run this suite, say why it did not.
if (skipUnlessRealBackend && isLinux && hasSecretTool && hasDbus) {
  console.warn(
    `[real-backend] skipping: ${disposableVerdict.reason}. ` +
      `Provision with scripts/ci/provision-disposable-keyring.sh.`
  );
}

// ── Cleanup helper ──────────────────────────────────────────────────
//
// Each test creates one or more entries in the live keyring keyed by the
// per-tenant service name. The afterEach cleanup invokes `secret-tool
// clear` for every service the test touched so the volatile keyring stays
// empty for the next test (and so any developer who inadvertently runs
// this on a real keyring outside CI does not accumulate test garbage).

function clearKeyringEntry(service: string): void {
  spawnSync(
    "secret-tool",
    ["clear", "service", service, "account", "sanctuary"],
    { stdio: "ignore" }
  );
}

describe.skipIf(skipUnlessRealBackend)(
  "Linux Secret Service real-backend integration",
  () => {
    let home: string;
    const touchedServices: string[] = [];
    let realBackendMode: RealBackendModeState;

    // Hooks inside a `describe.skipIf`-skipped suite do not run, so the store
    // stays installed on every host that fails the guard above. The entry point
    // re-checks the same predicate anyway and throws rather than removing the
    // store, so a skip guard that ever drifts fails loudly instead of writing
    // to somebody's keyring.
    beforeAll(() => {
      realBackendMode = enterRealBackendMode(realBackendProbe);
    });

    afterAll(() => {
      leaveRealBackendMode(realBackendMode);
    });

    beforeEach(async () => {
      home = await mkdtemp(join(tmpdir(), "sanctuary-linux-ss-real-"));
      touchedServices.length = 0;
    });

    afterEach(async () => {
      for (const service of touchedServices) {
        clearKeyringEntry(service);
      }
      await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function trackTenant(tenantPath: string): void {
      touchedServices.push(keychainServiceFor(tenantPath, home));
    }

    // ── Round-trip via getOrCreatePassphrase ────────────────────────

    it("getOrCreatePassphrase writes to the real Secret Service on first run and reads it back on the second", async () => {
      const tenant = join(home, "round-trip");
      trackTenant(tenant);

      const first = await getOrCreatePassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      expect(first.source).toBe("generated");
      expect(first.location).toBe(OS_KEYRING_LOCATION_LINUX);
      expect(isOsKeyringLocation(first.location)).toBe(true);
      expect(first.value.length).toBeGreaterThan(0);

      const second = await getOrCreatePassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      expect(second.source).toBe("keychain");
      expect(second.location).toBe(OS_KEYRING_LOCATION_LINUX);
      expect(second.value).toBe(first.value);
    });

    // ── Round-trip via persistUserProvidedPassphrase ────────────────

    it("persistUserProvidedPassphrase round-trips a known value through the real Secret Service", async () => {
      const tenant = join(home, "persist-readback");
      trackTenant(tenant);
      const stored = "test-passphrase-real-backend-" + Date.now();

      const persisted = await persistUserProvidedPassphrase(stored, {
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      expect(persisted.source).toBe("keychain");
      expect(persisted.location).toBe(OS_KEYRING_LOCATION_LINUX);

      const read = await readStoredPassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      expect(read).not.toBeNull();
      expect(read!.source).toBe("keychain");
      expect(read!.value).toBe(stored);
    });

    // ── Missing entry returns null ──────────────────────────────────

    it("readStoredPassphrase returns null for a storage path with no prior persist", async () => {
      const tenant = join(home, "never-written");
      trackTenant(tenant);

      const result = await readStoredPassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      expect(result).toBeNull();
    });

    // ── Per-tenant isolation through real keyring ───────────────────

    it("two distinct storage paths get distinct entries in the real keyring", async () => {
      const alpha = join(home, "tenant-alpha");
      const beta = join(home, "tenant-beta");
      trackTenant(alpha);
      trackTenant(beta);

      const a = await getOrCreatePassphrase({
        home,
        storagePath: alpha,
        platformOverride: "linux",
      });
      const b = await getOrCreatePassphrase({
        home,
        storagePath: beta,
        platformOverride: "linux",
      });
      expect(a.value).not.toBe(b.value);
      expect(a.source).toBe("generated");
      expect(b.source).toBe("generated");

      // Reading B back must surface B's value, never A's, against the real
      // keyring (proves the per-tenant service-name suffix actually
      // disambiguates at the libsecret attribute layer, not just in mocks).
      const reReadB = await getOrCreatePassphrase({
        home,
        storagePath: beta,
        platformOverride: "linux",
      });
      expect(reReadB.source).toBe("keychain");
      expect(reReadB.value).toBe(b.value);
      expect(reReadB.value).not.toBe(a.value);
    });

    // ── Graceful degrade when D-Bus is unavailable ──────────────────
    //
    // Spawn-prompt test #3 specified `rejects.toThrow()` for the no-D-Bus
    // path. That is a misread of production behavior: per
    // `passphrase.ts:438-447`, all Secret Service failure modes (binary
    // missing, no session bus, daemon refusal, user-cancel) fall through
    // to the encrypted fallback file, NOT a thrown error. Invariant 5
    // ("never silently degrade to a less-secure behavior") is preserved
    // because the fallback file is itself authenticated encryption with a
    // machine-local HKDF key. This test asserts the real production
    // behavior, not the spawn-prompt's hypothetical shape.
    //
    // This case is also the canary for the test seam itself: it is the
    // only one here that a stubbed credential store cannot fake, because
    // a stub answers the same whether or not the bus is reachable. If it
    // ever reports `source: "keychain"`, the suite is talking to a stub
    // and the four cases above it are vacuous.

    it("graceful-degrades to fallback file when DBUS_SESSION_BUS_ADDRESS is suppressed", async () => {
      const tenant = join(home, "no-dbus");
      trackTenant(tenant);

      const savedDbus = process.env.DBUS_SESSION_BUS_ADDRESS;
      const savedDisplay = process.env.DISPLAY;
      // Point at an unreachable bus so secret-tool fails immediately
      // instead of hanging on autolaunch.
      process.env.DBUS_SESSION_BUS_ADDRESS =
        "unix:path=/tmp/sanctuary-test-nonexistent-bus";
      delete process.env.DISPLAY;

      try {
        const result = await persistUserProvidedPassphrase(
          "value-when-no-dbus",
          {
            home,
            storagePath: tenant,
            platformOverride: "linux",
          }
        );
        expect(result.source).toBe("fallback-file");
        expect(result.location).toBe(fallbackFilePath(home, tenant));
        expect(isOsKeyringLocation(result.location)).toBe(false);

        // The fallback file actually exists on disk after the fall-through.
        await access(fallbackFilePath(home, tenant));
      } finally {
        if (savedDbus !== undefined) {
          process.env.DBUS_SESSION_BUS_ADDRESS = savedDbus;
        } else {
          delete process.env.DBUS_SESSION_BUS_ADDRESS;
        }
        if (savedDisplay !== undefined) {
          process.env.DISPLAY = savedDisplay;
        }
      }
    });
  }
);
