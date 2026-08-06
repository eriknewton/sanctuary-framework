/**
 * Real Secret Service verification, OUTSIDE the test suite.
 *
 * ── WHY THIS IS NOT A VITEST FILE ───────────────────────────────────────
 *
 * It used to be `test/keychain-linux-real-backend-integration.test.ts`, which
 * had to remove the in-memory credential store to reach a genuine `secret-tool`.
 * A vitest file that can remove the credential isolation is a loaded weapon
 * inside the suite everyone runs: whatever gates it, the CAPABILITY is present
 * on every machine, and three successive attempts to gate it correctly each
 * shipped a check weaker than its claim (a bare env var; a nonce that only
 * proved some Secret Service answered; a socket-path shape an ordinary
 * `dbus-launch` produces; and then `GITHUB_ACTIONS=true`, which `act` sets too).
 *
 * So the capability is gone rather than guarded. `setKeychainExec` can no longer
 * be un-set, there is no allow-real opt-in, and under vitest the chokepoint has
 * exactly two outcomes: the fake serves the call, or it throws. This file is how
 * the real shell-out still gets exercised, and it runs as a plain node process
 * where spawning the credential CLI is simply normal behavior, not an escape.
 *
 * ── WHAT THIS COVERS, AND WHAT ALREADY COVERED IT ───────────────────────
 *
 * `test/keychain-linux-secret-service.test.ts` remains authoritative for
 * unit-level behavior and proves the degrade path with an injected
 * `storeFailure`, on every platform, in ordinary CI. This script is NOT the only
 * coverage of these behaviors. What it adds is confirmation against the real
 * libsecret/D-Bus stack: binary path, exit-code semantics, stdin handling, and
 * attribute serialization, which a mock cannot see drift in.
 *
 * ── FAILURE MODES ───────────────────────────────────────────────────────
 *
 * Every check throws on failure and the process exits non-zero. The count is
 * asserted against EXPECTED_CHECKS below, so a check that silently stops running
 * fails here rather than shrinking the covered surface unnoticed. The final
 * marker line is what the workflow greps for: a script that dies before printing
 * it, or never runs at all, must not look like a pass.
 *
 * Run: `npx tsx scripts/real-backend-check.ts` from `server/`, on Linux, with a
 * Secret Service on the session bus. Invoked by
 * `.github/workflows/keychain-linux-real-backend.yml`.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, accessSync } from "node:fs";
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

/**
 * Number of checks below. Asserted at the end so a check that stops running is a
 * failure, not a quiet reduction in coverage. Unlike the vitest arrangement this
 * replaces, the number and the checks live in ONE file, so they cannot drift.
 */
const EXPECTED_CHECKS = 5;

const MARKER = "REAL_BACKEND_CHECKS_PASSED";

let checksRun = 0;
const touchedServices: string[] = [];

function check(name: string, fn: () => Promise<void>): () => Promise<void> {
  return async () => {
    process.stdout.write(`  - ${name} ... `);
    await fn();
    checksRun += 1;
    process.stdout.write("ok\n");
  };
}

/** Remove an entry from the live keyring. Best effort; the runner is ephemeral. */
function clearKeyringEntry(service: string): void {
  spawnSync("secret-tool", ["clear", "service", service, "account", "sanctuary"], {
    stdio: "ignore",
  });
}

function withTempHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
  const home = mkdtempSync(join(tmpdir(), "sanctuary-real-backend-"));
  return fn(home).finally(() => {
    rmSync(home, { recursive: true, force: true, maxRetries: 5 });
  });
}

function trackTenant(tenantPath: string, home: string): void {
  touchedServices.push(keychainServiceFor(tenantPath, home));
}

// ── Checks ──────────────────────────────────────────────────────────────

const roundTrip = check(
  "getOrCreatePassphrase writes to the real Secret Service, then reads it back",
  async () =>
    withTempHome(async (home) => {
      const tenant = join(home, "round-trip");
      trackTenant(tenant, home);

      const first = await getOrCreatePassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      assert.equal(first.source, "generated");
      assert.equal(first.location, OS_KEYRING_LOCATION_LINUX);
      assert.equal(isOsKeyringLocation(first.location), true);
      assert.ok(first.value.length > 0, "generated passphrase must not be empty");

      const second = await getOrCreatePassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      assert.equal(second.source, "keychain");
      assert.equal(second.location, OS_KEYRING_LOCATION_LINUX);
      assert.equal(second.value, first.value);
    })
);

const persistReadBack = check(
  "persistUserProvidedPassphrase round-trips a known value",
  async () =>
    withTempHome(async (home) => {
      const tenant = join(home, "persist-readback");
      trackTenant(tenant, home);
      const stored = `test-passphrase-real-backend-${Date.now()}`;

      const persisted = await persistUserProvidedPassphrase(stored, {
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      assert.equal(persisted.source, "keychain");
      assert.equal(persisted.location, OS_KEYRING_LOCATION_LINUX);

      const read = await readStoredPassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      assert.notEqual(read, null);
      assert.equal(read!.source, "keychain");
      assert.equal(read!.value, stored);
    })
);

const absentIsNull = check(
  "readStoredPassphrase returns null for a storage path never written",
  async () =>
    withTempHome(async (home) => {
      const tenant = join(home, "never-written");
      trackTenant(tenant, home);

      const result = await readStoredPassphrase({
        home,
        storagePath: tenant,
        platformOverride: "linux",
      });
      assert.equal(result, null);
    })
);

const tenantIsolation = check(
  "two storage paths get distinct entries in the real keyring",
  async () =>
    withTempHome(async (home) => {
      const alpha = join(home, "tenant-alpha");
      const beta = join(home, "tenant-beta");
      trackTenant(alpha, home);
      trackTenant(beta, home);

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
      assert.notEqual(a.value, b.value);
      assert.equal(a.source, "generated");
      assert.equal(b.source, "generated");

      // Reading B back must surface B's value, never A's. This is what proves the
      // per-tenant service-name suffix disambiguates at the libsecret attribute
      // layer and not merely in a mock's map.
      const reReadB = await getOrCreatePassphrase({
        home,
        storagePath: beta,
        platformOverride: "linux",
      });
      assert.equal(reReadB.source, "keychain");
      assert.equal(reReadB.value, b.value);
      assert.notEqual(reReadB.value, a.value);
    })
);

const degradeToFallback = check(
  "degrades to the encrypted fallback file when the session bus is unreachable",
  async () =>
    withTempHome(async (home) => {
      const tenant = join(home, "no-dbus");
      trackTenant(tenant, home);

      // Production behavior (passphrase.ts): every Secret Service failure mode
      // (binary missing, no bus, daemon refusal, user cancel) falls through to
      // the encrypted fallback file rather than throwing. Invariant 5 holds
      // because that file is authenticated encryption under a machine-local HKDF
      // key, so this is not a silent downgrade to plaintext.
      //
      // This is the check a stubbed credential store could never fake, because a
      // stub answers the same whether or not D-Bus is reachable. Against the real
      // backend it is the one that notices a dead bus.
      const savedDbus = process.env.DBUS_SESSION_BUS_ADDRESS;
      const savedDisplay = process.env.DISPLAY;
      // Point at an unreachable bus so secret-tool fails immediately rather than
      // hanging on autolaunch.
      process.env.DBUS_SESSION_BUS_ADDRESS =
        "unix:path=/tmp/sanctuary-real-backend-nonexistent-bus";
      delete process.env.DISPLAY;

      try {
        const result = await persistUserProvidedPassphrase("value-when-no-dbus", {
          home,
          storagePath: tenant,
          platformOverride: "linux",
        });
        assert.equal(result.source, "fallback-file");
        assert.equal(result.location, fallbackFilePath(home, tenant));
        assert.equal(isOsKeyringLocation(result.location), false);
        // Assert the postcondition on disk, not just the returned label.
        accessSync(fallbackFilePath(home, tenant));
      } finally {
        if (savedDbus !== undefined) {
          process.env.DBUS_SESSION_BUS_ADDRESS = savedDbus;
        } else {
          delete process.env.DBUS_SESSION_BUS_ADDRESS;
        }
        if (savedDisplay !== undefined) process.env.DISPLAY = savedDisplay;
      }
    })
);

// ── Runner ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  if (process.platform !== "linux") {
    throw new Error(
      `real-backend-check is Linux-only (this is ${process.platform}). It is invoked by ` +
        `.github/workflows/keychain-linux-real-backend.yml against a provisioned Secret Service.`
    );
  }
  if (!process.env.DBUS_SESSION_BUS_ADDRESS) {
    throw new Error(
      "DBUS_SESSION_BUS_ADDRESS is not set: there is no session bus to talk to. " +
        "Refusing to run, because every check would degrade to the fallback file and " +
        "four of the five would pass while proving nothing about libsecret."
    );
  }

  console.log("real-backend-check: exercising the production secret-tool path");
  try {
    await roundTrip();
    await persistReadBack();
    await absentIsNull();
    await tenantIsolation();
    await degradeToFallback();
  } finally {
    for (const service of touchedServices) clearKeyringEntry(service);
  }

  assert.equal(
    checksRun,
    EXPECTED_CHECKS,
    `expected ${EXPECTED_CHECKS} checks to run, ran ${checksRun}`
  );
  console.log(`${MARKER}=${checksRun}`);
}

main().catch((err: unknown) => {
  console.error(`real-backend-check FAILED: ${(err as Error).message}`);
  console.error((err as Error).stack ?? "");
  process.exitCode = 1;
});
