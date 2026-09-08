/**
 * A stray OS-keyring custody item must not shadow the credential a
 * PRE-ENVELOPE (legacy) fortress is actually opened with.
 *
 * Capability under test: on a fortress created before custody envelopes
 * (`_meta/key-params`, master = Argon2id(passphrase, params)), the shared
 * resolver (`wrap/custody-credential.ts`) skips a `sanctuary-custody-<id>`
 * keyring item it cannot authenticate and resolves the stored passphrase
 * instead, so both boots and `protect` open the fortress; and a legacy
 * fortress with ONLY that item still refuses rather than minting.
 *
 * WHY IT FAILED BEFORE THE FIX: with no envelope there is nothing to verify a
 * candidate against, so every host-local candidate was taken AS-IS in
 * resolution order. The enrolled custody key comes first, so a stale item (a
 * removed fortress, an `init` that failed after enrolling) or a planted one
 * was selected, the stored passphrase was never consulted, and custody
 * establishment then refused because legacy migration needs the passphrase.
 * The fortress was openable the whole time.
 *
 * Every keyring read and write here goes through the wrap keychain chokepoint,
 * which the suite serves from the in-memory store (test/setup/keychain-fake.ts):
 * no `security` / `secret-tool` subprocess runs, and the operator's login
 * keychain and real `~/.sanctuary` are never touched. Each test gets its own
 * temporary HOME and fortress.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  custodyCredentialRefusal,
  HOST_LOCAL_CUSTODY_SOURCES,
  resolveFortressCustodyCredential,
} from "../../src/wrap/custody-credential.js";
import { readCustodyEnvelope } from "../../src/core/master-custody.js";
import { getOrCreateKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";
import { createSanctuaryServer } from "../../src/index.js";
import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  deriveMasterKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { constantTimeEqual, stringToBytes } from "../../src/core/encoding.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import { bindWithRetry, randomTestPort } from "../util/port-collision-retry.js";

const LEGACY_PASSPHRASE = "legacy-fortress-passphrase-not-a-real-secret";
const DASHBOARD_TOKEN = "legacy-stray-custody-dashboard-token-not-a-secret";

/**
 * Seed the pre-envelope fortress shape: `_meta/key-params` plus one identity
 * encrypted under the derived master.
 *
 * The identity is not decoration. Legacy migration verifies the supplied
 * passphrase against existing ciphertext before it captures a master into an
 * envelope, so a fortress with no such evidence would migrate on ANY
 * passphrase and this suite would prove nothing about which credential opened
 * it. Returns the legacy master so a boot's master can be compared to it.
 *
 * FAILURE MODE, from the outside: seed this against a storage backend the boot
 * does not use and the boot sees a virgin directory, mints, and "passes" for
 * the wrong reason. The dashboard reads `<storagePath>/state` on the real
 * filesystem; the MCP boot reads the backend it is handed.
 */
async function seedLegacyPassphraseFortress(
  storage: StorageBackend,
  passphrase: string,
): Promise<Uint8Array> {
  const { key: master, params } = await deriveMasterKey(passphrase);
  await storage.write(
    "_meta",
    "key-params",
    stringToBytes(JSON.stringify(params)),
  );
  const identityKey = derivePurposeKey(master, "identity-encryption");
  const manager = new IdentityManager(storage, master);
  await manager.load();
  const { storedIdentity } = createIdentity(
    "legacy-seed",
    identityKey,
    "passphrase",
  );
  await manager.save(storedIdentity);
  return master;
}

describe("a stray keyring custody item never shadows a legacy fortress's passphrase", () => {
  let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
  let fortress: string;
  let dashboard: DashboardApprovalChannel | null = null;

  beforeEach(async () => {
    fortressHome = await createTempHome("sanctuary-legacy-stray-custody");
    fortress = fortressHome.defaultFortressPath;
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    // The boot notices are operator-facing chatter here, not the assertion.
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop().catch(() => undefined);
      dashboard = null;
    }
    vi.restoreAllMocks();
    await fortressHome.cleanup();
  });

  /** Put a `sanctuary-custody-<id>` item for THIS fortress on the host. */
  async function plantStrayCustodyItem(): Promise<void> {
    const planted = await getOrCreateKeychainCustodyKey(fortress);
    if (!planted) throw new Error("test keyring did not yield a custody key");
    // Nothing here holds the bytes: the point is only that the ITEM exists.
    planted.fill(0);
  }

  it("resolves the stored passphrase and reports the item as present but unverifiable", async () => {
    // FAILS BEFORE THE FIX: with no envelope the resolver took the first
    // present host-local candidate as-is, and the enrolled custody key is
    // tried first, so `source` was "enrolled-custody-key" here.
    const storage = new FilesystemStorage(join(fortress, "state"));
    await seedLegacyPassphraseFortress(storage, LEGACY_PASSPHRASE);
    await plantStrayCustodyItem();
    await persistUserProvidedPassphrase(LEGACY_PASSPHRASE, {
      storagePath: fortress,
    });

    const resolution = await resolveFortressCustodyCredential({
      storagePath: fortress,
      allow: HOST_LOCAL_CUSTODY_SOURCES,
      allowMint: false,
    });

    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("stored-passphrase");
    // Present, skipped, and named as such: absent, unverifiable and rejected
    // are three different answers to an operator.
    expect(resolution.report.found).toContain("enrolled-custody-key");
    expect(resolution.report.indeterminate).toContain("enrolled-custody-key");
    expect(resolution.report.rejected).not.toContain("enrolled-custody-key");
    expect(resolution.report.custodyKeyUnverifiable).toBe(true);
    // The FORTRESS is fine. Saying otherwise would send the operator to
    // restore custody state that is not damaged.
    expect(resolution.report.integrityIndeterminate).toBe(false);
  }, 60_000);

  it("refuses with the remedy that matches the state when the item is all there is", async () => {
    // FAILS BEFORE THE FIX: the item resolved, so there was no refusal at all
    // at this layer; the run failed later, inside custody establishment, with
    // a message about a credential the operator never chose.
    const storage = new FilesystemStorage(join(fortress, "state"));
    await seedLegacyPassphraseFortress(storage, LEGACY_PASSPHRASE);
    await plantStrayCustodyItem();

    const resolution = await resolveFortressCustodyCredential({
      storagePath: fortress,
      allow: HOST_LOCAL_CUSTODY_SOURCES,
      allowMint: false,
    });
    expect(resolution.status).toBe("unresolved");
    expect(resolution.report.custodyKeyUnverifiable).toBe(true);

    const refusal = custodyCredentialRefusal(resolution.report, fortress);
    expect(refusal.message).toContain("before custody envelopes");
    expect(refusal.message).toContain("is not a credential for it");
    // The keyring answered fine and the custody state is intact, so neither of
    // the other two remedies may appear.
    expect(refusal.message).not.toContain("Unlock the OS keyring and retry");
    expect(refusal.message).not.toContain("Restore this fortress's custody state");
    // Never a value.
    expect(refusal.message).not.toContain(LEGACY_PASSPHRASE);
  }, 60_000);

  it("the standalone dashboard boots on the stored passphrase with the item present", async () => {
    // The reported shape: before #1394 this boot used the stored passphrase
    // and worked; routing it through the shared resolver made the stray item
    // win and the boot refused.
    //
    // FAILS BEFORE THE FIX: `Encrypted identities found but NONE loaded` /
    // custody-migration refusal, because establishment received 32 keyring
    // bytes for a fortress whose master is derived from the passphrase.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const legacyMaster = await seedLegacyPassphraseFortress(
      storage,
      LEGACY_PASSPHRASE,
    );
    await plantStrayCustodyItem();
    await persistUserProvidedPassphrase(LEGACY_PASSPHRASE, {
      storagePath: fortress,
    });

    const started = await bindWithRetry(async () => {
      const port = randomTestPort();
      const channel = await startStandaloneDashboard({
        storagePath: fortress,
        discoveryOptions: { home: fortressHome.home, root: fortress },
        host: "127.0.0.1",
        authToken: DASHBOARD_TOKEN,
        distressPort: 0,
        port,
      });
      return { channel, port };
    });
    dashboard = started.channel;

    // Genuinely unlocked, not parked: a protected route answers, which needs
    // the master-key-derived dependencies to have been wired.
    const res = await fetch(`http://127.0.0.1:${started.port}/api/status`, {
      headers: { Authorization: `Bearer ${DASHBOARD_TOKEN}` },
    });
    expect(res.status).toBe(200);

    // It opened the LEGACY master, so it migrated this fortress in place
    // rather than deriving a parallel one.
    const envelope = await readCustodyEnvelope(storage);
    expect(envelope).not.toBeNull();
    const reader = new IdentityManager(storage, legacyMaster);
    const loaded = await reader.load();
    expect(loaded.loaded).toBeGreaterThanOrEqual(1);
    legacyMaster.fill(0);
  }, 120_000);

  it("the MCP stdio boot opens the same fortress with the same credential", async () => {
    // One resolver, two boots: a fortress the dashboard opens is one
    // `createSanctuaryServer` opens, on identical host state.
    const storage = new MemoryStorage();
    const legacyMaster = await seedLegacyPassphraseFortress(
      storage,
      LEGACY_PASSPHRASE,
    );
    await plantStrayCustodyItem();
    await persistUserProvidedPassphrase(LEGACY_PASSPHRASE, {
      storagePath: fortress,
    });

    const server = await createSanctuaryServer({ storage });
    try {
      expect(constantTimeEqual(server.masterKey, legacyMaster)).toBe(true);
    } finally {
      await server.cleanup();
      legacyMaster.fill(0);
    }
  }, 120_000);

  it("the MCP boot on a legacy fortress with ONLY the stray item refuses with that remedy, and mints nothing", async () => {
    // The other half of the fix: skipping an unverifiable item must not turn
    // into inventing custody. This fortress has a master already, so a mint
    // would derive a parallel one over live data.
    //
    // FAILS BEFORE THE ROUND-2 FIX: the boot adapter returned `virgin` for any
    // fortress with no ENVELOPE, so a legacy fortress fell through to
    // `establishMaster`'s first run and refused one layer down with the
    // generic "passphrase required" text. It did throw and it did not mint, so
    // the bare `rejects.toThrow()` this test used to carry passed against main
    // and proved nothing; these assertions are what the pre-fix boot cannot
    // satisfy, because the resolver's refusal never reached the operator.
    const storage = new MemoryStorage();
    const legacyMaster = await seedLegacyPassphraseFortress(
      storage,
      LEGACY_PASSPHRASE,
    );
    legacyMaster.fill(0);
    await plantStrayCustodyItem();

    const refusal = await createSanctuaryServer({ storage }).then(
      async (server) => {
        // A boot that SUCCEEDS here has minted over live pre-envelope data;
        // reap it before failing so the assertion below is the failure.
        await server.cleanup().catch(() => undefined);
        return null;
      },
      (err: unknown) => (err instanceof Error ? err.message : String(err)),
    );
    expect(refusal).not.toBeNull();
    // Present, named, and not called a mismatch or a damaged fortress.
    expect(refusal).toContain(
      "Present but unusable right now: the OS-keyring custody factor enrolled for this fortress",
    );
    expect(refusal).toContain("before custody envelopes");
    expect(refusal).toContain("SANCTUARY_PASSPHRASE or --passphrase");
    expect(refusal).not.toContain("Unlock the OS keyring and retry");
    expect(refusal).not.toContain("Restore this fortress's custody state");

    // The resolver's own account of this host, so the refusal above is read
    // against the state that produced it rather than trusted as prose.
    const resolution = await resolveFortressCustodyCredential({
      storagePath: fortress,
      storage,
      allow: HOST_LOCAL_CUSTODY_SOURCES,
      allowMint: false,
    });
    expect(resolution.status).toBe("unresolved");
    expect(resolution.report.custodyKeyUnverifiable).toBe(true);
    // A legacy marker IS custody state: reading `!envelopePresent` as "virgin"
    // is precisely the mapping this round removed.
    expect(resolution.report.envelopePresent).toBe(false);
    expect(resolution.report.noCustodyStateAtAll).toBe(false);

    // No envelope was written: nothing created custody behind the refusal.
    expect(await readCustodyEnvelope(storage)).toBeNull();
  }, 120_000);

  it("the dashboard boot on the same fortress refuses with the same remedy, and mints nothing", async () => {
    // The second boot path has to print the same remedy on the same host
    // state, or `protect --claude-code --agent-guided` (which spawns this one)
    // sends the operator somewhere else than the MCP boot does.
    //
    // FAILS BEFORE THE ROUND-2 FIX: the adapter answered `virgin`, so this
    // boot never received a report to fold into its diagnostic
    // (`hostLocalReport` stayed undefined and the accepted-sources block was
    // empty), and the operator saw only the generic establishment refusal.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const legacyMaster = await seedLegacyPassphraseFortress(
      storage,
      LEGACY_PASSPHRASE,
    );
    legacyMaster.fill(0);
    await plantStrayCustodyItem();

    const refusal = await startStandaloneDashboard({
      storagePath: fortress,
      discoveryOptions: { home: fortressHome.home, root: fortress },
      host: "127.0.0.1",
      authToken: DASHBOARD_TOKEN,
      distressPort: 0,
      // Never bound: custody refuses before the HTTP server is created, so no
      // listener can leak out of this test.
      port: 0,
    }).then(
      async (channel) => {
        await channel.stop().catch(() => undefined);
        return null;
      },
      (err: unknown) => (err instanceof Error ? err.message : String(err)),
    );
    expect(refusal).not.toBeNull();
    expect(refusal).toContain(
      "Present but unusable right now: the OS-keyring custody factor enrolled for this fortress",
    );
    expect(refusal).toContain("before custody envelopes");
    expect(refusal).toContain("SANCTUARY_PASSPHRASE or --passphrase");
    expect(refusal).not.toContain("Unlock the OS keyring and retry");
    // Never a value, on either boot path.
    expect(refusal).not.toContain(LEGACY_PASSPHRASE);

    expect(await readCustodyEnvelope(storage)).toBeNull();
  }, 120_000);
});
