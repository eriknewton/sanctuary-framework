/**
 * Sanctuary MCP Server — v0.10.4 dashboard tenant-discovery regression tests
 *
 * These tests reproduce the Mini1 field failure that v0.10.2 shipped a
 * "fix" for but did not actually resolve: `sanctuary dashboard` against a
 * default root that holds orphan identity .enc files (or no state at all)
 * while sub-tenants exist under the same root with their own per-tenant
 * keychain entries. Pre-v0.10.4 the dashboard either threw a misleading
 * "set SANCTUARY_PASSPHRASE" error or silently fresh-installed a new
 * recovery key over the default root.
 *
 * The acceptance shape is **not a handshake mock**: every test creates real
 * identity .enc files via the same `IdentityManager` + AES-256-GCM path the
 * production code uses, persists per-tenant passphrases via
 * `persistUserProvidedPassphrase` exactly the way `sanctuary wrap` does, and
 * boots `startStandaloneDashboard` with no production-path overrides. The
 * v0.10.2 regression test mocked the keychain shape and the dashboard's code
 * matched the mock — that test passed but the real-world boot still failed.
 * These tests fail without the v0.10.4 patch and pass with it.
 */
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  startStandaloneDashboard,
  discoverableSubTenants,
  renderTenantDiscoveryHint,
} from "../src/dashboard-standalone.js";
import { persistUserProvidedPassphrase } from "../src/cocoon/passphrase.js";
import { IdentityManager } from "../src/l1-cognitive/tools.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../src/core/key-derivation.js";
import { createIdentity } from "../src/core/identity.js";
import { stringToBytes } from "../src/core/encoding.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";

function randomPort(): number {
  return 14000 + Math.floor(Math.random() * 30000);
}

/**
 * Real seeding helper. Mirrors `sanctuary wrap`'s on-disk shape: persisted
 * passphrase via `persistUserProvidedPassphrase`, persisted Argon2id params,
 * one or more identity .enc files written through the production
 * `IdentityManager`. No mocks.
 */
async function seedTenant(
  storagePath: string,
  passphrase: string,
  identityCount: number,
  options: { persistPassphrase: boolean } = { persistPassphrase: true }
): Promise<void> {
  await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
  if (options.persistPassphrase) {
    await persistUserProvidedPassphrase(passphrase, {
      storagePath,
      platformOverride: "linux",
      // Force fallback-file path even on Linux hosts with Secret Service
      // running. Without this, a test run on a developer's Linux machine
      // with gnome-keyring active would write the test passphrase into the
      // real Secret Service and pollute the user's keyring. Returning code
      // 1 from the injected exec causes writeToSecretService() to treat the
      // attempt as failed and fall through to the encrypted fallback file.
      exec: async () => ({ stdout: "", stderr: "", code: 1 }),
    });
  }
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const { key: mk, params } = await deriveMasterKey(passphrase);
  await storage.write(
    "_meta",
    "key-params",
    stringToBytes(JSON.stringify(params))
  );
  const idEncKey = derivePurposeKey(mk, "identity-encryption");
  const mgr = new IdentityManager(storage, mk);
  await mgr.load();
  for (let i = 0; i < identityCount; i++) {
    const { storedIdentity } = createIdentity(
      `seeded-${i}`,
      idEncKey,
      "passphrase"
    );
    await mgr.save(storedIdentity);
  }
}

describe("v0.10.4: standalone dashboard discovers wrapped sub-tenants", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let root: string;
  let originalHome: string | undefined;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-v010-4-"));
    process.env.VITEST = "true";
    // Override HOME so discoverTenants() does not scan the developer's real
    // ~/.sanctuary (which on a developer machine includes a "default"
    // tenant and breaks the assertion below). CI runners have no
    // ~/.sanctuary so the assertion held there even without this override;
    // local runs against a wrapped Sanctuary install previously failed.
    originalHome = process.env.HOME;
    process.env.HOME = root;
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
    await rm(root, { recursive: true, force: true }).catch(() => {});
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    if (originalHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = originalHome;
    }
  });

  it("discoverableSubTenants() returns initialized tenants under the discovery root, excluding the configured path", async () => {
    await seedTenant(join(root, "alpha"), "alpha-pass", 1);
    await seedTenant(join(root, "beta"), "beta-pass", 1);
    // Pass an isolated discovery scope rooted at the temp dir so the test
    // never reads from the developer's real ~/.sanctuary/. Without this,
    // a developer machine that has run `sanctuary wrap` for real surfaces
    // its own "default" tenant and the not-toContain("default") assertion
    // below fails — bites local commits even though CI passes on fresh
    // runners. The configured currentStoragePath is `root` itself, which
    // is the parent of the seeded tenants and not initialized as a tenant
    // on its own, so it is correctly excluded by both the `initialized`
    // filter and the `currentStoragePath` filter.
    const found = await discoverableSubTenants(root, {
      root,
      home: root,
      env: {},
    });
    const names = found.map((t) => t.name).sort();
    expect(Array.isArray(found)).toBe(true);
    expect(names).toEqual(["alpha", "beta"]);
    expect(names).not.toContain("default"); // never includes the configured path
  });

  it("renderTenantDiscoveryHint() formats one-tenant guidance with --tenant <name>", () => {
    const out = renderTenantDiscoveryHint([
      {
        name: "alpha",
        storage_path: "/tmp/x/alpha",
        exists: true,
        initialized: true,
        has_cocoon_profile: false,
        keychain_service: "sanctuary-passphrase-aaaaaaaaaaaa",
        passphrase_status: "fallback-file",
        last_activity: null,
        runtime: null,
      },
    ]);
    expect(out).toMatch(/Detected 1 wrapped tenant/);
    expect(out).toMatch(/sanctuary dashboard --tenant alpha/);
    expect(out).toMatch(/sanctuary-passphrase-aaaaaaaaaaaa/);
    // The misleading legacy hint must never appear.
    expect(out).not.toMatch(/SANCTUARY_PASSPHRASE=/);
  });

  it("renderTenantDiscoveryHint() formats multi-tenant guidance with --tenant + --multi", () => {
    const out = renderTenantDiscoveryHint([
      {
        name: "alpha",
        storage_path: "/tmp/x/alpha",
        exists: true,
        initialized: true,
        has_cocoon_profile: false,
        keychain_service: "sanctuary-passphrase-aaaaaaaaaaaa",
        passphrase_status: "fallback-file",
        last_activity: null,
        runtime: null,
      },
      {
        name: "beta",
        storage_path: "/tmp/x/beta",
        exists: true,
        initialized: true,
        has_cocoon_profile: false,
        keychain_service: "sanctuary-passphrase-bbbbbbbbbbbb",
        passphrase_status: "keychain",
        last_activity: null,
        runtime: null,
      },
    ]);
    expect(out).toMatch(/Detected 2 wrapped tenants/);
    expect(out).toMatch(/sanctuary dashboard --tenant <name>/);
    expect(out).toMatch(/sanctuary dashboard --multi/);
  });

  it("REPRODUCES the Mini1 failure: dashboard against a default root with orphan identity files and no resolvable passphrase throws an actionable error mentioning the storage path", async () => {
    // Plant orphan identity .enc files at the default root via the real
    // production path (no mocks). Do NOT persist the passphrase, so the
    // dashboard cannot resolve it via keychain or fallback file.
    await seedTenant(root, "lost-original-passphrase", 2, {
      persistPassphrase: false,
    });

    delete process.env.SANCTUARY_PASSPHRASE;
    process.env.SANCTUARY_STORAGE_PATH = root;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "v010-4-token";

    let threw: Error | null = null;
    try {
      dashboard = await startStandaloneDashboard({
        port: randomPort(),
        host: "127.0.0.1",
      });
    } catch (err) {
      threw = err as Error;
    }
    expect(threw).not.toBeNull();
    // v0.10.4 actionable error: names the storage path and points at the
    // schema doc; never recommends the misleading single-passphrase fix.
    expect(threw!.message).toMatch(/Existing encrypted data found at /);
    expect(threw!.message).toContain(root);
    expect(threw!.message).toMatch(/keychain-schema\.md/);
  });

  it("--tenant <name> resolves a wrapped tenant by name and boots against its storage path", async () => {
    // Place the tenant in a registered extras path so discovery can find it
    // without requiring it to live under the actual ~/.sanctuary on the
    // test machine (we never want tests writing into the developer's home).
    const tenantPath = join(root, "alpha-tenant");
    await seedTenant(tenantPath, "alpha-real-passphrase", 1);
    process.env.SANCTUARY_AGENTS_EXTRA_PATHS = tenantPath;

    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;

    const port = randomPort();
    dashboard = await startStandaloneDashboard({
      tenant: "alpha-tenant",
      port,
      host: "127.0.0.1",
    });

    // Boot succeeded against the tenant's storage path — confirm by reading
    // /api/status, which only works if the master key derived correctly.
    const res = await fetch(`http://127.0.0.1:${port}/api/status`);
    expect(res.status).toBe(200);

    delete process.env.SANCTUARY_AGENTS_EXTRA_PATHS;
  });

  it("--tenant <name> with no matching tenant throws a clear error listing what IS available", async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;

    let threw: Error | null = null;
    try {
      dashboard = await startStandaloneDashboard({
        tenant: "does-not-exist",
        port: randomPort(),
        host: "127.0.0.1",
      });
    } catch (err) {
      threw = err as Error;
    }
    expect(threw).not.toBeNull();
    expect(threw!.message).toMatch(/--tenant "does-not-exist" did not match/);
    expect(threw!.message).toMatch(/sanctuary agents/);
  });

  it("warning banner replaces the misleading SANCTUARY_PASSPHRASE fix-hint with the schema-doc reference", async () => {
    // Seed default root with one identity under passphrase A, then attempt
    // to boot under passphrase B — encrypted identities exist but cannot
    // decrypt. Banner should fire.
    await seedTenant(root, "passphrase-A", 1);

    process.env.SANCTUARY_STORAGE_PATH = root;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "v010-4-banner-token";

    const logs: string[] = [];
    const origError = console.error;
    console.error = (...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    };

    try {
      dashboard = await startStandaloneDashboard({
        passphrase: "passphrase-B-WRONG",
        port: randomPort(),
        host: "127.0.0.1",
      });
    } finally {
      console.error = origError;
    }

    const banner = logs.join("\n");
    expect(banner).toMatch(/Encrypted identities found but NONE loaded/);
    // Schema doc reference is now the canonical pointer.
    expect(banner).toMatch(/server\/docs\/keychain-schema\.md/);
    // The fix-hint must NOT instruct the user to set SANCTUARY_PASSPHRASE
    // as an environment variable — that was actively misleading on
    // multi-tenant hosts.
    expect(banner).not.toMatch(/SANCTUARY_PASSPHRASE=<your-passphrase>/);
    expect(banner).not.toMatch(/restart with the correct SANCTUARY_PASSPHRASE/);
  });
});
