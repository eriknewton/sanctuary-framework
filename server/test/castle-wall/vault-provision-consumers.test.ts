/**
 * Every surface that reports on the Castle Wall carries THIS VAULT's own wall
 * state, and none of them presents a not-yet-walled vault as protected.
 *
 * Why a test per surface rather than one on the shared derivation: the
 * derivation was already correct and shared. What was missing was WIRING, and a
 * missing wire is invisible from the derivation's own tests — each consumer
 * kept returning a plausible verdict about the MACHINE while saying nothing
 * about the vault. On a Mac an earlier install armed, that reads as protection
 * for a vault that is on no wall at all.
 *
 * Isolation: every fortress is a per-test temp directory. Nothing here reads or
 * writes the real machine-wide anchor, the operator's login keychain, or a real
 * `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CASTLE_WALL_NOT_YET_WALLED,
  castleWallProvisionRecordPath,
} from "../../src/castle-wall/provision-state.js";
import { evaluateCastleWall } from "../../src/health/evidence.js";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { generateSHR } from "../../src/shr/generator.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { defaultConfig } from "../../src/config.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";

async function claimingFortress(root: string, name: string): Promise<string> {
  const fortressPath = join(root, name);
  await mkdir(join(fortressPath, "state", "_meta"), { recursive: true, mode: 0o700 });
  await writeFile(castleWallProvisionRecordPath(fortressPath), CASTLE_WALL_NOT_YET_WALLED, {
    mode: 0o600,
  });
  return fortressPath;
}

/**
 * Reach into the private production resolver
 * (`principal-policy/dashboard.ts:resolveVaultProvisionClaimed`, Codex lens A
 * round 2's fix location #1) exactly the way `test/principal-policy/
 * dashboard.test.ts` reaches into other private dashboard internals — a real
 * `DashboardApprovalChannel` instance, `_sanctuaryConfig` set directly, no HTTP
 * server started. This proves the FIX AT ITS OWN LINE, not just at the
 * abstracted `AggregatorSources`/`PostureRouteDeps` boolean-injection seam the
 * other describe blocks in this file exercise (which cannot see this specific
 * regression: they inject the boolean already-collapsed).
 */
function resolverFor(storagePath: string): () => Promise<boolean> {
  const dashboard = new DashboardApprovalChannel({
    port: 0,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auto_deny: true,
  });
  (dashboard as unknown as { _sanctuaryConfig: { storage_path: string } })._sanctuaryConfig = {
    storage_path: storagePath,
  } as unknown as { storage_path: string };
  return () =>
    (
      dashboard as unknown as { resolveVaultProvisionClaimed(): Promise<boolean> }
    ).resolveVaultProvisionClaimed();
}

describe("the production resolver reads unreadable evidence as claimed, never as absent", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-vault-resolver-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  async function fortressWithRecord(
    name: string,
    content: string | null,
  ): Promise<string> {
    const fortressPath = join(tmp, name);
    await mkdir(join(fortressPath, "state", "_meta"), { recursive: true, mode: 0o700 });
    if (content !== null) {
      await writeFile(castleWallProvisionRecordPath(fortressPath), content, { mode: 0o600 });
    }
    return fortressPath;
  }

  it("absent (no record ever written) reads as unclaimed — the legacy pass-through", async () => {
    const fortressPath = await fortressWithRecord("absent", null);
    await expect(resolverFor(fortressPath)()).resolves.toBe(false);
  });

  it("the current not_yet_walled claim reads as claimed", async () => {
    const fortressPath = await fortressWithRecord("intact", CASTLE_WALL_NOT_YET_WALLED);
    await expect(resolverFor(fortressPath)()).resolves.toBe(true);
  });

  it("an EMPTY record (exists, zero bytes) reads as claimed, not as absent", async () => {
    // The exact Codex lens A round 2 counterexample: an emptied marker file
    // used to collapse to the same `false` as a genuinely absent one.
    const fortressPath = await fortressWithRecord("empty", "");
    await expect(resolverFor(fortressPath)()).resolves.toBe(true);
  });

  it("an unparseable record (garbage bytes) reads as claimed, not as absent", async () => {
    const fortressPath = await fortressWithRecord("garbage", "\x00\x01\xff not json at all {{{");
    await expect(resolverFor(fortressPath)()).resolves.toBe(true);
  });

  it("a wrong-type record (a recognizable but non-current token) reads as claimed, not as absent", async () => {
    const fortressPath = await fortressWithRecord("wrong-type", "walled");
    await expect(resolverFor(fortressPath)()).resolves.toBe(true);
  });
});

// NOTE (release/1.8.6 branch): the "MCP health and attestation carry the
// vault claim on macOS" describe block that lived here is intentionally
// dropped from this cherry-pick. It exercises castleWallSnapshotForHealthReport
// in server/src/health/castle-wall-detector.ts, a module introduced by the
// Linux Castle Wall reconstruction (#1398), which this release branch does not
// carry (base 913fa8b9 predates it).

describe("the dashboard snapshot never shows a not-yet-walled vault as protected", () => {
  function sources(
    resolveVaultProvisionClaimed?: () => Promise<boolean>,
  ): AggregatorSources {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    return {
      mode: "co-located",
      server_version: "test",
      auditLog,
      platform: "darwin",
      ...(resolveVaultProvisionClaimed ? { resolveVaultProvisionClaimed } : {}),
    } as AggregatorSources;
  }

  it("carries the claim onto the snapshot and keeps the light off green", async () => {
    const claimed = await getProtectionSnapshot(sources(async () => true));
    expect(claimed.castle_wall_provision).toBe(CASTLE_WALL_NOT_YET_WALLED);
    expect(claimed.overall.light).not.toBe("green");

    // A fortress with no claim renders exactly what it rendered before.
    const unclaimed = await getProtectionSnapshot(sources());
    expect(unclaimed).not.toHaveProperty("castle_wall_provision");
  });

  it("treats a resolver that throws as a claim-read FAILURE — fail closed, never as an absent claim", async () => {
    // Codex lens A round 2 (2026-09-10): the prior fallback (`false`, "no
    // claim") let a throwing resolver render exactly like a genuinely absent
    // one. A read that failed is not a read that found nothing, and must
    // never be indistinguishable from protection.
    const thrown = await getProtectionSnapshot(
      sources(async () => {
        throw new Error("injected claim-read failure");
      }),
    );
    expect(thrown.overall.light).not.toBe("green");
    expect(thrown.castle_wall_provision).toBe(CASTLE_WALL_NOT_YET_WALLED);
  });
});

describe("the browser surfaces render the vault claim beside the machine wall", () => {
  it("gives the posture home page its own vault line", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain('w.castle_wall_provision === "not_yet_walled"');
    expect(html).toContain("this vault is not on the wall above");
  });

  it("gives the v1.1 console its own vault line", () => {
    const script = getClientScript();
    expect(script).toContain("home.castle_wall.castle_wall_provision");
    expect(script).toContain("not on this Mac");
  });
});

describe("a signed, published report never omits a not-yet-walled vault", () => {
  /** Minimal identity manager the generator can actually sign with. */
  function signingIdentityManager(masterKey: Uint8Array): {
    manager: never;
  } {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "vault-provision-shr",
      encKey,
      "recovery-key",
    );
    const identities = new Map([[publicIdentity.identity_id, storedIdentity]]);
    return {
      manager: {
        get: (id: string) => identities.get(id),
        getDefault: () => identities.get(publicIdentity.identity_id),
        list: () => [...identities.values()],
      } as never,
    };
  }

  it("emits an L2 degradation naming the gap, inside the signed body", () => {
    // The SHR body is a versioned-frozen v1.0 schema external counterparties
    // parse, so the honest subtraction is carried in the degradations array the
    // schema already provides rather than by adding a body field to it. It is
    // inside the SIGNED body either way, which is the point: this is the one
    // surface where over-claiming leaves the machine under a signature.
    const masterKey = generateRandomKey();
    const { manager } = signingIdentityManager(masterKey);
    const shr = generateSHR(undefined, {
      config: defaultConfig(),
      identityManager: manager,
      masterKey,
      vaultProvision: CASTLE_WALL_NOT_YET_WALLED,
    }) as SignedSHR;

    const entry = shr.body.degradations.find(
      (d) => d.code === "VAULT_NOT_ON_CASTLE_WALL",
    );
    expect(entry).toBeDefined();
    expect(entry!.layer).toBe("l2");
    expect(entry!.description).toContain("not on this machine's Castle Wall");
    expect(entry!.mitigation).toBeTruthy();
  });

  it("says nothing extra for a fortress that carries no claim", () => {
    const masterKey = generateRandomKey();
    const { manager } = signingIdentityManager(masterKey);
    const shr = generateSHR(undefined, {
      config: defaultConfig(),
      identityManager: manager,
      masterKey,
    }) as SignedSHR;
    expect(
      shr.body.degradations.some((d) => d.code === "VAULT_NOT_ON_CASTLE_WALL"),
    ).toBe(false);
  });
});


// NOTE (release/1.8.6 branch): the "the externally published reputation
// payload carries the vault claim" describe block that lived here is
// intentionally dropped from this cherry-pick. The evidence that feeds
// reputation_publish's auto-generated SHR only carries a vault_provision
// claim when server/src/reputation/tools.ts wires a CastleWallRuntimeSnapshot
// into buildHealthEvidenceReport via castleWallSnapshotForHealthReport in
// server/src/health/castle-wall-detector.ts, a module introduced by the
// Linux Castle Wall reconstruction (#1398), which this release branch does
// not carry (base 913fa8b9 predates it). On this branch that call site never
// receives a castleWall snapshot, so the published payload never carries
// castle_wall_provision either way.
