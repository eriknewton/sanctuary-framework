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
import { castleWallSnapshotForHealthReport } from "../../src/health/castle-wall-detector.js";
import { evaluateCastleWall } from "../../src/health/evidence.js";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import { generateSHR } from "../../src/shr/generator.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { loadConfig } from "../../src/config.js";
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

describe("MCP health and attestation carry the vault claim on macOS", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-vault-consumers-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("attaches the claim on the platform that has no runtime detector", async () => {
    // macOS is where the claim MATTERS and is exactly where the Linux
    // producer-signed detector returns nothing, so before this the field was
    // dropped on the only platform that can carry a Castle Wall today.
    const fortressPath = await claimingFortress(tmp, "macos-vault");
    const snapshot = await castleWallSnapshotForHealthReport({
      config: { storage_path: fortressPath },
      masterKey: new Uint8Array(32),
      overrides: { platform: "darwin" },
    });
    expect(snapshot?.vaultProvision).toBe(CASTLE_WALL_NOT_YET_WALLED);

    const evidence = evaluateCastleWall(snapshot);
    expect(evidence.vault_provision).toBe(CASTLE_WALL_NOT_YET_WALLED);
    // ...and the RUNTIME verdict is byte-identical to the no-detector answer,
    // so this is purely additive: nothing about the wall runtime changed.
    const baseline = evaluateCastleWall(undefined);
    expect({ ...evidence, vault_provision: undefined }).toEqual({
      ...baseline,
      vault_provision: undefined,
    });
  });

  it("says nothing extra for a fortress that carries no claim", async () => {
    const snapshot = await castleWallSnapshotForHealthReport({
      config: { storage_path: join(tmp, "no-claim") },
      masterKey: new Uint8Array(32),
      overrides: { platform: "darwin" },
    });
    expect(snapshot).toBeUndefined();
    expect(evaluateCastleWall(snapshot)).not.toHaveProperty("vault_provision");
  });
});

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

  it("treats a resolver that throws as no claim, never as protection", async () => {
    const thrown = await getProtectionSnapshot(
      sources(async () => {
        throw new Error("injected claim-read failure");
      }),
    );
    expect(thrown.overall.light).not.toBe("green");
    expect(thrown).not.toHaveProperty("castle_wall_provision");
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


describe("the externally published reputation payload carries the vault claim", () => {
  let tmp: string;
  const realFetch = globalThis.fetch;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-vault-publish-"));
  });

  afterEach(async () => {
    globalThis.fetch = realFetch;
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  /**
   * Build the L4 tool surface against a fortress path we control, and capture
   * the outbound POST body instead of making one.
   */
  async function publishFrom(
    fortressPath: string,
  ): Promise<Record<string, unknown>> {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools: l1Tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
    );
    await identityManager.load();
    const config = { ...(await loadConfig()), storage_path: fortressPath };
    const { tools: l4Tools } = createL4Tools(
      storage,
      masterKey,
      identityManager,
      auditLog,
      undefined,
      "https://verascore.ai",
      config,
    );
    type Tool = {
      name: string;
      handler: (a: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>;
    };
    const tools = [...l1Tools, ...l4Tools] as unknown as Tool[];
    const call = async (name: string, args: Record<string, unknown> = {}) => {
      const tool = tools.find((t) => t.name === name);
      if (!tool) throw new Error(`Tool not found: ${name}`);
      return JSON.parse((await tool.handler(args)).content[0]!.text) as Record<
        string,
        unknown
      >;
    };
    await call("identity_create", { label: "vault-provision-publisher" });

    const posted: Array<Record<string, unknown>> = [];
    globalThis.fetch = (async (_url: string, init?: RequestInit) => {
      posted.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
      return {
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      } as unknown as Response;
    }) as typeof fetch;

    await call("reputation_publish", { type: "shr" });
    expect(posted).toHaveLength(1);
    return posted[0]!.data as Record<string, unknown>;
  }

  it("publishes the claim it already had in hand instead of dropping it", async () => {
    // The evidence object handed to this builder ALREADY carried the answer;
    // the builder read four layer scores off it and threw the rest away. None
    // of those scores says whether this vault is on the wall running on this
    // machine, and the payload is signed and sent to an external reputation
    // surface, so the omission is the over-claim.
    const fortressPath = await claimingFortress(tmp, "publishing-vault");
    const data = await publishFrom(fortressPath);
    expect(data.castle_wall_provision).toBe(CASTLE_WALL_NOT_YET_WALLED);
  });

  it("adds nothing for a fortress that carries no claim", async () => {
    const data = await publishFrom(join(tmp, "no-claim-vault"));
    expect(data).not.toHaveProperty("castle_wall_provision");
  });
});
