/**
 * Fleet control plane PR-2: end-to-end enforcement invariant.
 *
 * Exercises the REAL path a request takes on the enforced roster provider -
 * persisted activation → resolveActivation (re-verify at the current clock) →
 * applyFleetCap - with a real Ed25519-signed license and MemoryStorage, and
 * asserts the two ratified invariants that matter most:
 *
 *   A. WALL / LOCAL DASHBOARD / POLICY-PUSH ARE NEVER GATED. Through EVERY
 *      resolution state (no license / valid paid / expired / over-cap community),
 *      the roster's `policy_distribution` rail (the free security function, the
 *      proxy for "we never gate your security") survives capping intact. Capping
 *      only ever removes CENTRAL-roster nodes; it never touches the rail, and this
 *      module has no wall/enforcement/local-dashboard code path at all.
 *
 *   B. OVER-CAP = KEEP WALL, DROP FROM CONSOLE. An unlicensed 8-node fleet shows
 *      only 5 nodes centrally; a Team license lifts it to all 8; an expired Team
 *      license drops back to 5 - never a silent free-ride, never a silent break.
 *
 * A real issuer key signs the license so a dropped verify fails loudly here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import {
  ENTITLEMENT_TOKEN_VERSION_V2,
  buildEntitlementMessageV2,
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "../../src/entitlement/token.js";
import {
  writeFleetActivation,
  resolveActivation,
} from "../../src/entitlement/activation.js";
import { applyFleetCap } from "../../src/entitlement/fleet-cap.js";
import type {
  FleetRoster,
  FleetRosterNode,
} from "../../src/principal-policy/fleet-roster.js";

const issuer = generateKeypair();
const master = randomBytes(32);
const NOW = 1_800_000_000;

function node(id: string): FleetRosterNode {
  return {
    node_id: id,
    label: null,
    trust_state: "admitted",
    trust_evaluable: true,
    reach: "recent",
    node_mode: "local",
    provider_in_trust_boundary: true,
    last_sync_received_at: "2026-07-05T00:00:00.000Z",
    policy: {
      version: 7,
      hash: "policy-hash",
      hash_algorithm: "sha256",
      applied_at: "2026-07-05T00:00:00.000Z",
      source_event_id: "e",
      drift_state: "in_sync",
    },
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-05T00:00:00.000Z",
  };
}

/** A live 8-node roster with a real (uncapped) policy-distribution rail. */
function eightNodeRoster(): FleetRoster {
  const nodes = Array.from({ length: 8 }, (_, i) => node(`n${i}`));
  return {
    available: true,
    enabled: true,
    fortress_id: "f",
    node_id: "n0",
    eviction_serial: 0,
    nodes,
    summary: { total: 8, admitted: 8, revoked: 0, untrusted: 0 },
    sync_health: {
      reachable: 8,
      stale: 0,
      never: 0,
      oldest_last_sync: "2026-07-05T00:00:00.000Z",
      freshness_window_ms: 600_000,
    },
    policy_distribution: {
      available: true,
      operator_policy: {
        version: 7,
        hash: "policy-hash",
        hash_algorithm: "sha256",
        applied_at: "2026-07-05T00:00:00.000Z",
        source_event_id: "policy-event",
      },
      summary: { in_sync: 8, drifted: 0, unknown: 0 },
    },
  };
}

function teamLicense(overrides: Partial<EntitlementClaimsV2> = {}): EntitlementToken {
  const claims: EntitlementClaimsV2 = {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: "lic-e2e",
    subject: "fleet-op",
    tier: "team",
    pricingUnit: "node",
    entitledCount: 25,
    period: "monthly",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
    graceUntil: NOW + 100 + 14 * 86_400,
    featureFlags: ["roster", "policy-dist"],
    issuer: "issuer-fp",
    ...overrides,
  };
  return {
    claims,
    signature: toBase64url(ed25519.sign(buildEntitlementMessageV2(claims), issuer.privateKey)),
  };
}

/** Resolve the cap the enforced provider would apply, then cap the roster. */
async function enforce(
  storage: MemoryStorage,
  now: number,
): Promise<ReturnType<typeof applyFleetCap>> {
  const cap = await resolveActivation(storage, master, issuer.publicKey, now);
  return applyFleetCap(eightNodeRoster(), cap);
}

describe("PR-2 enforcement - over-cap keeps wall, drops from console", () => {
  it("UNLICENSED 8-node fleet shows only 5 centrally, wall+policy-push intact", async () => {
    const storage = new MemoryStorage(); // no activation
    const { roster, cap, droppedNodeCount } = await enforce(storage, NOW);
    expect(cap.paid).toBe(false);
    expect(roster.nodes).toHaveLength(5); // 3 dropped from the console
    expect(droppedNodeCount).toBe(3);
    // The 3 dropped nodes keep their free local wall + local dashboard: this
    // module never touched enforcement. And the policy-push rail is intact for ALL
    // nodes (free security, never gated).
    expect(roster.policy_distribution.available).toBe(true);
    expect(roster.policy_distribution.operator_policy).not.toBeNull();
  });

  it("a valid TEAM license lifts the cap to all 8 nodes", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, teamLicense(), 0);
    const { roster, cap, droppedNodeCount } = await enforce(storage, NOW);
    expect(cap.paid).toBe(true);
    expect(roster.nodes).toHaveLength(8);
    expect(droppedNodeCount).toBe(0);
    expect(roster.policy_distribution.operator_policy).not.toBeNull();
  });

  it("an EXPIRED team license drops the console back to 5 (no free-ride), wall+policy-push intact", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, teamLicense(), 0);
    const { roster, cap, droppedNodeCount } = await enforce(
      storage,
      NOW + 100 + 15 * 86_400, // past grace
    );
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("expired");
    expect(roster.nodes).toHaveLength(5);
    expect(droppedNodeCount).toBe(3);
    // Even with the plan lapsed, policy-push stays available to every node.
    expect(roster.policy_distribution.available).toBe(true);
    expect(roster.policy_distribution.operator_policy).not.toBeNull();
  });

  it("a grandfathered 8-node fleet keeps all 8 free even with NO license", async () => {
    const storage = new MemoryStorage();
    // Simulate first-activation-then-lapse where the baseline was captured at 8:
    // write an expired license carrying an 8-node grandfather baseline.
    await writeFleetActivation(storage, master, teamLicense(), 8);
    const { roster, cap, droppedNodeCount } = await enforce(
      storage,
      NOW + 100 + 15 * 86_400, // expired → community, but baseline 8
    );
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("grandfathered");
    expect(cap.maxNodes).toBe(8);
    expect(roster.nodes).toHaveLength(8);
    expect(droppedNodeCount).toBe(0);
    expect(roster.policy_distribution.operator_policy).not.toBeNull();
  });
});
