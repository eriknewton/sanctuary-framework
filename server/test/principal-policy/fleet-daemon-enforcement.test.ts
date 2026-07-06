/**
 * Fleet control plane PR-B: node-count enforcement on the DAEMON federation
 * roster - end-to-end over the REAL DashboardApprovalChannel.
 *
 * This is the test PR-2 (#886) LACKED: it exercises the cap over a NON-EMPTY,
 * durable federation roster - the real `_federationState.nodes` the daemon
 * persists (#888) - proving `applyFleetCap` actually DROPS REAL NODES. On the
 * wrap surface #886 wired, the roster was empty by construction, so the cap never
 * dropped anything and enforcement was inert. Here it is live and drives the
 * REAL `GET /api/posture/fleet` + `POST /api/fleet/activate` routes over HTTP.
 *
 * The path under test, exactly as a request takes it:
 *   real DashboardApprovalChannel (storage + master key + operator identity
 *   wired) → `_federationState.nodes` seeded with real node views (some revoked)
 *   → the daemon's `fleetRoster` closure runs `buildFleetRoster` over the live
 *   `V1FederationDeps` → `resolveActivation` re-verifies the persisted license at
 *   the CURRENT clock → `applyFleetCap` reshapes the CENTRAL roster.
 *
 * Licenses use REAL wall-clock-relative windows so the daemon's own resolution
 * (against `Date.now()`) demonstrates the lift/drop through HTTP directly - no
 * injected clock.
 *
 * Ratified invariants asserted:
 *   A. OVER-CAP = KEEP WALL, DROP FROM CONSOLE (unlicensed / expired 8-node fleet
 *      → 5 on the console; valid Team license → all 8). Real nodes leave/return;
 *      the cap NEVER touches a node's wall (this path has no wall/enforcement).
 *   B. POLICY-PUSH (FREE SECURITY) IS NEVER GATED (the rail survives capping).
 *   C. GRANDFATHER BASELINE SOURCED FROM DURABLE `summary.admitted`.
 *   D. FAIL-CLOSED AUTH on the activation route (operator bearer required).
 *
 * A real Ed25519 issuer key (the operator identity) signs the license so a
 * dropped verify fails loudly here.
 */

import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";
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
import {
  writeRevocationList,
  signRevocationList,
  verifyPushedRevocationList,
} from "../../src/entitlement/revocation-list.js";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";
import type {
  FederationContext,
  FederationNodeView,
} from "../../src/v1/federation.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import type { SHRGeneratorOptions } from "../../src/shr/generator.js";

// ── Operator identity = the pinned license ISSUER (same fortress issues + activates) ──
const issuer = (() => {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
})();

/** Stub operator identity whose default public key is the license issuer key. */
function stubIdentityManager(publicKey: Uint8Array): IdentityManager {
  return {
    getDefault: () => ({
      identity_id: "op-1",
      label: "operator",
      did: "did:key:test",
      public_key: toBase64url(publicKey),
      created_at: "2026-06-01T00:00:00.000Z",
      key_type: "ed25519",
      key_protection: "passphrase",
    }),
    getPrimaryIdentityId: () => "op-1",
    get: () => undefined,
  } as unknown as IdentityManager;
}

/** A minimal non-issuer federation context so `buildFleetRoster` builds a real roster. */
const CTX: FederationContext = {
  fortressId: "fortress:test",
  nodeId: "home-mac",
  nodeMode: "local",
  pinnedMasterPubkey: {
    fortress_id: "fortress:test",
    public_key: "AAAA",
  } as FederationContext["pinnedMasterPubkey"],
  issuingPrincipalCert: {} as FederationContext["issuingPrincipalCert"],
  isNodeRevoked: () => false,
} as FederationContext;

function nodeView(nodeId: string): FederationNodeView {
  return {
    node_id: nodeId,
    label: null,
    attestation_status: "verified",
    node_mode: "local",
    host_provider: null,
    trust_boundary: {
      version: "operator-cloud-trust-boundary-v1",
      posture: "local_operator_host",
      label: "local operator host",
      provider_in_trust_boundary: false,
      tee_attested: false,
      disclosure: null,
    } as FederationNodeView["trust_boundary"],
    tee_attested: false,
    disclosure_acknowledged_at: null,
    drill_status: "not_applicable",
    first_seen: "2026-06-24T11:00:00.000Z",
    last_seen: "2026-06-24T11:59:00.000Z",
    last_sync: {
      received_at: "2026-06-24T11:59:00.000Z",
      sent_at: "2026-06-24T11:59:00.000Z",
      last_sequence: 3,
    },
    applied_policy: {
      version: null,
      hash: null,
      hash_algorithm: null,
      applied_at: null,
      source_event_id: null,
    },
  };
}

/** A node-metered Team license with an explicit wall-clock-relative window. */
function teamLicense(window: {
  entitledCount?: number | null;
  notBefore: number;
  notAfter: number;
  graceUntil: number;
}): EntitlementToken {
  const claims: EntitlementClaimsV2 = {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: "lic-daemon-e2e",
    subject: "fleet-op",
    tier: "team",
    pricingUnit: "node",
    entitledCount:
      window.entitledCount === undefined ? 25 : window.entitledCount,
    period: "monthly",
    notBefore: window.notBefore,
    notAfter: window.notAfter,
    graceUntil: window.graceUntil,
    featureFlags: ["roster", "policy-dist"],
    issuer: "issuer-fp",
  };
  return {
    claims,
    signature: toBase64url(
      ed25519.sign(buildEntitlementMessageV2(claims), issuer.privateKey),
    ),
  };
}

/** A license valid RIGHT NOW (so the daemon's live resolution honors it). */
function liveValidLicense(entitledCount: number | null = 25): EntitlementToken {
  const now = Math.floor(Date.now() / 1000);
  return teamLicense({
    entitledCount,
    notBefore: now - 3600,
    notAfter: now + 3600,
    graceUntil: now + 3600,
  });
}

/** A license already EXPIRED (past notAfter AND grace) at wall-clock. */
function expiredLicense(): EntitlementToken {
  const now = Math.floor(Date.now() / 1000);
  return teamLicense({
    notBefore: now - 7200,
    notAfter: now - 3600,
    graceUntil: now - 1800,
  });
}

interface Harness {
  dashboard: DashboardApprovalChannel;
  storage: MemoryStorage;
  masterKey: Uint8Array;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

/**
 * Boot a real daemon dashboard with CUSTODY wired (storage + master key +
 * operator identity) and seed `_federationState.nodes` with `total` nodes, the
 * last `revokedCount` of which are revoked. This is the durable federation
 * roster #888 persists; the enforcement gate reads it live.
 */
async function startHarness(opts: {
  totalNodes: number;
  revokedCount?: number;
}): Promise<Harness> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `pr-b-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });

  const identityManager = stubIdentityManager(issuer.publicKey);
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
    identityManager,
    storage,
    // Only `masterKey` is read by the enforcement gate; config + identityManager
    // are structurally required by SHRGeneratorOptions but unused on this path.
    shrOpts: {
      config: {} as SHRGeneratorOptions["config"],
      identityManager,
      masterKey,
    },
  });

  dashboard.setFederationContext(CTX);

  // Seed the DURABLE federation roster directly (the real `_federationState`
  // the daemon persists). A full join-ceremony would work too but is far heavier;
  // seeding the map is faithful because the enforcement gate reads it through the
  // SAME `buildV1FederationDeps().listNodes()` + `isNodeRevoked` projection the
  // console uses.
  const nodes = new Map<string, FederationNodeView>();
  const revoked = new Set<string>();
  const revokedCount = opts.revokedCount ?? 0;
  for (let i = 0; i < opts.totalNodes; i++) {
    const id = `node-${i}`;
    nodes.set(id, nodeView(id));
    if (i >= opts.totalNodes - revokedCount) revoked.add(id);
  }
  const dash = dashboard as unknown as {
    _federationState: {
      nodes: Map<string, FederationNodeView>;
      revoked: Set<string>;
    };
  };
  dash._federationState = { ...dash._federationState, nodes, revoked };

  await dashboard.start();
  return {
    dashboard,
    storage,
    masterKey,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    stop: async () => {
      await dashboard.stop();
    },
  };
}

/** Read the roster the board renders, through the authenticated posture surface. */
async function fetchFleet(h: Harness): Promise<FleetRoster> {
  const res = await fetch(`${h.baseUrl}/api/posture/fleet`, {
    headers: { Authorization: `Bearer ${h.authToken}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as FleetRoster;
}

async function activate(
  h: Harness,
  body: unknown,
  token?: string,
): Promise<Response> {
  return fetch(`${h.baseUrl}/api/fleet/activate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

function pasted(token: EntitlementToken): string {
  return toBase64url(stringToBytes(JSON.stringify(token)));
}

let h: Harness | null = null;
afterEach(async () => {
  if (h) {
    await h.stop();
    h = null;
  }
});

describe("PR-B daemon enforcement - cap DROPS REAL nodes on the durable roster", () => {
  it("UNLICENSED 8-node fleet shows only 5 on the central roster (3 real nodes dropped)", async () => {
    h = await startHarness({ totalNodes: 8 });
    const roster = await fetchFleet(h);
    // The durable roster has 8 real nodes; the community cap drops 3 from the
    // console. This is the exact behavior #886 could NOT exercise (empty roster).
    expect(roster.available).toBe(true);
    expect(roster.nodes).toHaveLength(5);
    expect(roster.summary.total).toBe(5);
    // Every dropped node keeps its free local wall + local dashboard (this path
    // has no wall/enforcement code); policy-push stays available to ALL nodes.
    expect(roster.policy_distribution.available).toBe(true);
  });

  it("a valid TEAM license lifts the central roster to ALL 8 real nodes (HTTP, live clock)", async () => {
    h = await startHarness({ totalNodes: 8 });
    // Persist a license valid RIGHT NOW; the daemon re-resolves it live on the
    // next roster read against Date.now().
    await writeFleetActivation(h.storage, h.masterKey, liveValidLicense(25), 0);
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(8);
    expect(roster.summary.total).toBe(8);
    expect(roster.policy_distribution.available).toBe(true);
  });

  it("an EXPIRED team license drops the central roster back to 5 real nodes (no free-ride)", async () => {
    h = await startHarness({ totalNodes: 8 });
    await writeFleetActivation(h.storage, h.masterKey, expiredLicense(), 0);
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(5);
    expect(roster.summary.total).toBe(5);
    // Even lapsed, policy-push stays available to every node (never gated).
    expect(roster.policy_distribution.available).toBe(true);
  });

  it("a GRANDFATHERED 8-node fleet keeps all 8 free even with an EXPIRED license (HTTP)", async () => {
    h = await startHarness({ totalNodes: 8 });
    // First activation captured the baseline at 8 (an existing oversized fleet);
    // the license is now expired → community by license, but the baseline holds.
    await writeFleetActivation(h.storage, h.masterKey, expiredLicense(), 8);
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(8);
    expect(roster.summary.total).toBe(8);
  });

  it("counts by summary.admitted: revoked nodes are the real trust projection, not re-derived", async () => {
    // 8 nodes, 4 revoked. Under the community cap of 5 the first 5 (stable order)
    // are retained; the retained slice's admitted/revoked split is the real
    // federation projection (`isNodeRevoked`), never a guess from a response.
    h = await startHarness({ totalNodes: 8, revokedCount: 4 });
    const roster = await fetchFleet(h);
    expect(roster.summary.total).toBe(5);
    expect(roster.summary.admitted + roster.summary.revoked).toBe(5);
    // node-0..node-3 admitted, node-4..node-7 revoked; retained first 5 = 4
    // admitted + 1 revoked.
    expect(roster.summary.admitted).toBe(4);
    expect(roster.summary.revoked).toBe(1);
  });
});

describe("PR-B daemon activation route - fail-closed auth + real grandfather baseline", () => {
  it("401s POST /api/fleet/activate without the operator bearer token", async () => {
    h = await startHarness({ totalNodes: 8 });
    const res = await activate(h, { license: "x" }); // no token
    expect(res.status).toBe(401);
  });

  it("401s with the WRONG bearer token", async () => {
    h = await startHarness({ totalNodes: 8 });
    const res = await activate(h, { license: "x" }, "wrong-token");
    expect(res.status).toBe(401);
  });

  it("400 validation_error when the license field is missing or empty", async () => {
    h = await startHarness({ totalNodes: 8 });
    const missing = await activate(h, {}, h.authToken);
    expect(missing.status).toBe(400);
    const empty = await activate(h, { license: "   " }, h.authToken);
    expect(empty.status).toBe(400);
  });

  it("400 malformed_token on a garbage paste, persists nothing", async () => {
    h = await startHarness({ totalNodes: 8 });
    const res = await activate(
      h,
      { license: "this-is-not-a-license" },
      h.authToken,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; reason: string };
    expect(body.ok).toBe(false);
    expect(body.reason).toBe("malformed_token");
    // Nothing was persisted: the roster still caps to the community floor.
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(5);
  });

  it("200 + lifts the roster to all 8 on a valid paste (activation → enforcement, HTTP round-trip)", async () => {
    h = await startHarness({ totalNodes: 8 });
    const res = await activate(
      h,
      { license: pasted(liveValidLicense(25)) },
      h.authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      tier: string;
      max_nodes: number | null;
    };
    expect(body.ok).toBe(true);
    expect(body.tier).toBe("team");
    expect(body.max_nodes).toBe(25);
    // The very next roster read reflects the activation: all 8 real nodes appear.
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(8);
  });

  it("ACTIVATION captures the grandfather baseline from durable summary.admitted (8)", async () => {
    // Activating over an oversized (8-admitted) fleet must persist baseline 8, so
    // that once the license later lapses the fleet is NOT force-capped to 5.
    h = await startHarness({ totalNodes: 8 });
    const res = await activate(
      h,
      { license: pasted(liveValidLicense(25)) },
      h.authToken,
    );
    expect(res.status).toBe(200);

    // Read the persisted record's resolution at a POST-EXPIRY clock: the license
    // no longer grants, but the grandfather baseline (captured from the durable
    // admitted count at activation) keeps the cap at 8.
    const now = Math.floor(Date.now() / 1000);
    const cap = await resolveActivation(
      h.storage,
      h.masterKey,
      issuer.publicKey,
      now + 10 * 86_400, // far past the 1-hour window + grace
    );
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("grandfathered");
    expect(cap.maxNodes).toBe(8);
  });

  it("a small (<=5-node) fleet captures baseline 0 (plain community cap, no grandfather)", async () => {
    h = await startHarness({ totalNodes: 3 });
    const res = await activate(
      h,
      { license: pasted(liveValidLicense(25)) },
      h.authToken,
    );
    expect(res.status).toBe(200);
    const now = Math.floor(Date.now() / 1000);
    const cap = await resolveActivation(
      h.storage,
      h.masterKey,
      issuer.publicKey,
      now + 10 * 86_400, // expired → community; baseline 0 → plain 5-node cap
    );
    // A STORED-then-lapsed license resolves via the entitlement core to
    // `expired` (distinct from the ABSENT-record `no_license`); with baseline 0
    // the cap is the plain 5-node community floor - no grandfather raise.
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("expired");
    expect(cap.maxNodes).toBe(5);
  });
});

describe("PR-3 fail-closed - a CORRUPT revocation list drops a paid fleet on the enforcement path", () => {
  it("a PRESENT-but-corrupt revocation list drops the paid roster from 8 back to 5 (fail closed, HTTP)", async () => {
    // Coordinator-adjudicated 2026-07-06: revocation state that cannot be
    // authenticated must NOT keep a paid tier. A valid Team license lifts the
    // roster to all 8; a present-but-corrupt revocation list then forces the
    // per-request `resolveFleetCap` to Community (5), even though the license
    // token itself still verifies and is in-window.
    h = await startHarness({ totalNodes: 8 });
    await writeFleetActivation(h.storage, h.masterKey, liveValidLicense(25), 0);
    // Baseline: paid, all 8 on the console.
    expect((await fetchFleet(h)).nodes).toHaveLength(8);

    // Write a revocation list under a DIFFERENT master so it reads INVALID under
    // the harness master (a present-but-corrupt list, the fail-closed trigger).
    await writeRevocationList(h.storage, randomBytes(32), {
      version: 1,
      revokedLicenseIds: ["lic-daemon-e2e"],
      issuer: "issuer-fp",
      issuedAt: "2026-07-06T00:00:00.000Z",
    });

    // The paid fleet is now dropped to the community floor of 5.
    const dropped = await fetchFleet(h);
    expect(dropped.nodes).toHaveLength(5);
    // Security is never gated: policy-push stays available to every node.
    expect(dropped.policy_distribution.available).toBe(true);
  });

  it("an ABSENT revocation list keeps the paid roster at all 8 (must NOT fail closed)", async () => {
    // The absent-vs-corrupt distinction at the enforcement path: an absent list
    // means nothing is revoked, so the paid fleet is unaffected.
    h = await startHarness({ totalNodes: 8 });
    await writeFleetActivation(h.storage, h.masterKey, liveValidLicense(25), 0);
    // No revocation list written (absent).
    expect((await fetchFleet(h)).nodes).toHaveLength(8);
  });

  it("a VALID revocation list that names the active license drops the roster to 5 (authenticated revoke)", async () => {
    // The positive-path control: a real, authenticated revocation of the active
    // license id also drops the paid fleet - proving the corrupt-list path is
    // fail-closed alongside a genuine revoke, not instead of it.
    h = await startHarness({ totalNodes: 8 });
    await writeFleetActivation(h.storage, h.masterKey, liveValidLicense(25), 0);
    const signed = signRevocationList(
      {
        version: 1,
        revokedLicenseIds: ["lic-daemon-e2e"],
        issuer: "issuer-fp",
        issuedAt: "2026-07-06T00:00:00.000Z",
      },
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 0);
    expect(v.ok).toBe(true);
    if (v.ok) await writeRevocationList(h.storage, h.masterKey, v.payload);
    expect((await fetchFleet(h)).nodes).toHaveLength(5);
  });
});
