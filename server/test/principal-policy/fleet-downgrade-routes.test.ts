/**
 * Fleet control plane PR-3: the downgrade UX + revocation routes over the REAL
 * DashboardApprovalChannel.
 *
 * Exercises, end to end over HTTP with custody wired:
 *   - GET  /api/fleet/status           the downgrade BANNER state (ok / expired /
 *                                       revoked / over_cap) + dropped node count.
 *   - GET  /api/fleet/downgrade-log     the operator-visible transition log.
 *   - POST /api/fleet/revocation-list   push a SIGNED list; fail-closed auth,
 *                                       pinned-key verify, monotonic version,
 *                                       and the end-to-end "revocation drops a
 *                                       paid license from the console" invariant.
 *
 * Ratified invariants asserted:
 *   - A revoked license drops from the CENTRAL console but the roster's
 *     policy_distribution rail (free security) survives - security never gated.
 *   - The revocation-list push is operator-bearer gated (fail-closed auth).
 *   - A push signed by the WRONG key, or with a stale version, is rejected.
 */

import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toBase64url } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";
import {
  ENTITLEMENT_TOKEN_VERSION_V2,
  buildEntitlementMessageV2,
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "../../src/entitlement/token.js";
import { writeFleetActivation } from "../../src/entitlement/activation.js";
import {
  REVOCATION_LIST_META_KEY,
  signRevocationList,
  writeRevocationList,
  type RevocationListPayload,
  type SignedRevocationList,
} from "../../src/entitlement/revocation-list.js";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";
import type {
  FederationContext,
  FederationNodeView,
} from "../../src/v1/federation.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import type { SHRGeneratorOptions } from "../../src/shr/generator.js";

const issuer = (() => {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
})();
const wrongIssuer = (() => {
  const privateKey = randomBytes(32);
  return { privateKey };
})();

const LICENSE_ID = "lic-pr3-e2e";

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

function license(window: {
  notBefore: number;
  notAfter: number;
  graceUntil: number;
}): EntitlementToken {
  const claims: EntitlementClaimsV2 = {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: LICENSE_ID,
    subject: "fleet-op",
    tier: "team",
    pricingUnit: "node",
    entitledCount: 25,
    period: "monthly",
    notBefore: window.notBefore,
    notAfter: window.notAfter,
    graceUntil: window.graceUntil,
    featureFlags: ["roster"],
    issuer: "issuer-fp",
  };
  return {
    claims,
    signature: toBase64url(
      ed25519.sign(buildEntitlementMessageV2(claims), issuer.privateKey),
    ),
  };
}

function liveLicense(): EntitlementToken {
  const now = Math.floor(Date.now() / 1000);
  return license({ notBefore: now - 3600, notAfter: now + 3600, graceUntil: now + 3600 });
}

function expiredLicense(): EntitlementToken {
  const now = Math.floor(Date.now() / 1000);
  return license({ notBefore: now - 7200, notAfter: now - 3600, graceUntil: now - 1800 });
}

function signedList(
  ids: string[],
  version: number,
  signerKey: Uint8Array = issuer.privateKey,
): SignedRevocationList {
  const payload: RevocationListPayload = {
    version,
    revokedLicenseIds: ids,
    issuer: "issuer-fp",
    issuedAt: "2026-07-06T00:00:00.000Z",
  };
  return signRevocationList(payload, (m) => ed25519.sign(m, signerKey));
}

interface Harness {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

async function startHarness(totalNodes: number): Promise<Harness> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `pr3-${randomBytes(8).toString("hex")}`;
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
    shrOpts: {
      config: {} as SHRGeneratorOptions["config"],
      identityManager,
      masterKey,
    },
  });

  dashboard.setFederationContext(CTX);

  const nodes = new Map<string, FederationNodeView>();
  for (let i = 0; i < totalNodes; i++) {
    nodes.set(`node-${i}`, nodeView(`node-${i}`));
  }
  const dash = dashboard as unknown as {
    _federationState: { nodes: Map<string, FederationNodeView>; revoked: Set<string> };
  };
  dash._federationState = {
    ...dash._federationState,
    nodes,
    revoked: new Set<string>(),
  };

  await dashboard.start();
  return {
    storage,
    masterKey,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    stop: async () => {
      await dashboard.stop();
    },
  };
}

async function get(h: Harness, path: string): Promise<Response> {
  return fetch(`${h.baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${h.authToken}` },
  });
}

async function pushList(
  h: Harness,
  signed: SignedRevocationList,
  token?: string,
): Promise<Response> {
  return fetch(`${h.baseUrl}/api/fleet/revocation-list`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(signed),
  });
}

async function fetchFleet(h: Harness): Promise<FleetRoster> {
  const res = await get(h, "/api/posture/fleet");
  expect(res.status).toBe(200);
  return (await res.json()) as FleetRoster;
}

let h: Harness | null = null;
afterEach(async () => {
  if (h) {
    await h.stop();
    h = null;
  }
});

describe("PR-3 GET /api/fleet/status - the downgrade banner", () => {
  it("reports over_cap for an unlicensed 8-node fleet (3 nodes out of console)", async () => {
    h = await startHarness(8);
    const res = await get(h, "/api/fleet/status");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.tier).toBe("community");
    expect(body.paid).toBe(false);
    expect(body.banner_state).toBe("over_cap");
    expect(body.dropped_node_count).toBe(3);
    expect(body.security_unaffected).toBe(true);
  });

  it("reports ok for a valid paid license within cap", async () => {
    h = await startHarness(8);
    await writeFleetActivation(h.storage, h.masterKey, liveLicense(), 0);
    const res = await get(h, "/api/fleet/status");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.paid).toBe(true);
    expect(body.tier).toBe("team");
    expect(body.banner_state).toBe("ok");
    expect(body.dropped_node_count).toBe(0);
  });

  it("reports expired for a lapsed license", async () => {
    h = await startHarness(8);
    await writeFleetActivation(h.storage, h.masterKey, expiredLicense(), 0);
    const res = await get(h, "/api/fleet/status");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.paid).toBe(false);
    expect(body.banner_state).toBe("expired");
  });

  // The banner's unverifiable determination MUST come from the SAME chokepoint
  // enforcement uses (revocationVerifiability), not a parallel corrupt-only
  // readRevocationList check. Enforcement drops a paid grant whose established
  // revocation floor is un-provable (deleted or rolled back below the floor) to
  // Community; the banner must then report the operator-actionable re-push state
  // (revocation_list_unreadable), NOT mislabel it "revoked".
  it("reports revocation_list_unreadable when the list is DELETED below an established floor", async () => {
    h = await startHarness(8);
    // A live paid license, then a genuine revocation push at v5 establishes the
    // floor (+ the custody witness latch that survives deletion of the list).
    await writeFleetActivation(h.storage, h.masterKey, liveLicense(), 0);
    expect((await pushList(h, signedList([LICENSE_ID], 5), h.authToken)).status).toBe(200);
    // Delete the on-disk revocation list. The witness latch keeps the floor at 5,
    // so the chokepoint reports `unverifiable` (absent_below_floor): enforcement
    // drops to Community, and the banner must say "re-push", not "revoked".
    await h.storage.delete("_meta", REVOCATION_LIST_META_KEY);

    const res = await get(h, "/api/fleet/status");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.paid).toBe(false); // enforcement correctly dropped to Community
    expect(body.revocation_list_unreadable).toBe(true);
    expect(body.banner_state).toBe("revocation_list_unreadable");
    expect(body.banner_state).not.toBe("revoked");
  });

  it("reports revocation_list_unreadable when the list is ROLLED BACK below an established floor", async () => {
    h = await startHarness(8);
    await writeFleetActivation(h.storage, h.masterKey, liveLicense(), 0);
    // Establish the floor at v5 with a genuine push (raises the custody witness
    // latch to 5, which survives any later on-disk list change).
    expect((await pushList(h, signedList([LICENSE_ID], 5), h.authToken)).status).toBe(200);
    // Model an on-disk ROLLBACK: replace the stored list with an OLD, genuinely
    // master-MAC'd v1 record below the established floor. writeRevocationList's own
    // monotonic guard reads the CURRENT on-disk version, so delete first, then
    // write v1 - the witness latch keeps the enforcement floor at 5.
    await h.storage.delete("_meta", REVOCATION_LIST_META_KEY);
    await writeRevocationList(h.storage, h.masterKey, {
      version: 1,
      revokedLicenseIds: [LICENSE_ID],
      issuer: "issuer-fp",
      issuedAt: "2026-07-06T00:00:00.000Z",
    });

    const res = await get(h, "/api/fleet/status");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.paid).toBe(false); // rolled-back-below-floor -> dropped to Community
    expect(body.revocation_list_unreadable).toBe(true);
    expect(body.banner_state).toBe("revocation_list_unreadable");
    expect(body.banner_state).not.toBe("revoked");
  });
});

describe("PR-3 POST /api/fleet/revocation-list - fail-closed push", () => {
  it("401s without the operator bearer token", async () => {
    h = await startHarness(8);
    const res = await pushList(h, signedList([LICENSE_ID], 1)); // no token
    expect(res.status).toBe(401);
  });

  it("accepts a valid signed list and reports the version + count", async () => {
    h = await startHarness(8);
    const res = await pushList(h, signedList([LICENSE_ID], 1), h.authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.version).toBe(1);
    expect(body.revoked_count).toBe(1);
  });

  it("rejects a list signed by the WRONG key (bad_signature)", async () => {
    h = await startHarness(8);
    const res = await pushList(h, signedList([LICENSE_ID], 1, wrongIssuer.privateKey), h.authToken);
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(false);
    expect(body.reason).toBe("bad_signature");
  });

  it("rejects a stale (non-newer) version after a first push (not_newer)", async () => {
    h = await startHarness(8);
    expect((await pushList(h, signedList([LICENSE_ID], 5), h.authToken)).status).toBe(200);
    const res = await pushList(h, signedList([LICENSE_ID], 5), h.authToken);
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.reason).toBe("not_newer");
  });

  it("END TO END: pushing a revocation for the ACTIVE license drops it from the console", async () => {
    h = await startHarness(8);
    // Activate a live paid license: all 8 nodes are in the console.
    await writeFleetActivation(h.storage, h.masterKey, liveLicense(), 0);
    expect((await fetchFleet(h)).nodes).toHaveLength(8);

    // Push a signed revocation for that license id.
    const res = await pushList(h, signedList([LICENSE_ID], 1), h.authToken);
    expect(res.status).toBe(200);

    // The console now drops back to the free cap (5); the license is revoked.
    const roster = await fetchFleet(h);
    expect(roster.nodes).toHaveLength(5);
    // Security is NEVER gated: the policy-distribution rail survives.
    expect(roster.policy_distribution.available).toBe(true);
  });
});

describe("PR-3 GET /api/fleet/downgrade-log - operator-visible log", () => {
  it("returns a readable (initially empty) log", async () => {
    h = await startHarness(8);
    const res = await get(h, "/api/fleet/downgrade-log");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.readable).toBe(true);
    expect(Array.isArray(body.entries)).toBe(true);
  });

  it("records a transition after a revocation push (newest-first)", async () => {
    h = await startHarness(8);
    await writeFleetActivation(h.storage, h.masterKey, liveLicense(), 0);
    // Prime the prior-cap state with one status read, then revoke.
    await get(h, "/api/fleet/status");
    await pushList(h, signedList([LICENSE_ID], 1), h.authToken);
    // The push triggers an immediate re-resolve tick that logs the downgrade.
    // Give the fire-and-forget tick a moment to persist.
    await new Promise((r) => setTimeout(r, 50));
    const res = await get(h, "/api/fleet/downgrade-log");
    const body = (await res.json()) as { entries: Array<{ kind: string }> };
    expect(body.entries.some((e) => e.kind === "downgrade")).toBe(true);
  });
});
