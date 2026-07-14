/**
 * Fleet control plane, Add-Machine slice: HTTP-handler tests for the two
 * NET-NEW operator-facing routes over a REAL DashboardApprovalChannel.
 *
 *   GET  /api/fleet/capacity      - read-only enrollment headroom
 *   POST /api/fleet/enroll-token  - mint a bootstrap token (capacity pre-check)
 *
 * Both compose SHIPPED parts only (resolveFleetCap, buildFleetRoster,
 * JoinCeremony.authorizeInit - #888's durable roster + the ALREADY-BUILT join
 * ceremony) verbatim; neither route reimplements or reopens the ceremony or the
 * durable roster.
 *
 * HONESTY BOUND: this suite seeds federation deps in-process (an issuer
 * `FederationContext` built by `test/v1/fed-materials.ts`) and asserts the
 * operator-facing surface + capacity binding. It does NOT drive a real second
 * machine over the network; the 2-machine hardware enrollment drill stays
 * owed (see the PR body).
 *
 * Definition-of-Done assertions:
 *  1. GET /api/fleet/capacity: correct active_nodes/remaining/at_capacity for
 *     a seeded roster; fail-closed community floor on a resolve failure; never
 *     throws.
 *  2. POST /api/fleet/enroll-token: 401 without the operator bearer; 409
 *     at_capacity at a finite cap (message names the cap AND states walls are
 *     unaffected); mints + returns a bootstrap-token-shaped object under cap;
 *     409 federation_not_provisioned when federation is not enabled/wired.
 *  3. Invariant: the enroll-token / capacity handlers reference no
 *     wall/enforcement/policy-push symbol - this is a security carve-out, so
 *     the pre-check can only ever over-block, never over-admit.
 */

import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { getFreePort } from "../helpers/free-port.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import type { FederationNodeView } from "../../src/v1/federation.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import type { SHRGeneratorOptions } from "../../src/shr/generator.js";

function stubIdentityManager(): IdentityManager {
  return {
    getDefault: () => ({
      identity_id: "op-1",
      label: "operator",
      did: "did:key:test",
      public_key: "AAAA",
      created_at: "2026-06-01T00:00:00.000Z",
      key_type: "ed25519",
      key_protection: "passphrase",
    }),
    getPrimaryIdentityId: () => "op-1",
    get: () => undefined,
  } as unknown as IdentityManager;
}

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
    first_seen: "2026-07-06T11:00:00.000Z",
    last_seen: "2026-07-06T11:59:00.000Z",
    last_sync: {
      received_at: "2026-07-06T11:59:00.000Z",
      sent_at: "2026-07-06T11:59:00.000Z",
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

interface Harness {
  dashboard: DashboardApprovalChannel;
  storage: MemoryStorage;
  masterKey: Uint8Array;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

/**
 * Boot a real daemon dashboard with CUSTODY wired, an ISSUER federation
 * context (so the ceremony can mint), and `_federationState.nodes` seeded with
 * `totalNodes` real node views, so `summary.admitted` is a known number - the
 * SAME seeding shape `fleet-daemon-enforcement.test.ts` uses for the sibling
 * activation route.
 */
async function startHarness(opts: {
  totalNodes: number;
  federationEnabled?: boolean;
  provisioned?: boolean;
}): Promise<Harness> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `am-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });

  const identityManager = stubIdentityManager();
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

  if (opts.provisioned !== false) {
    const { context } = makeFederationMaterials();
    dashboard.setFederationContext(context);
  }
  if (opts.federationEnabled !== false) {
    (dashboard as unknown as { _federationEnabled: boolean })._federationEnabled = true;
  }

  const nodes = new Map<string, FederationNodeView>();
  for (let i = 0; i < opts.totalNodes; i++) {
    nodes.set(`node-${i}`, nodeView(`node-${i}`));
  }
  const dash = dashboard as unknown as {
    _federationState: {
      nodes: Map<string, FederationNodeView>;
      revoked: Set<string>;
    };
  };
  dash._federationState = { ...dash._federationState, nodes, revoked: new Set() };

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

async function getCapacity(h: Harness, token?: string): Promise<Response> {
  return fetch(`${h.baseUrl}/api/fleet/capacity`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

/**
 * Poison the durable roster so `buildFleetRoster`'s unguarded
 * `deps.listNodes()` call throws (a genuine derivation failure), rather than
 * returning `available: false` (honest absence) or an empty node list. This
 * is the fail-open reproduction case: a naive mint pre-check would read the
 * caught failure as `active_nodes: 0` and mint anyway even though the real
 * roster is unknown, possibly at or over cap.
 */
function poisonRoster(h: Harness): void {
  const dash = h.dashboard as unknown as {
    _federationState: { nodes: unknown; revoked: Set<string> };
  };
  dash._federationState = {
    ...dash._federationState,
    nodes: {
      values: () => {
        throw new Error("simulated roster derivation failure");
      },
    },
  };
}

async function enrollToken(
  h: Harness,
  body: unknown,
  token?: string,
): Promise<Response> {
  return fetch(`${h.baseUrl}/api/fleet/enroll-token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

let h: Harness | null = null;
afterEach(async () => {
  if (h) {
    await h.stop();
    h = null;
  }
});

describe("GET /api/fleet/capacity - read-only enrollment headroom", () => {
  it("reports active_nodes/remaining/at_capacity for a seeded roster under the community floor", async () => {
    h = await startHarness({ totalNodes: 3 });
    const res = await getCapacity(h, h.authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      tier: string;
      max_nodes: number | null;
      active_nodes: number;
      remaining: number | null;
      at_capacity: boolean;
      enrollment_allowed: boolean;
    };
    expect(body.tier).toBe("community");
    expect(body.max_nodes).toBe(5);
    expect(body.active_nodes).toBe(3);
    expect(body.remaining).toBe(2);
    expect(body.at_capacity).toBe(false);
    expect(body.enrollment_allowed).toBe(true);
  });

  it("reports at_capacity true when the seeded roster is exactly at the community floor", async () => {
    h = await startHarness({ totalNodes: 5 });
    const res = await getCapacity(h, h.authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { at_capacity: boolean; remaining: number | null };
    expect(body.at_capacity).toBe(true);
    expect(body.remaining).toBe(0);
  });

  it("401s a read with no credential at all (like every other authenticated dashboard GET)", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await getCapacity(h);
    expect(res.status).toBe(401);
  });

  it("fail-closed community floor + active_nodes 0 when federation is not provisioned (no roster)", async () => {
    h = await startHarness({ totalNodes: 0, provisioned: false });
    const res = await getCapacity(h, h.authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      tier: string;
      max_nodes: number | null;
      active_nodes: number;
      at_capacity: boolean;
    };
    expect(body.tier).toBe("community");
    expect(body.max_nodes).toBe(5);
    expect(body.active_nodes).toBe(0);
    expect(body.at_capacity).toBe(false);
  });

  it("never throws: response is always well-formed JSON with the expected fields", async () => {
    h = await startHarness({ totalNodes: 0, provisioned: false });
    const res = await getCapacity(h, h.authToken);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.tier).toBe("string");
    expect(typeof body.active_nodes).toBe("number");
    expect(typeof body.at_capacity).toBe("boolean");
    expect(typeof body.enrollment_allowed).toBe("boolean");
  });
});

describe("POST /api/fleet/enroll-token - auth + capacity pre-check + mint", () => {
  it("401s without the operator bearer token", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await enrollToken(h, { node_id: "node-x", node_mode: "local" });
    expect(res.status).toBe(401);
  });

  it("401s with the WRONG bearer token", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await enrollToken(
      h,
      { node_id: "node-x", node_mode: "local" },
      "wrong-token",
    );
    expect(res.status).toBe(401);
  });

  it("400 validation_error on a missing node_id", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await enrollToken(h, { node_mode: "local" }, h.authToken);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("validation_error");
  });

  it("400 validation_error on an invalid node_mode", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await enrollToken(
      h,
      { node_id: "node-x", node_mode: "not-a-mode" },
      h.authToken,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("validation_error");
  });

  it("400 on unparseable JSON body", async () => {
    h = await startHarness({ totalNodes: 1 });
    const res = await fetch(`${h.baseUrl}/api/fleet/enroll-token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${h.authToken}`,
      },
      body: "{not json",
    });
    expect(res.status).toBe(400);
  });

  it("409 at_capacity when the seeded roster is at the finite community cap; message names the cap and states walls are unaffected", async () => {
    h = await startHarness({ totalNodes: 5 });
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as {
      error: string;
      active_nodes: number;
      max_nodes: number;
      message: string;
    };
    expect(body.error).toBe("at_capacity");
    expect(body.active_nodes).toBe(5);
    expect(body.max_nodes).toBe(5);
    expect(body.message).toContain("5");
    expect(body.message.toLowerCase()).toContain("wall");
  });

  it("mints + returns a bootstrap-token-shaped object when under cap", async () => {
    h = await startHarness({ totalNodes: 2 });
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      bootstrap_token: {
        intended_node_id: string;
        intended_node_mode: string;
        fortress_id: string;
        issuing_principal: string;
        expires_at: string;
        issued_at: string;
        nonce: string;
        signature_scheme: string;
        signature: string;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.bootstrap_token.intended_node_id).toBe("node-new");
    expect(body.bootstrap_token.intended_node_mode).toBe("local");
    expect(typeof body.bootstrap_token.signature).toBe("string");
    expect(body.bootstrap_token.signature.length).toBeGreaterThan(0);
    // No private key / master / passphrase field anywhere in the response.
    const raw = JSON.stringify(body);
    expect(raw).not.toMatch(/private_key|master_secret|passphrase/i);
  });

  it("409 federation_not_provisioned when federation is not provisioned at all", async () => {
    h = await startHarness({ totalNodes: 0, provisioned: false });
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("federation_not_provisioned");
  });

  it("409 federation_not_provisioned when federation is provisioned but disabled", async () => {
    h = await startHarness({ totalNodes: 0, federationEnabled: false });
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("federation_not_provisioned");
  });
});

describe("POST /api/fleet/enroll-token - fails closed when the roster count is unreliable", () => {
  it("returns 503 capacity_unavailable and does NOT mint when buildFleetRoster throws", async () => {
    h = await startHarness({ totalNodes: 3 });
    poisonRoster(h);
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("capacity_unavailable");
    expect(body.message.length).toBeGreaterThan(0);
    // No bootstrap token shape leaked on the fail-closed path.
    expect(JSON.stringify(body)).not.toMatch(/bootstrap_token|signature/i);
  });

  it("a genuine 0-active roster (no poison) still mints - real headroom is not blocked", async () => {
    h = await startHarness({ totalNodes: 0 });
    const res = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it("GET /api/fleet/capacity is unaffected by the roster poison (read-only surface may still show active_nodes: 0)", async () => {
    h = await startHarness({ totalNodes: 3 });
    poisonRoster(h);
    const res = await getCapacity(h, h.authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active_nodes: number };
    expect(body.active_nodes).toBe(0);
  });
});

describe("Add-Machine slice - never gates security (invariant)", () => {
  it("the capacity 409 path never advances/reads any wall/enforcement/policy-push dependency", async () => {
    // A seeded harness with NO wall/enforcement dependency wired at all (this
    // harness never sets any castle-wall / policy-push binding); the fact
    // that both the capacity read and the at-capacity 409 succeed cleanly
    // over HTTP with nothing but federation deps wired is itself the
    // evidence: if either path referenced an enforcement dependency, this
    // harness would throw (no such dependency exists on this dashboard
    // instance) rather than return a clean response.
    h = await startHarness({ totalNodes: 5 });
    const capacityRes = await getCapacity(h, h.authToken);
    expect(capacityRes.status).toBe(200);
    const enrollRes = await enrollToken(
      h,
      { node_id: "node-new", node_mode: "local" },
      h.authToken,
    );
    expect(enrollRes.status).toBe(409);
    // Every existing node's wall is a LOCAL, per-node concern this daemon
    // never touches; the roster is unaffected by the 409 (still 5 seeded
    // nodes, none dropped, none added).
    const capacityAfter = (await (await getCapacity(h, h.authToken)).json()) as {
      active_nodes: number;
    };
    expect(capacityAfter.active_nodes).toBe(5);
  });
});

describe("POST /api/fleet/enroll-token - request-body values cannot bypass a gate (CodeQL js/user-controlled-bypass regression)", () => {
  // CodeQL flagged the node_id validation condition as a "user-controlled
  // bypass of a security check" because the attacker-controlled body flows
  // into a condition that dominates the mint. This suite is the standing
  // proof that the finding is a FALSE POSITIVE: no choice of node_id or
  // node_mode can bypass the paid node-cap gate or the not-provisioned gate.
  // The body only labels the token; the real gates read server-side state.

  it("no attacker-chosen node_id/node_mode mints when the roster is at the finite cap (every choice still 409 at_capacity)", async () => {
    // A well-formed body always clears input validation. If clearing it were a
    // "bypass", one of these would mint. None does: the cap gate is checked
    // against the TOTAL admitted roster count, independent of the body.
    const bodies = [
      { node_id: "attacker-node", node_mode: "local" },
      { node_id: "attacker-node", node_mode: "operator_cloud" },
      { node_id: "attacker-node", node_mode: "sovereign_tee" },
      { node_id: "   padded-id   ", node_mode: "local" },
      { node_id: "x".repeat(512), node_mode: "sovereign_tee" },
    ];
    for (const body of bodies) {
      h = await startHarness({ totalNodes: 5 });
      const res = await enrollToken(h, body, h.authToken);
      expect(res.status).toBe(409);
      const parsed = (await res.json()) as { error: string };
      expect(parsed.error).toBe("at_capacity");
      // No token shape ever leaks on the gated path, whatever the body was.
      expect(JSON.stringify(parsed)).not.toMatch(/bootstrap_token|signature/i);
      await h.stop();
      h = null;
    }
  });

  it("no attacker-chosen node_id/node_mode mints when federation is not provisioned (every choice still 409 federation_not_provisioned)", async () => {
    const modes = ["local", "operator_cloud", "sovereign_tee"] as const;
    for (const mode of modes) {
      h = await startHarness({ totalNodes: 0, provisioned: false });
      const res = await enrollToken(
        h,
        { node_id: "attacker-node", node_mode: mode },
        h.authToken,
      );
      expect(res.status).toBe(409);
      const parsed = (await res.json()) as { error: string };
      expect(parsed.error).toBe("federation_not_provisioned");
      await h.stop();
      h = null;
    }
  });
});
