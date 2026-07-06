/**
 * Fleet control plane PR-3: SCHEDULED RE-RESOLVE + AUTO-CAPTURE tests.
 *
 * Definition-of-Done:
 *  1. diffCapTransition (pure): no-prior / identical -> no change; a shrink (lower
 *     cap, unlimited->finite, tier drop) -> downgrade with the dropped node ids;
 *     a lift -> upgrade with no dropped ids.
 *  2. runFleetReResolve AUTO-CAPTURE: a never-activated (absent) over-cap fleet
 *     records its CURRENT durable admitted count as the permanent grandfather
 *     baseline, ONCE (grow-only, idempotent), and it SURVIVES (persisted). A fleet
 *     within the free cap captures nothing.
 *  3. REVOCATION: a paid, in-window license whose id is on the signed revocation
 *     list is forced to Community (revoked:true), preserving its grandfather
 *     baseline; an un-revoked license keeps its paid cap.
 *  4. EXPIRY: a license past notAfter+grace resolves to Community and logs a
 *     downgrade with the dropped ids.
 *  5. GRACE: a license in its grace window keeps the paid cap (graceActive).
 *  6. A downgrade-log entry is appended on a real transition (best-effort).
 *
 * A real Ed25519 issuer key signs the fixtures.
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
  readFleetActivation,
} from "../../src/entitlement/activation.js";
import { COMMUNITY_FREE_NODE_CAP } from "../../src/entitlement/fleet-cap.js";
import {
  signRevocationList,
  verifyPushedRevocationList,
  writeRevocationList,
  type RevocationListPayload,
} from "../../src/entitlement/revocation-list.js";
import { readDowngradeLog } from "../../src/entitlement/downgrade-log.js";
import {
  diffCapTransition,
  runFleetReResolve,
  type PriorCapState,
  type ReResolveRosterView,
} from "../../src/entitlement/re-resolve.js";

const issuer = generateKeypair();
const master = randomBytes(32);
const NOW = 1_800_000_000;
const LICENSE_ID = "lic-team-1";

function v2Claims(overrides: Partial<EntitlementClaimsV2> = {}): EntitlementClaimsV2 {
  return {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: LICENSE_ID,
    subject: "fleet-op",
    tier: "team",
    pricingUnit: "node",
    entitledCount: 25,
    period: "monthly",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
    graceUntil: NOW + 100 + 14 * 86_400,
    featureFlags: ["roster"],
    issuer: "issuer-fp",
    ...overrides,
  };
}

function signV2(claims: EntitlementClaimsV2): EntitlementToken {
  return {
    claims,
    signature: toBase64url(ed25519.sign(buildEntitlementMessageV2(claims), issuer.privateKey)),
  };
}

function roster(admittedCount: number, ids?: string[]): ReResolveRosterView {
  return {
    available: true,
    admittedCount,
    orderedNodeIds: ids ?? Array.from({ length: admittedCount }, (_, i) => `node-${i}`),
  };
}

async function pushRevocation(
  storage: MemoryStorage,
  ids: string[],
  version = 1,
): Promise<void> {
  const payload: RevocationListPayload = {
    version,
    revokedLicenseIds: ids,
    issuer: "issuer-fp",
    issuedAt: "2026-07-06T00:00:00.000Z",
  };
  const signed = signRevocationList(payload, (m) => ed25519.sign(m, issuer.privateKey));
  const v = verifyPushedRevocationList(signed, issuer.publicKey, 0);
  expect(v.ok).toBe(true);
  if (v.ok) await writeRevocationList(storage, master, v.payload);
}

// ── diffCapTransition (pure) ─────────────────────────────────────────────────

describe("diffCapTransition", () => {
  const paidCap = { maxNodes: 25, paid: true, tier: "team", reason: "granted" as const, graceActive: false };
  const communityCap = { maxNodes: 5, paid: false, tier: "community", reason: "expired" as const, graceActive: false };

  it("no prior + within-cap roster -> no change", () => {
    const t = diffCapTransition(null, paidCap, roster(3));
    expect(t.changed).toBe(false);
  });

  it("no prior + over-cap roster -> logs a downgrade with the dropped ids", () => {
    const t = diffCapTransition(null, communityCap, roster(8));
    expect(t).toEqual({
      changed: true,
      kind: "downgrade",
      droppedNodeIds: ["node-5", "node-6", "node-7"],
    });
  });

  it("identical prior -> no change", () => {
    const prior: PriorCapState = { tier: "team", maxNodes: 25 };
    expect(diffCapTransition(prior, paidCap, roster(3)).changed).toBe(false);
  });

  it("paid -> community (cap shrink) is a downgrade with dropped ids", () => {
    const prior: PriorCapState = { tier: "team", maxNodes: 25 };
    const t = diffCapTransition(prior, communityCap, roster(8));
    expect(t.kind).toBe("downgrade");
    expect(t.droppedNodeIds).toEqual(["node-5", "node-6", "node-7"]);
  });

  it("community -> paid (cap lift) is an upgrade with no dropped ids", () => {
    const prior: PriorCapState = { tier: "community", maxNodes: 5 };
    const t = diffCapTransition(prior, paidCap, roster(8));
    expect(t.kind).toBe("upgrade");
    expect(t.droppedNodeIds).toEqual([]);
  });

  it("finite -> unlimited is an upgrade", () => {
    const prior: PriorCapState = { tier: "team", maxNodes: 25 };
    const unlimited = { maxNodes: null, paid: true, tier: "fleet", reason: "granted" as const, graceActive: false };
    expect(diffCapTransition(prior, unlimited, roster(50)).kind).toBe("upgrade");
  });

  it("unlimited -> finite is a downgrade", () => {
    const prior: PriorCapState = { tier: "fleet", maxNodes: null };
    const t = diffCapTransition(prior, paidCap, roster(30));
    expect(t.kind).toBe("downgrade");
    expect(t.droppedNodeIds.length).toBe(5); // nodes 25..29 leave
  });
});

// ── AUTO-CAPTURE ─────────────────────────────────────────────────────────────

describe("runFleetReResolve - grandfather auto-capture", () => {
  it("captures the durable count for a never-activated OVER-CAP fleet, ONCE, and it survives", async () => {
    const storage = new MemoryStorage();
    // No activation record at all (never activated) + 9 admitted nodes (> free 5).
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(9),
      prior: null,
    });
    expect(result.grandfatherCaptured).toBe(true);
    // Community cap, but the FLOOR is now the captured 9, not 5.
    expect(result.cap.tier).toBe("community");
    expect(result.cap.maxNodes).toBe(9);

    // Persisted + survives: a fresh read honors the baseline.
    const record = await readFleetActivation(storage, master);
    expect(record.status).toBe("valid");
    if (record.status === "valid") {
      expect(record.data.grandfatheredBaseline).toBe(9);
    }

    // A second pass does NOT re-capture (idempotent) and does NOT lower it.
    const again = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(3), // even if the count later drops, the floor holds
      prior: { tier: result.cap.tier, maxNodes: result.cap.maxNodes },
    });
    expect(again.grandfatherCaptured).toBe(false);
    expect(again.cap.maxNodes).toBe(9);
  });

  it("does NOT capture for a fleet WITHIN the free cap", async () => {
    const storage = new MemoryStorage();
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(4),
      prior: null,
    });
    expect(result.grandfatherCaptured).toBe(false);
    expect(result.cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect((await readFleetActivation(storage, master)).status).toBe("absent");
  });

  it("logs a grandfather_capture entry on capture", async () => {
    const storage = new MemoryStorage();
    await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(9),
      prior: null,
    });
    const log = await readDowngradeLog(storage, master);
    expect(log.entries.some((e) => e.kind === "grandfather_capture")).toBe(true);
  });
});

// ── REVOCATION ───────────────────────────────────────────────────────────────

describe("runFleetReResolve - revocation forces Community", () => {
  it("forces a paid in-window license to Community when its id is revoked", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    await pushRevocation(storage, [LICENSE_ID]);

    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(10),
      prior: { tier: "team", maxNodes: 25 },
    });
    expect(result.revoked).toBe(true);
    expect(result.cap.paid).toBe(false);
    expect(result.cap.tier).toBe("community");
    expect(result.cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
  });

  it("keeps the paid cap when the license id is NOT on the list", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    await pushRevocation(storage, ["some-other-license"]);

    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(10),
      prior: { tier: "team", maxNodes: 25 },
    });
    expect(result.revoked).toBe(false);
    expect(result.cap.paid).toBe(true);
    expect(result.cap.maxNodes).toBe(25);
  });

  it("a revoked-but-grandfathered fleet keeps its grandfathered floor", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 12);
    await pushRevocation(storage, [LICENSE_ID]);

    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(12),
      prior: { tier: "team", maxNodes: 25 },
    });
    expect(result.revoked).toBe(true);
    expect(result.cap.tier).toBe("community");
    // The grandfathered floor (12) is preserved, not stripped to 5.
    expect(result.cap.maxNodes).toBe(12);
  });
});

// ── EXPIRY + GRACE ───────────────────────────────────────────────────────────

describe("runFleetReResolve - expiry and grace", () => {
  it("EXPIRED (past grace) resolves to Community and logs a downgrade", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    // now is far past notAfter + grace.
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW + 100 + 20 * 86_400,
      roster: roster(9),
      prior: { tier: "team", maxNodes: 25 },
    });
    expect(result.cap.paid).toBe(false);
    expect(result.cap.tier).toBe("community");
    const log = await readDowngradeLog(storage, master);
    expect(log.entries.some((e) => e.kind === "downgrade")).toBe(true);
    // The dropped node ids are recorded for the "which nodes left" answer.
    const downgrade = log.entries.find((e) => e.kind === "downgrade");
    expect(downgrade?.droppedNodeIds.length).toBeGreaterThan(0);
  });

  it("IN GRACE keeps the paid cap (graceActive)", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    // now is in (notAfter, graceUntil].
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW + 100 + 5 * 86_400,
      roster: roster(10),
      prior: null,
    });
    expect(result.cap.paid).toBe(true);
    expect(result.cap.graceActive).toBe(true);
    expect(result.cap.maxNodes).toBe(25);
  });
});

// ── fail-closed / never-throws ────────────────────────────────────────────────

describe("runFleetReResolve - fail-closed posture", () => {
  it("an unavailable roster + absent record resolves to the plain community floor, no capture", async () => {
    const storage = new MemoryStorage();
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: { available: false, admittedCount: 0, orderedNodeIds: [] },
      prior: null,
    });
    expect(result.grandfatherCaptured).toBe(false);
    expect(result.cap.tier).toBe("community");
    expect(result.cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
  });

  it("surfaces a corrupt revocation list without stripping a paid fleet", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    // A revocation list written under a DIFFERENT master reads invalid here.
    await writeRevocationList(storage, randomBytes(32), {
      version: 1,
      revokedLicenseIds: [LICENSE_ID],
      issuer: "issuer-fp",
      issuedAt: "2026-07-06T00:00:00.000Z",
    });
    const result = await runFleetReResolve({
      storage,
      master,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      roster: roster(10),
      prior: null,
    });
    // The corrupt list is surfaced, but the paid fleet is NOT stripped.
    expect(result.revocationListUnreadable).toBe(true);
    expect(result.revoked).toBe(false);
    expect(result.cap.paid).toBe(true);
  });
});
