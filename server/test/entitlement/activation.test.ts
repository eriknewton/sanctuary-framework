/**
 * Fleet control plane PR-2: ACTIVATION STATE - signed persistence + fail-closed
 * resolve-on-read tests.
 *
 * Definition-of-Done:
 *  1. activateFleet verifies a pasted license through the shipped Ed25519 core
 *     against the pinned issuer key and persists a master-MAC'd record; a
 *     malformed / unverifiable / expired paste is REJECTED and persists nothing.
 *  2. resolveActivation re-resolves the STORED token against the CURRENT clock,
 *     so a license that was valid at activation resolves to community once
 *     expired - no silent free-ride past expiry.
 *  3. Fail-closed reads: absent → community(no_license); tampered/wrong-key MAC →
 *     community(unreadable), never a paid grant, never trusting an on-disk
 *     baseline inside a failed MAC.
 *  4. Grandfather baseline is persisted under the MAC and honored on resolve.
 *  5. decodeLicense accepts base64url + raw-JSON encodings and fails to null on
 *     garbage (never throws).
 *
 * A real Ed25519 issuer key signs the fixtures so a dropped verify fails here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import {
  ENTITLEMENT_TOKEN_VERSION_V2,
  buildEntitlementMessageV2,
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "../../src/entitlement/token.js";
import {
  FLEET_ACTIVATION_META_KEY,
  activateFleet,
  clearFleetActivation,
  decodeLicense,
  readFleetActivation,
  resolveActivation,
  writeFleetActivation,
} from "../../src/entitlement/activation.js";
import { COMMUNITY_FREE_NODE_CAP } from "../../src/entitlement/fleet-cap.js";

const issuer = generateKeypair();
const wrongIssuer = generateKeypair();
const master = randomBytes(32);
const wrongMaster = randomBytes(32);
const NOW = 1_800_000_000;
const ISSUER_ID = "issuer-fingerprint-team";

function v2Claims(overrides: Partial<EntitlementClaimsV2> = {}): EntitlementClaimsV2 {
  return {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: "lic-activate-1",
    subject: "fleet-op",
    tier: "team",
    pricingUnit: "node",
    entitledCount: 25,
    period: "monthly",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
    graceUntil: NOW + 100 + 14 * 86_400,
    featureFlags: ["roster", "policy-dist"],
    issuer: ISSUER_ID,
    ...overrides,
  };
}

function signV2(
  claims: EntitlementClaimsV2,
  privateKey: Uint8Array = issuer.privateKey,
): EntitlementToken {
  const message = buildEntitlementMessageV2(claims);
  return { claims, signature: toBase64url(ed25519.sign(message, privateKey)) };
}

/** The pasted-license string an operator would copy: base64url of the token JSON. */
function pasted(token: EntitlementToken): string {
  return toBase64url(stringToBytes(JSON.stringify(token)));
}

// ── activateFleet: verify-before-persist ─────────────────────────────────────

describe("activateFleet - verifies before persisting", () => {
  it("activates a valid pasted license and persists a MAC'd record", async () => {
    const storage = new MemoryStorage();
    const result = await activateFleet({
      storage,
      master,
      pastedLicense: pasted(signV2(v2Claims())),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.tier).toBe("team");
      expect(result.cap.maxNodes).toBe(25);
      expect(result.cap.paid).toBe(true);
    }
    // The record is on disk and authenticates under the master.
    const record = await readFleetActivation(storage, master);
    expect(record.status).toBe("valid");
  });

  it("REJECTS a paste signed by the WRONG issuer and persists nothing", async () => {
    const storage = new MemoryStorage();
    const result = await activateFleet({
      storage,
      master,
      pastedLicense: pasted(signV2(v2Claims(), wrongIssuer.privateKey)),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("verify_failed");
    expect(await readFleetActivation(storage, master)).toStrictEqual({
      status: "absent",
    });
  });

  it("REJECTS an already-expired paste and persists nothing", async () => {
    const storage = new MemoryStorage();
    const result = await activateFleet({
      storage,
      master,
      pastedLicense: pasted(signV2(v2Claims())),
      issuerPublicKey: issuer.publicKey,
      // Past notAfter AND graceUntil.
      now: NOW + 100 + 15 * 86_400,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("verify_failed");
    expect((await readFleetActivation(storage, master)).status).toBe("absent");
  });

  it("REJECTS a garbage paste as malformed_token, persists nothing", async () => {
    const storage = new MemoryStorage();
    const result = await activateFleet({
      storage,
      master,
      pastedLicense: "this-is-not-a-license",
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("malformed_token");
    expect((await readFleetActivation(storage, master)).status).toBe("absent");
  });

  it("captures the grandfathered baseline into the persisted record", async () => {
    const storage = new MemoryStorage();
    await activateFleet({
      storage,
      master,
      pastedLicense: pasted(signV2(v2Claims())),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
      grandfatheredBaseline: 8,
    });
    const record = await readFleetActivation(storage, master);
    expect(record.status).toBe("valid");
    if (record.status === "valid") {
      expect(record.data.grandfatheredBaseline).toBe(8);
    }
  });
});

// ── resolveActivation: re-resolve against the current clock ──────────────────

describe("resolveActivation - fail-closed resolve-on-read", () => {
  it("no activation record → community floor, reason no_license", async () => {
    const storage = new MemoryStorage();
    const cap = await resolveActivation(storage, master, issuer.publicKey, NOW);
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("no_license");
  });

  it("a valid activation resolves to the paid cap while in-window", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    const cap = await resolveActivation(storage, master, issuer.publicKey, NOW);
    expect(cap.maxNodes).toBe(25);
    expect(cap.paid).toBe(true);
    expect(cap.reason).toBe("granted");
  });

  it("a stored license that is now EXPIRED resolves to community (no free-ride)", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    const cap = await resolveActivation(
      storage,
      master,
      issuer.publicKey,
      NOW + 100 + 15 * 86_400, // past grace
    );
    expect(cap.paid).toBe(false);
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.reason).toBe("expired");
  });

  it("a stored license inside GRACE still resolves to the paid cap", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    const cap = await resolveActivation(
      storage,
      master,
      issuer.publicKey,
      NOW + 100 + 7 * 86_400, // after notAfter, inside 14-day grace
    );
    expect(cap.paid).toBe(true);
    expect(cap.maxNodes).toBe(25);
    expect(cap.graceActive).toBe(true);
  });

  it("a valid record still honors the grandfathered baseline when the token is expired", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 12);
    const cap = await resolveActivation(
      storage,
      master,
      issuer.publicKey,
      NOW + 100 + 15 * 86_400, // expired → community, but baseline is 12
    );
    expect(cap.paid).toBe(false);
    expect(cap.maxNodes).toBe(12);
    expect(cap.reason).toBe("grandfathered");
  });

  it("a WRONG-master read → community(unreadable), never a paid grant, baseline NOT trusted", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 12);
    // Read under the wrong master: the MAC fails → invalid → community floor, and
    // the on-disk baseline (12, inside the failed MAC) is NOT honored (falls to 5).
    const cap = await resolveActivation(storage, wrongMaster, issuer.publicKey, NOW);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("unreadable");
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
  });

  it("a TAMPERED on-disk record → community(unreadable)", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    // Corrupt the stored bytes.
    await storage.write(
      "_meta",
      FLEET_ACTIVATION_META_KEY,
      stringToBytes('{"__sanctuary_fleet_activation_v1":true,"data":{"token":{"claims":{},"signature":"x"},"grandfatheredBaseline":0,"activatedAt":"x"},"mac":"AAAA"}'),
    );
    const cap = await resolveActivation(storage, master, issuer.publicKey, NOW);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("unreadable");
  });

  it("clearFleetActivation returns the fortress to the community floor", async () => {
    const storage = new MemoryStorage();
    await writeFleetActivation(storage, master, signV2(v2Claims()), 0);
    await clearFleetActivation(storage);
    const cap = await resolveActivation(storage, master, issuer.publicKey, NOW);
    expect(cap.reason).toBe("no_license");
    expect(cap.paid).toBe(false);
  });
});

// ── readFleetActivation: tri-state ───────────────────────────────────────────

describe("readFleetActivation - tri-state", () => {
  it("absent when nothing is written", async () => {
    const storage = new MemoryStorage();
    expect(await readFleetActivation(storage, master)).toStrictEqual({
      status: "absent",
    });
  });

  it("invalid when the marker is missing", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      FLEET_ACTIVATION_META_KEY,
      stringToBytes('{"data":{},"mac":"AAAA"}'),
    );
    expect((await readFleetActivation(storage, master)).status).toBe("invalid");
  });

  it("invalid when the stored baseline is negative (forged record)", async () => {
    const storage = new MemoryStorage();
    // A hand-forged record with a negative baseline must not authenticate.
    await storage.write(
      "_meta",
      FLEET_ACTIVATION_META_KEY,
      stringToBytes('{"__sanctuary_fleet_activation_v1":true,"data":{"token":{"claims":{},"signature":"x"},"grandfatheredBaseline":-1,"activatedAt":"x"},"mac":"AAAA"}'),
    );
    expect((await readFleetActivation(storage, master)).status).toBe("invalid");
  });
});

// ── decodeLicense ────────────────────────────────────────────────────────────

describe("decodeLicense", () => {
  it("decodes a base64url-encoded token", () => {
    const token = signV2(v2Claims());
    const decoded = decodeLicense(pasted(token));
    expect(decoded).not.toBeNull();
    expect(decoded?.signature).toBe(token.signature);
  });

  it("decodes a raw-JSON token object string", () => {
    const token = signV2(v2Claims());
    const decoded = decodeLicense(JSON.stringify(token));
    expect(decoded).not.toBeNull();
    expect(decoded?.signature).toBe(token.signature);
  });

  it("returns null (never throws) on garbage, empty, or non-token JSON", () => {
    expect(decodeLicense("")).toBeNull();
    expect(decodeLicense("   ")).toBeNull();
    expect(decodeLicense("!!!not base64!!!")).toBeNull();
    expect(decodeLicense('{"foo":1}')).toBeNull();
    expect(decodeLicense(toBase64url(stringToBytes('{"foo":1}')))).toBeNull();
  });
});
