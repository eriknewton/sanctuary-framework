/**
 * INDEPENDENT refute suite (S5-3 review). Attempts to forge / replay / stale a
 * root-owned liveness token past the gate's verify. Every test here is an
 * ATTACK; the assertion is that the attack DENIES (live:false). A test that
 * showed live:true would be a real finding.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign } from "node:crypto";

import {
  GateLivenessOracle,
  canonicalLivenessPayload,
  verifyLivenessToken,
  createOracleLivenessProbe,
  GATE_LIVENESS_TOKEN_VERSION,
  type LivenessOracleOps,
  type LivenessProbeBinding,
  type SignedLivenessToken,
  type LivenessTokenClaims,
} from "../../src/egress-gate/liveness-oracle.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const BINDING: LivenessProbeBinding = { agentUid: 502, gatePort: 51000, generationId: 7 };

function memOps(store: Map<number, string>, clock: () => number, live = true): LivenessOracleOps {
  return {
    writeToken: (uid, payload) => {
      store.set(uid, payload);
      return Promise.resolve();
    },
    removeToken: (uid) => {
      store.delete(uid);
      return Promise.resolve();
    },
    probe: (): Promise<PfLivenessResult> => Promise.resolve({ live, reasons: [] }),
    now: clock,
  };
}

describe("REFUTE liveness-oracle: forge / replay / stale attempts must all deny", () => {
  it("ATTACK forged signature (attacker key) — must NOT be live", async () => {
    const legit = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const claims: LivenessTokenClaims = {
      version: GATE_LIVENESS_TOKEN_VERSION,
      agent_uid: BINDING.agentUid,
      gate_port: BINDING.gatePort,
      generation_id: BINDING.generationId,
      live: true,
      expires_at: 10_000,
    };
    const sig = edSign(null, canonicalLivenessPayload(claims), attacker.privateKey).toString("base64");
    const forged: SignedLivenessToken = { ...claims, sig };
    const res = verifyLivenessToken({
      raw: JSON.stringify(forged),
      publicKey: legit.publicKey,
      binding: BINDING,
      now: 1_000,
    });
    expect(res.live).toBe(false); // forge failed => confirmed safe
  });

  it("ATTACK flip live:false->true WITHOUT re-signing — must NOT be live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    // supervisor signs an honest live:false token
    const claims: LivenessTokenClaims = {
      version: GATE_LIVENESS_TOKEN_VERSION,
      agent_uid: BINDING.agentUid,
      gate_port: BINDING.gatePort,
      generation_id: BINDING.generationId,
      live: false,
      expires_at: 10_000,
    };
    const sig = edSign(null, canonicalLivenessPayload(claims), privateKey).toString("base64");
    // attacker edits the on-disk JSON to live:true, keeping the old signature
    const tampered = JSON.stringify({ ...claims, live: true, sig });
    const res = verifyLivenessToken({ raw: tampered, publicKey, binding: BINDING, now: 1_000 });
    expect(res.live).toBe(false);
  });

  it("ATTACK cross-generation replay (token gen A onto gate expecting gen B) — must NOT be live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    const oracle = new GateLivenessOracle(privateKey, memOps(store, () => 1_000), { ttlMs: 60_000 });
    // supervisor publishes a genuine LIVE token for generation 7
    await oracle.refresh(BINDING);
    const raw = store.get(BINDING.agentUid)!;
    // gate now runs on generation 8 (a new G5). The old, unexpired, correctly
    // signed gen-7 token must NOT satisfy the gen-8 binding.
    const res = verifyLivenessToken({
      raw,
      publicKey,
      binding: { ...BINDING, generationId: 8 },
      now: 1_500,
    });
    expect(res.live).toBe(false);
  });

  it("ATTACK cross-agent / cross-port replay — must NOT be live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    const oracle = new GateLivenessOracle(privateKey, memOps(store, () => 1_000), { ttlMs: 60_000 });
    await oracle.refresh(BINDING);
    const raw = store.get(BINDING.agentUid)!;
    // replay onto a different agent uid
    expect(
      verifyLivenessToken({ raw, publicKey, binding: { ...BINDING, agentUid: 503 }, now: 1_500 }).live,
    ).toBe(false);
    // replay onto a different gate port
    expect(
      verifyLivenessToken({ raw, publicKey, binding: { ...BINDING, gatePort: 51001 }, now: 1_500 }).live,
    ).toBe(false);
  });

  it("ATTACK use a token exactly at expiry (now == expires_at) — must NOT be live (>= enforced)", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    let clock = 1_000;
    const oracle = new GateLivenessOracle(privateKey, memOps(store, () => clock), { ttlMs: 2_000 });
    await oracle.refresh(BINDING); // expires_at = 3_000
    const raw = store.get(BINDING.agentUid)!;
    // one ms before expiry: live
    expect(verifyLivenessToken({ raw, publicKey, binding: BINDING, now: 2_999 }).live).toBe(true);
    // exactly at expiry: MUST deny
    expect(verifyLivenessToken({ raw, publicKey, binding: BINDING, now: 3_000 }).live).toBe(false);
    // past expiry: deny
    expect(verifyLivenessToken({ raw, publicKey, binding: BINDING, now: 3_001 }).live).toBe(false);
  });

  it("ATTACK absent / unparseable / malformed token — must NOT be live", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    expect(verifyLivenessToken({ raw: null, publicKey, binding: BINDING, now: 1 }).live).toBe(false);
    expect(verifyLivenessToken({ raw: "{not json", publicKey, binding: BINDING, now: 1 }).live).toBe(false);
    expect(verifyLivenessToken({ raw: "{}", publicKey, binding: BINDING, now: 1 }).live).toBe(false);
    // valid-looking but sig field missing/empty
    expect(
      verifyLivenessToken({
        raw: JSON.stringify({
          version: 1,
          agent_uid: 502,
          gate_port: 51000,
          generation_id: 7,
          live: true,
          expires_at: 10_000,
          sig: "",
        }),
        publicKey,
        binding: BINDING,
        now: 1,
      }).live,
    ).toBe(false);
  });

  it("ATTACK oracle probe reports not-live but token otherwise valid — must NOT be live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    // probe returns live:false; oracle still signs a token but with live:false
    const oracle = new GateLivenessOracle(privateKey, memOps(store, () => 1_000, false), { ttlMs: 60_000 });
    await oracle.refresh(BINDING);
    const raw = store.get(BINDING.agentUid)!;
    expect(verifyLivenessToken({ raw, publicKey, binding: BINDING, now: 1_500 }).live).toBe(false);
  });

  it("ATTACK token-source read throws — probe must fail closed (not live)", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const probe = createOracleLivenessProbe({
      source: { read: () => Promise.reject(new Error("EACCES boom")) },
      publicKey,
      binding: BINDING,
      now: () => 1_000,
    });
    const res = await probe.check();
    expect(res.live).toBe(false);
  });

  it("ATTACK no cached green survives invalidate (probe re-reads every call)", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const store = new Map<number, string>();
    const oracle = new GateLivenessOracle(privateKey, memOps(store, () => 1_000), { ttlMs: 60_000 });
    await oracle.refresh(BINDING);
    const probe = createOracleLivenessProbe({ source: { read: (u) => Promise.resolve(store.get(u) ?? null) }, publicKey, binding: BINDING, now: () => 1_500 });
    expect((await probe.check()).live).toBe(true);
    await oracle.invalidate(BINDING.agentUid);
    expect((await probe.check()).live).toBe(false); // immediately denies, no cache
  });
});
