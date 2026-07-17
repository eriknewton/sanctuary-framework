/**
 * Unit tests for the root-owned signed-freshness-token liveness oracle (Slice 5
 * S5-3). Real Ed25519 keys; injected clock/probe/IO. The gate verifies a
 * signature and never holds pf privilege; no cached green survives a flush.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GateLivenessOracle,
  verifyLivenessToken,
  createOracleLivenessProbe,
  canonicalLivenessPayload,
  createFsLivenessOracleOps,
  createFsLivenessTokenSource,
  GATE_LIVENESS_TOKEN_VERSION,
  type LivenessOracleOps,
  type LivenessTokenSource,
  type SignedLivenessToken,
} from "../../src/egress-gate/liveness-oracle.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const binding = { agentUid: 502, gatePort: 51000, generationId: 7 };

/** An in-memory oracle-ops harness with a settable clock + probe verdict. */
function harness(initial: { now: number; live: boolean }): {
  ops: LivenessOracleOps;
  source: LivenessTokenSource;
  set: (v: Partial<{ now: number; live: boolean }>) => void;
  removed: number[];
  tokenFor: (uid: number) => SignedLivenessToken | null;
} {
  const store = new Map<number, string>();
  const state = { ...initial };
  const removed: number[] = [];
  const ops: LivenessOracleOps = {
    writeToken: (uid, payload) => {
      store.set(uid, payload);
      return Promise.resolve();
    },
    removeToken: (uid) => {
      store.delete(uid);
      removed.push(uid);
      return Promise.resolve();
    },
    probe: (): Promise<PfLivenessResult> =>
      Promise.resolve(state.live ? { live: true, reasons: [] } : { live: false, reasons: ["anchor flushed"] }),
    now: () => state.now,
  };
  const source: LivenessTokenSource = {
    read: (uid) => Promise.resolve(store.get(uid) ?? null),
  };
  return {
    ops,
    source,
    set: (v) => Object.assign(state, v),
    removed,
    tokenFor: (uid) => {
      const raw = store.get(uid);
      return raw ? (JSON.parse(raw) as SignedLivenessToken) : null;
    },
  };
}

describe("egress-gate/liveness-oracle sign + verify", () => {
  it("publishes a signed live token a matching-binding probe reads as live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 2_000 });
    const token = await oracle.refresh(binding);
    expect(token).not.toBeNull();
    expect(token?.live).toBe(true);
    expect(token?.expires_at).toBe(3_000);

    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 1_500 });
    expect(await probe.check()).toEqual({ live: true, reasons: [] });
  });

  it("an absent token is not live (supervisor invalidated / never published)", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const emptySource: LivenessTokenSource = { read: () => Promise.resolve(null) };
    const probe = createOracleLivenessProbe({ source: emptySource, publicKey, binding, now: () => 1 });
    const result = await probe.check();
    expect(result.live).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/absent/);
  });

  it("an expired token is not live (staleness bounded by the TTL)", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 2_000 });
    await oracle.refresh(binding); // expires_at 3000
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 3_000 });
    const result = await probe.check();
    expect(result.live).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/expired/);
  });

  it("a token signed by a DIFFERENT key is not live (a non-root process cannot forge liveness)", async () => {
    const supervisor = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(attacker.privateKey, h.ops, { ttlMs: 2_000 });
    await oracle.refresh(binding);
    // Gate pins the SUPERVISOR public key; the attacker-signed token fails verify.
    const probe = createOracleLivenessProbe({
      source: h.source,
      publicKey: supervisor.publicKey,
      binding,
      now: () => 1_500,
    });
    const result = await probe.check();
    expect(result.live).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/signature invalid/);
  });

  it("a not-live probe INVALIDATES the token (returns null, removes it) rather than publishing live:false", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 2_000 });
    await oracle.refresh(binding); // live token published
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 1_500 });
    expect((await probe.check()).live).toBe(true);
    // pf flushed: the next refresh sees not-live and must invalidate, not publish live:false.
    h.set({ live: false });
    const result = await oracle.refresh(binding);
    expect(result).toBeNull();
    expect(h.removed).toContain(binding.agentUid);
    expect(h.tokenFor(binding.agentUid)).toBeNull();
    expect((await probe.check()).live).toBe(false); // absent -> deny
  });

  it("a probe THROW during refresh invalidates any prior live token (fail-closed), then rethrows", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 60_000 });
    await oracle.refresh(binding); // live token exists, long TTL
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 1_500 });
    expect((await probe.check()).live).toBe(true);
    // The pfctl probe throws on the next refresh; the old live token must NOT survive.
    const throwingOps = { ...h.ops, probe: () => Promise.reject(new Error("pfctl exploded")) };
    const throwingOracle = new GateLivenessOracle(privateKey, throwingOps, { ttlMs: 60_000 });
    await expect(throwingOracle.refresh(binding)).rejects.toThrow(/pfctl exploded/);
    expect(h.tokenFor(binding.agentUid)).toBeNull();
    expect((await probe.check()).live).toBe(false);
  });

  it("a probe throw AND a removeToken failure surfaces a combined loud error (double failure)", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const doubleFailOps = {
      ...h.ops,
      probe: () => Promise.reject(new Error("pfctl exploded")),
      removeToken: () => Promise.reject(new Error("rm EPERM")),
    };
    const oracle = new GateLivenessOracle(privateKey, doubleFailOps, { ttlMs: 2_000 });
    await expect(oracle.refresh(binding)).rejects.toThrow(/invalidation failed/);
  });

  it("the advertised binding cannot diverge from the enforced binding via caller mutation (Codex F3 round-2)", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 60_000 });
    // Publish a live token for agent 502 / port 51000 / gen 7 (=== binding).
    await oracle.refresh(binding);
    const callerBinding = { agentUid: binding.agentUid, gatePort: binding.gatePort, generationId: binding.generationId };
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding: callerBinding, now: () => 1_500 });
    // Advertised binding is the snapshot.
    expect(probe.binding).toEqual({ agentUid: 502, gatePort: 51000 });
    // Mutate the caller's object AFTER construction to a different principal.
    callerBinding.agentUid = 999;
    callerBinding.gatePort = 40000;
    // The advertised binding is unchanged AND check() still verifies against the
    // frozen 502/51000/7 snapshot -> the genuine 502 token verifies live, proving
    // the runtime path did not follow the mutation.
    expect(probe.binding).toEqual({ agentUid: 502, gatePort: 51000 });
    expect((await probe.check()).live).toBe(true);
  });

  it("the advertised binding object is FROZEN so it cannot be mutated after construction (Codex F3 round-3)", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 60_000 });
    await oracle.refresh(binding);
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 1_500 });
    expect(Object.isFrozen(probe.binding)).toBe(true);
    expect(Object.isFrozen(probe)).toBe(true);
    // Attempting to mutate the advertised binding to a different principal is a
    // no-op (frozen); the check-at-construction value and the runtime value stay
    // the same 502/51000, so the divergence bypass is structurally impossible.
    try {
      (probe.binding as { agentUid: number }).agentUid = 999;
    } catch {
      // strict-mode ESM throws on frozen mutation; either outcome is fine.
    }
    expect(probe.binding.agentUid).toBe(502);
    expect((await probe.check()).live).toBe(true);
  });

  it("a binding mismatch (agent/port/generation) is not live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 2_000 });
    await oracle.refresh(binding);
    const wrongGen = createOracleLivenessProbe({
      source: h.source,
      publicKey,
      binding: { ...binding, generationId: 8 },
      now: () => 1_500,
    });
    const r1 = await wrongGen.check();
    expect(r1.live).toBe(false);
    expect(r1.reasons.join(" ")).toMatch(/generation/);
    const wrongPort = createOracleLivenessProbe({
      source: h.source,
      publicKey,
      binding: { ...binding, gatePort: 40000 },
      now: () => 1_500,
    });
    expect((await wrongPort.check()).reasons.join(" ")).toMatch(/gate_port/);
  });

  it("a tampered claim (post-sign mutation) is not live", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    // Build a genuine live token, then extend expires_at without re-signing:
    // the claim change invalidates the Ed25519 signature.
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 2_000 });
    const token = await oracle.refresh(binding);
    expect(token).not.toBeNull();
    const tampered = JSON.stringify({ ...token, expires_at: 9_999_999 });
    const result = verifyLivenessToken({ raw: tampered, publicKey, binding, now: 1_500 });
    expect(result.live).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/signature invalid/);
  });

  it("an unparseable / malformed token is not live", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    expect(verifyLivenessToken({ raw: "{not json", publicKey, binding, now: 1 }).live).toBe(false);
    expect(
      verifyLivenessToken({ raw: JSON.stringify({ version: 999 }), publicKey, binding, now: 1 }).live,
    ).toBe(false);
  });

  it("NO CACHED GREEN SURVIVES A FLUSH: invalidate removes the token, next probe denies", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 1_000, live: true });
    const oracle = new GateLivenessOracle(privateKey, h.ops, { ttlMs: 60_000 }); // long TTL: only invalidate closes it
    await oracle.refresh(binding);
    const probe = createOracleLivenessProbe({ source: h.source, publicKey, binding, now: () => 1_500 });
    expect((await probe.check()).live).toBe(true);
    await oracle.invalidate(binding.agentUid); // a flush/drift-repair
    const after = await probe.check();
    expect(after.live).toBe(false);
    expect(h.removed).toContain(binding.agentUid);
  });

  it("rejects a non-positive TTL at construction", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const h = harness({ now: 0, live: true });
    expect(() => new GateLivenessOracle(privateKey, h.ops, { ttlMs: 0 })).toThrow(/positive number of ms/);
  });

  it("canonical payload is stable for equal claims", () => {
    const claims = {
      version: GATE_LIVENESS_TOKEN_VERSION,
      agent_uid: 502,
      gate_port: 51000,
      generation_id: 7,
      live: true,
      expires_at: 3000,
    } as const;
    expect(canonicalLivenessPayload(claims).equals(canonicalLivenessPayload({ ...claims }))).toBe(true);
  });
});

describe("egress-gate/liveness-oracle FS round-trip", () => {
  it("FS oracle ops write a gate-readable token the FS source verifies live, and invalidate removes it", async () => {
    const uid = process.getuid?.() ?? 0;
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const dir = await mkdtemp(join(tmpdir(), "s53-live-"));
    try {
      let clock = 1_000;
      const ops = createFsLivenessOracleOps({
        gateUid: uid,
        dir,
        now: () => clock,
        probe: () => Promise.resolve({ live: true, reasons: [] }),
      });
      const oracle = new GateLivenessOracle(privateKey, ops, { ttlMs: 5_000 });
      const fsBinding = { agentUid: uid, gatePort: 51234, generationId: 2 };
      await oracle.refresh(fsBinding);
      const source = createFsLivenessTokenSource(dir);
      const probe = createOracleLivenessProbe({ source, publicKey, binding: fsBinding, now: () => (clock = 2_000) });
      expect((await probe.check()).live).toBe(true);
      await oracle.invalidate(uid);
      expect((await probe.check()).live).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
