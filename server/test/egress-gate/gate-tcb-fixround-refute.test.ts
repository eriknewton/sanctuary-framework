/**
 * INDEPENDENT refute suite for the S5-3 TCB fix-round (Codex F1/F2/F3/F4).
 * Every test is an ATTACK on one of the four new guards; the assertion is that
 * the bypass FAILS (throw / deny / per-CONNECT re-probe). Written by the Family-A
 * refute reviewer re-checking the fold, distinct from the builder's own suite.
 */

import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHash, generateKeyPairSync } from "node:crypto";

import {
  createExclusiveEgressGate,
  GATE_BIND_HOST,
  type EgressGateEvent,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import { createGateClientAuthenticator, decideGateClientAuth } from "../../src/egress-gate/gate-client-auth.js";
import {
  GATE_CREDENTIAL_VERSION,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";
import {
  planGateAccountProvision,
  GateUidCollisionError,
} from "../../src/egress-gate/gate-account.js";
import {
  GateLivenessOracle,
  createOracleLivenessProbe,
  verifyLivenessToken,
  type LivenessTokenSource,
} from "../../src/egress-gate/liveness-oracle.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";
import type { ExclusiveEgressGatePolicy } from "../../src/castle-wall/allowlist/gate-derivation.js";

const AGENT_UID = 502;
const GATE_PORT = 47201;
const GATE_HOME = "/var/sanctuary-agents/sanctuary-gate-hermes";
const sha256Hex = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

const policy: ExclusiveEgressGatePolicy = { agent_uid: AGENT_UID, gate_port: GATE_PORT };
const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: 7,
  secret_sha256: sha256Hex("deadbeef"),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
const liveProbe: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };
// TCB gates additionally require the oracle-shape probe (coalescing:"forbidden"
// + a policy-matching binding); `liveProbe` above stays marker-less for the
// legacy (non-TCB) paths under test.
const tcbLiveProbe: GateLivenessProbe = {
  coalescing: "forbidden",
  binding: { agentUid: AGENT_UID, gatePort: GATE_PORT },
  check: () => Promise.resolve({ live: true, reasons: [] }),
};

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// F1: cross-principal clientAuth is refused at construction.
// ---------------------------------------------------------------------------
describe("F1 refute: cross-principal client authenticator", () => {
  it("REFUSES to build a gate whose authenticator serves a DIFFERENT uid than policy", () => {
    const wrongUidAuth = createGateClientAuthenticator({ agentUid: AGENT_UID + 1, acceptSource });
    expect(() =>
      createExclusiveEgressGate({ policy, rules: [], livenessProbe: liveProbe, clientAuth: wrongUidAuth }),
    ).toThrow(/must equal policy\.agent_uid/);
  });

  it("builds when the authenticator uid matches policy (control; TCB needs the oracle-shape probe)", () => {
    const okAuth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(() =>
      createExclusiveEgressGate({ policy, rules: [], livenessProbe: tcbLiveProbe, clientAuth: okAuth, peerRunner: { run: () => Promise.resolve({ code: 1, stdout: "" }) } }),
    ).not.toThrow();
  });

  it("ATTACK (second-family HIGH): a TCB gate wired to a marker-less legacy probe must be REFUSED, never defaulted to single-flight", () => {
    const okAuth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(() =>
      createExclusiveEgressGate({ policy, rules: [], livenessProbe: liveProbe, clientAuth: okAuth, peerRunner: { run: () => Promise.resolve({ code: 1, stdout: "" }) } }),
    ).toThrow(/TCB mode \(clientAuth present\) requires an oracle-shape liveness probe/);
  });

  it("even with a VALID credential a wrong peer uid still DENIES at runtime (bearer never overrides peer)", () => {
    const decision = decideGateClientAuth({
      agentUid: AGENT_UID,
      peer: { kind: "resolved", uid: AGENT_UID + 9, pid: 1 },
      credential: { ok: true },
    });
    expect(decision.allow).toBe(false);
    if (!decision.allow) expect(decision.reason).toBe("peer_uid_mismatch");
  });
});

// ---------------------------------------------------------------------------
// F2: gate uid colliding with agent/operator uid is excluded.
// ---------------------------------------------------------------------------
describe("F2 refute: gate-uid collision exclusion", () => {
  const opts = (excludeUids: number[]) => ({
    agentId: "hermes",
    agentUid: AGENT_UID,
    ceiling: 400,
    homeDirectory: GATE_HOME,
    excludeUids,
  });

  it("REFUSES a `skip` plan whose existing uid IS the confined agent uid", () => {
    // Existing sanctuary-gate-hermes account already sits on the agent uid.
    expect(() =>
      planGateAccountProvision(opts([AGENT_UID]), { existingUid: AGENT_UID, highestAssignedUid: 600 }),
    ).toThrow(GateUidCollisionError);
  });

  it("MOVES a `create` plan whose computed uid lands on an operator uid", () => {
    // ceiling 501, highest 500 => create uid = max(501, 501) = 501 (operator).
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 501, homeDirectory: GATE_HOME, excludeUids: [501] },
      { existingUid: undefined, highestAssignedUid: 500 },
    );
    expect(plan.action).toBe("create");
    expect(plan.uid).toBe(AGENT_UID + 1);
  });

  it("does NOT falsely refuse a legitimate distinct create uid (control)", () => {
    const plan = planGateAccountProvision(opts([AGENT_UID, 501]), { existingUid: undefined, highestAssignedUid: 700 });
    expect(plan.action).toBe("create");
    expect(plan.uid).toBe(701);
  });

  it("CLOSED (Codex round-3): with excludeUids OMITTED the agent-uid collision is STILL refused", () => {
    // The prior round left the agent-uid exclusion caller-supplied; round-3 made
    // `agentUid` a REQUIRED, always-excluded field. Omitting excludeUids no
    // longer lets a pre-existing sanctuary-gate account at the agent uid pass.
    expect(() =>
      planGateAccountProvision(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 400, homeDirectory: GATE_HOME },
        { existingUid: AGENT_UID, highestAssignedUid: 600 },
      ),
    ).toThrow(GateUidCollisionError);
  });
});

// ---------------------------------------------------------------------------
// F3: liveness probe binding cross-check.
// ---------------------------------------------------------------------------
describe("F3 refute: cross-principal liveness probe binding", () => {
  const source: LivenessTokenSource = { read: () => Promise.resolve(null) };
  const { publicKey } = generateKeyPairSync("ed25519");

  it("REFUSES a gate whose oracle probe is bound to a DIFFERENT agent/port", () => {
    const foreignProbe = createOracleLivenessProbe({
      source,
      publicKey,
      binding: { agentUid: 999, gatePort: GATE_PORT, generationId: 7 },
    });
    expect(() =>
      createExclusiveEgressGate({ policy, rules: [], livenessProbe: foreignProbe }),
    ).toThrow(/must match policy/);
  });

  it("REFUSES a gate whose oracle probe is bound to a DIFFERENT port", () => {
    const foreignPort = createOracleLivenessProbe({
      source,
      publicKey,
      binding: { agentUid: AGENT_UID, gatePort: GATE_PORT + 1, generationId: 7 },
    });
    expect(() =>
      createExclusiveEgressGate({ policy, rules: [], livenessProbe: foreignPort }),
    ).toThrow(/must match policy/);
  });

  it("builds when the probe binding matches policy (control)", () => {
    const okProbe = createOracleLivenessProbe({
      source,
      publicKey,
      binding: { agentUid: AGENT_UID, gatePort: GATE_PORT, generationId: 7 },
    });
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: okProbe })).not.toThrow();
  });

  it("a binding-less legacy probe is accepted as-is (documented safe path)", () => {
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: liveProbe })).not.toThrow();
  });

  it("a CORRECTLY-SIGNED live token for agent A is not-live when verified for agent B (replay refused at runtime)", async () => {
    const { privateKey, publicKey: pk } = generateKeyPairSync("ed25519");
    const oracle = new GateLivenessOracle(privateKey, {
      writeToken: () => Promise.resolve(),
      removeToken: () => Promise.resolve(),
      probe: () => Promise.resolve({ live: true, reasons: [] }),
      now: () => 1000,
    });
    // Token minted for agent A / port GATE_PORT / gen 7, genuinely live+signed.
    const token = await oracle.refresh({ agentUid: AGENT_UID, gatePort: GATE_PORT, generationId: 7 });
    const res = verifyLivenessToken({
      raw: JSON.stringify(token),
      publicKey: pk,
      binding: { agentUid: AGENT_UID + 1, gatePort: GATE_PORT, generationId: 7 }, // wrong agent
      now: 1500,
    });
    expect(res.live).toBe(false);
    expect(res.reasons.join(" ")).toMatch(/agent_uid/);
  });
});

// ---------------------------------------------------------------------------
// F4: singleFlightLiveness:false => per-CONNECT re-probe (no shared green).
// ---------------------------------------------------------------------------
describe("F4 refute: per-CONNECT liveness under singleFlightLiveness:false", () => {
  const running: Array<{ close: () => Promise<void> }> = [];
  afterEach(async () => {
    for (const r of running.splice(0)) await r.close();
  });

  function startEphemeral(probe: GateLivenessProbe, singleFlight: boolean, onEvent?: (e: EgressGateEvent) => void): Promise<{ port: number; close: () => Promise<void> }> {
    const server = createExclusiveEgressGate({
      policy, // valid policy (port GATE_PORT) for validation; we bind on 0 to avoid conflicts
      rules: [],
      livenessProbe: probe,
      singleFlightLiveness: singleFlight,
      ...(onEvent ? { onEvent } : {}),
    });
    return new Promise((resolve) => {
      server.listen(0, GATE_BIND_HOST, () => {
        const port = (server.address() as AddressInfo).port;
        resolve({ port, close: () => new Promise<void>((res) => server.close(() => res())) });
      });
    });
  }

  function controllableProbe() {
    let calls = 0;
    const resolvers: Array<(r: PfLivenessResult) => void> = [];
    const probe: GateLivenessProbe = {
      check: () =>
        new Promise<PfLivenessResult>((res) => {
          calls += 1;
          resolvers.push(res);
        }),
    };
    return {
      probe,
      get calls() {
        return calls;
      },
      resolveAll(r: PfLivenessResult) {
        for (const f of resolvers.splice(0)) f(r);
      },
    };
  }

  function fireConnect(port: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(`CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n`);
      });
      let data = "";
      socket.on("data", (c) => (data += c.toString("utf8")));
      socket.on("end", () => resolve(data.split("\r\n")[0] ?? ""));
      socket.on("error", reject);
    });
  }

  it("runs ONE probe for concurrent CONNECTs when single-flight (default) but N probes when false", async () => {
    // --- single-flight (default): concurrent connects share one in-flight probe.
    const sf = controllableProbe();
    const g1 = await startEphemeral(sf.probe, true);
    running.push({ close: () => g1.close() });
    const p1 = [fireConnect(g1.port), fireConnect(g1.port), fireConnect(g1.port)];
    await sleep(60);
    expect(sf.calls).toBe(1); // shared in-flight probe
    sf.resolveAll({ live: false, reasons: ["denied"] });
    for (const p of p1) expect(await p).toContain("503");

    // --- singleFlightLiveness:false: every concurrent CONNECT re-probes.
    const pc = controllableProbe();
    const g2 = await startEphemeral(pc.probe, false);
    running.push({ close: () => g2.close() });
    const p2 = [fireConnect(g2.port), fireConnect(g2.port), fireConnect(g2.port)];
    await sleep(60);
    expect(pc.calls).toBe(3); // per-CONNECT read, no shared green
    pc.resolveAll({ live: false, reasons: ["denied"] });
    for (const p of p2) expect(await p).toContain("503");
  });

  it("per-CONNECT path stays FAIL-CLOSED when the probe throws (503, never a default-live)", async () => {
    const throwingProbe: GateLivenessProbe = { check: () => Promise.reject(new Error("pf blew up")) };
    const events: EgressGateEvent[] = [];
    const g = await startEphemeral(throwingProbe, false, (e) => events.push(e));
    running.push({ close: () => g.close() });
    const status = await fireConnect(g.port);
    expect(status).toContain("503");
    expect(events.some((e) => e.kind === "liveness_refused")).toBe(true);
  });
});

// Keep the bind host referenced so an unused-import lint never masks a real edit.
void GATE_BIND_HOST;
