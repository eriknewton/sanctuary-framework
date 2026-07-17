/**
 * INDEPENDENT round-4 refute suite (Family-A final confirmation pass). Attacks
 * the round-4 fix: createGateClientAuthenticator freezes the authenticator so its
 * ADVERTISED `agentUid` (which gate-server.ts cross-checks against
 * policy.agent_uid at construction, F1) cannot be reassigned/mutated after
 * construction to a value that passes the guard while the runtime `authorize`
 * still enforces the original closed-over uid -- the same advertised-vs-enforced
 * divergence class the liveness probe (round-3) was frozen against.
 *
 * Every test is an ATTACK; the assertion is that the bypass FAILS. Written by the
 * refute reviewer, distinct from the builder's own suite. Adds nothing to source.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";

import {
  createExclusiveEgressGate,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import {
  createGateClientAuthenticator,
  type GateClientAuthenticator,
} from "../../src/egress-gate/gate-client-auth.js";
import {
  GATE_CREDENTIAL_VERSION,
  formatGateCredentialHeader,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";
import type { ExclusiveEgressGatePolicy } from "../../src/castle-wall/allowlist/gate-derivation.js";

const AGENT_UID = 502;
const OTHER_UID = 501;
const GATE_PORT = 47411;
const sha256Hex = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

const SECRET = "deadbeefcafe";
const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: 7,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
const liveProbe: GateLivenessProbe = { check: () => Promise.resolve({ live: true, reasons: [] }) };

const policyFor = (uid: number): ExclusiveEgressGatePolicy => ({ agent_uid: uid, gate_port: GATE_PORT });
const validHeader = formatGateCredentialHeader({ generation_id: 7, secret: SECRET });

// ---------------------------------------------------------------------------
// The authenticator is frozen: advertised agentUid == enforced agentUid, always.
// ---------------------------------------------------------------------------
describe("round-4 refute: authenticator agentUid cannot be diverged after construction", () => {
  it("the authenticator object AND its agentUid property are frozen (structural)", () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(Object.isFrozen(auth)).toBe(true);
    const desc = Object.getOwnPropertyDescriptor(auth, "agentUid");
    expect(desc?.writable).toBe(false);
    expect(desc?.configurable).toBe(false);
  });

  it("REASSIGNING auth.agentUid to a foreign uid does NOT take (frozen)", () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    try {
      (auth as unknown as { agentUid: number }).agentUid = OTHER_UID;
    } catch {
      // strict-mode ESM throws on writing a frozen prop; both outcomes are fine.
    }
    expect(auth.agentUid).toBe(AGENT_UID);
  });

  it("Object.defineProperty CANNOT redefine agentUid (non-configurable)", () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(() =>
      Object.defineProperty(auth, "agentUid", { value: OTHER_UID }),
    ).toThrow(TypeError);
    expect(auth.agentUid).toBe(AGENT_UID);
  });

  it("CANNOT inject a getter that reports one uid at construction and another later (frozen)", () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(() =>
      Object.defineProperty(auth, "agentUid", {
        get: () => OTHER_UID,
        configurable: true,
      }),
    ).toThrow(TypeError);
    expect(auth.agentUid).toBe(AGENT_UID);
  });

  // -------------------------------------------------------------------------
  // The exploit the freeze prevents, driven end-to-end: build an auth that
  // ENFORCES uid A, try to make it ADVERTISE uid B so the F1 guard passes
  // against a uid-B policy, then show the guard still catches the mismatch.
  // -------------------------------------------------------------------------
  it("cannot pass the F1 guard against a uid-B policy with an authenticator that enforces uid A", () => {
    // Authenticator built to ENFORCE OTHER_UID (its authorize closes over OTHER_UID).
    const authForOther = createGateClientAuthenticator({ agentUid: OTHER_UID, acceptSource });
    // Attack: try to make it ADVERTISE AGENT_UID so it pairs with a AGENT_UID policy.
    try {
      (authForOther as unknown as { agentUid: number }).agentUid = AGENT_UID;
    } catch {
      /* frozen */
    }
    // The advertised uid never changed, so the guard still refuses the cross-principal wiring.
    expect(authForOther.agentUid).toBe(OTHER_UID);
    expect(() =>
      createExclusiveEgressGate({
        policy: policyFor(AGENT_UID),
        rules: [],
        livenessProbe: liveProbe,
        clientAuth: authForOther,
      }),
    ).toThrow(/must equal policy\.agent_uid/);
  });

  it("advertised uid == enforced uid at RUNTIME: authorize enforces the same value the guard checked", async () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    // Attempt to divert the advertised uid to OTHER_UID after construction.
    try {
      (auth as unknown as { agentUid: number }).agentUid = OTHER_UID;
    } catch {
      /* frozen */
    }
    // Advertised uid is what the guard cross-checks -- still AGENT_UID.
    expect(auth.agentUid).toBe(AGENT_UID);
    // Runtime enforcement: a peer whose uid == the advertised (AGENT_UID) with a
    // valid current credential ALLOWS; a peer at OTHER_UID DENIES. Proves the
    // enforced uid is the same AGENT_UID the guard read (no divergence).
    const allow = await auth.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 10 },
    });
    expect(allow.allow).toBe(true);
    const deny = await auth.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: OTHER_UID, pid: 11 },
    });
    expect(deny.allow).toBe(false);
    if (!deny.allow) expect(deny.reason).toBe("peer_uid_mismatch");
  });

  it("the matching-uid authenticator still builds a gate (control, freeze does not break the happy path)", () => {
    const auth = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource });
    expect(() =>
      createExclusiveEgressGate({
        policy: policyFor(AGENT_UID),
        rules: [],
        livenessProbe: liveProbe,
        clientAuth: auth,
        peerRunner: { run: () => Promise.resolve({ code: 1, stdout: "" }) },
      }),
    ).not.toThrow();
  });

  it("refuses to construct an authenticator bound to a non-positive/root uid (defense in depth)", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => createGateClientAuthenticator({ agentUid: bad, acceptSource })).toThrow(
        /non-positive\/root agent uid/,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Hunt: any OTHER construction-checked field that is a separate mutable copy
// from the runtime-enforced value in the same authenticator surface.
// ---------------------------------------------------------------------------
describe("round-4 refute: no residual advertised-vs-enforced divergence on the authenticator", () => {
  it("the accept-source is read per-CONNECT (a stale reference cannot pin an old accept-state)", async () => {
    // Mutable accept-state: prove authorize re-reads current() each call rather
    // than snapshotting a stale record at construction.
    let record: GateCredentialAcceptRecord | null = acceptRecord;
    const mutableSource: GateAcceptSource = { current: () => Promise.resolve(record) };
    const auth: GateClientAuthenticator = createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource: mutableSource });
    // First: valid credential + matching peer -> allow.
    const first = await auth.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 10 },
    });
    expect(first.allow).toBe(true);
    // Now revoke (unprotect) by returning null accept-state; the SAME authenticator
    // must now DENY (fail-closed, no snapshot from construction).
    record = null;
    const second = await auth.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: AGENT_UID, pid: 10 },
    });
    expect(second.allow).toBe(false);
    if (!second.allow) expect(second.reason).toBe("no_accept_state");
  });
});
