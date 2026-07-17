/**
 * Unit tests for the fail-closed client authorization (Slice 5 S5-3): the pure
 * two-lens decision + the injected-accept-source authenticator. Bearer never
 * overrides peer; unresolved/skipped peers deny.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";

import {
  decideGateClientAuth,
  createGateClientAuthenticator,
  type GatePeerResolution,
} from "../../src/egress-gate/gate-client-auth.js";
import {
  formatGateCredentialHeader,
  GATE_CREDENTIAL_VERSION,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";

function sha256Hex(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

const resolvedAgent: GatePeerResolution = { kind: "resolved", uid: 502, pid: 777 };
const resolvedOperator: GatePeerResolution = { kind: "resolved", uid: 501, pid: 888 };
const unresolved: GatePeerResolution = { kind: "unresolved" };
const skippedCap: GatePeerResolution = { kind: "skipped_cap" };

describe("egress-gate/gate-client-auth decision (pure)", () => {
  it("allows only credential-ok AND peer-resolved-and-matched", () => {
    expect(
      decideGateClientAuth({ agentUid: 502, peer: resolvedAgent, credential: { ok: true } }),
    ).toEqual({ allow: true, peerUid: 502 });
  });

  it("denies with the credential reason when the credential fails (even with a matched peer)", () => {
    expect(
      decideGateClientAuth({
        agentUid: 502,
        peer: resolvedAgent,
        credential: { ok: false, reason: "no_credential" },
      }),
    ).toEqual({ allow: false, reason: "no_credential" });
  });

  it("denies peer_unresolved when the credential is ok but the peer is unresolved (bearer never overrides peer)", () => {
    expect(
      decideGateClientAuth({ agentUid: 502, peer: unresolved, credential: { ok: true } }),
    ).toEqual({ allow: false, reason: "peer_unresolved" });
  });

  it("denies peer_unresolved when the peer lookup was skipped at the cap (fail-closed)", () => {
    expect(
      decideGateClientAuth({ agentUid: 502, peer: skippedCap, credential: { ok: true } }),
    ).toEqual({ allow: false, reason: "peer_unresolved" });
  });

  it("denies peer_uid_mismatch (carrying peer identity) when a valid credential comes from the wrong uid", () => {
    expect(
      decideGateClientAuth({ agentUid: 502, peer: resolvedOperator, credential: { ok: true } }),
    ).toEqual({ allow: false, reason: "peer_uid_mismatch", peerUid: 501, peerPid: 888 });
  });
});

describe("egress-gate/gate-client-auth authenticator (injected accept-source)", () => {
  const accept: GateCredentialAcceptRecord = {
    version: GATE_CREDENTIAL_VERSION,
    generation_id: 7,
    secret_sha256: sha256Hex("deadbeef"),
  };
  const acceptSource: GateAcceptSource = { current: () => Promise.resolve(accept) };
  const validHeader = formatGateCredentialHeader({ generation_id: 7, secret: "deadbeef" });

  it("authorizes a valid credential from the matching peer", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const decision = await auth.authorize({ credentialHeader: validHeader, peer: resolvedAgent });
    expect(decision).toEqual({ allow: true, peerUid: 502 });
  });

  it("denies a present-but-garbage header as malformed_credential", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const decision = await auth.authorize({ credentialHeader: "Sanctuary-Gate garbage", peer: resolvedAgent });
    expect(decision).toEqual({ allow: false, reason: "malformed_credential" });
  });

  it("denies an absent header as no_credential", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const decision = await auth.authorize({ credentialHeader: undefined, peer: resolvedAgent });
    expect(decision).toEqual({ allow: false, reason: "no_credential" });
  });

  it("denies a stale-generation credential", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const stale = formatGateCredentialHeader({ generation_id: 6, secret: "deadbeef" });
    const decision = await auth.authorize({ credentialHeader: stale, peer: resolvedAgent });
    expect(decision).toEqual({ allow: false, reason: "stale_generation" });
  });

  it("denies a valid credential from the WRONG peer uid (bearer never overrides peer)", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const decision = await auth.authorize({ credentialHeader: validHeader, peer: resolvedOperator });
    expect(decision).toEqual({ allow: false, reason: "peer_uid_mismatch", peerUid: 501, peerPid: 888 });
  });

  it("denies a valid credential when the peer is unresolved", async () => {
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource });
    const decision = await auth.authorize({ credentialHeader: validHeader, peer: unresolved });
    expect(decision).toEqual({ allow: false, reason: "peer_unresolved" });
  });

  it("denies with accept_unreadable when the accept-source throws (fail-closed, never default-allow)", async () => {
    const throwingSource: GateAcceptSource = {
      current: () => Promise.reject(new Error("malformed accept file")),
    };
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource: throwingSource });
    const decision = await auth.authorize({ credentialHeader: validHeader, peer: resolvedAgent });
    expect(decision).toEqual({ allow: false, reason: "accept_unreadable" });
  });

  it("denies with no_accept_state when the gate has no accept file yet (unprotected)", async () => {
    const emptySource: GateAcceptSource = { current: () => Promise.resolve(null) };
    const auth = createGateClientAuthenticator({ agentUid: 502, acceptSource: emptySource });
    const decision = await auth.authorize({ credentialHeader: validHeader, peer: resolvedAgent });
    expect(decision).toEqual({ allow: false, reason: "no_accept_state" });
  });

  it("refuses to bind to a root/zero agent uid", () => {
    expect(() => createGateClientAuthenticator({ agentUid: 0, acceptSource })).toThrow(
      /non-positive\/root/,
    );
  });

  it("is FROZEN so the advertised agentUid cannot diverge from the enforced one (Codex round-4)", async () => {
    // Bypass attempt: build an authenticator for uid 501, then mutate the
    // advertised .agentUid to 502 so a gate for policy 502 would construct while
    // authorize() still uses 501. Freezing makes the mutation a no-op, so the
    // advertised uid stays 501 (the gate's F1 guard would then reject a 502 policy).
    const auth = createGateClientAuthenticator({ agentUid: 501, acceptSource });
    expect(Object.isFrozen(auth)).toBe(true);
    try {
      (auth as { agentUid: number }).agentUid = 502;
    } catch {
      // strict-mode ESM throws on frozen reassignment; either outcome is fine.
    }
    expect(auth.agentUid).toBe(501);
    // authorize still enforces uid 501: a peer resolved as 502 is a mismatch.
    const decision = await auth.authorize({
      credentialHeader: validHeader,
      peer: { kind: "resolved", uid: 502, pid: 1 },
    });
    expect(decision.allow).toBe(false);
    if (!decision.allow) {
      expect(decision.reason).toBe("peer_uid_mismatch");
    }
  });
});
