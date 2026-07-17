/**
 * Fail-closed client authorization for the exclusive-egress gate (Unified
 * Protect Slice 5 S5-3; design 4b, review HIGH-5).
 *
 * THE REFRAME. The gate is the SOLE sanctioned egress route, so an unidentified
 * client must get NOTHING. Slice 2's peer identity was advisory-only (a mismatch
 * was logged but the request still proceeded). S5-3 makes client authorization
 * FAIL-CLOSED: an unauthenticated, wrong-uid, unresolved, or stale-generation
 * client is DENIED and audited (`client_denied`), never proxied.
 *
 * TWO INDEPENDENT LENSES, BOTH REQUIRED (bearer never overrides peer):
 *   1. the generation-bound bearer credential (`gate-credential.ts`) is the
 *      PRIMARY factor (reliable per-CONNECT, forge-resistant, current-only);
 *   2. the loopback peer uid (`peer-identity.ts`) is a SECOND factor that must
 *      also RESOLVE and MATCH the agent uid.
 * A valid credential with the WRONG peer uid still DENIES; a valid credential
 * with an UNRESOLVED peer still DENIES. That is the design's "bearer alone never
 * overrides peer uid": wrong uid, unresolved peer, missing credential, AND
 * stale-generation credential ALL deny.
 *
 * WHY UNRESOLVED ==> DENY (the honest availability bound). Peer resolution can
 * legitimately fail under load (the PEER_LOOKUP_MAX_CONCURRENT skip path in
 * `gate-server.ts`) or lose a TOCTOU race. Under the fail-closed posture that
 * cost is paid toward DENY: a burst that saturates the peer-lookup cap denies
 * the agent's own connects rather than admitting an unverified peer. This is the
 * conservative direction (never-silently-degrade); it is stated plainly in the
 * module and the ledger, so agent-connect denial under peer-lookup saturation is
 * never read as a defect. The bearer credential is exactly why peer resolution
 * can be the STRICTER of the two without being the only one.
 *
 * PURE + INJECTED. {@link decideGateClientAuth} is a pure function over the two
 * lens results; {@link createGateClientAuthenticator} wires it to an injected
 * accept-source (reads the root-written `.accept` file) so it is host-free in
 * tests and reads the CURRENT generation's accept-state per CONNECT (rotation
 * propagates without restarting the gate). It authorizes; it never grants or
 * dials -- the gate does that only on an `allow`.
 */

import {
  parseGateCredentialHeader,
  verifyGateCredential,
  type GateAcceptSource,
  type GateCredentialDenyReason,
  type GateCredentialVerdict,
} from "./gate-credential.js";

/** How the gate resolved (or failed to resolve) the connecting loopback peer. */
export type GatePeerResolution =
  | { kind: "resolved"; uid: number; pid: number }
  /** lsof returned null / the socket raced / the lookup was not attempted. */
  | { kind: "unresolved" }
  /** the lookup was skipped at the subprocess-amplification cap (still a deny). */
  | { kind: "skipped_cap" };

/** Why a client CONNECT was denied (the `client_denied` audit reason). */
export type GateClientDenyReason =
  | "peer_unresolved"
  | "peer_uid_mismatch"
  | "accept_unreadable"
  | GateCredentialDenyReason;

/** The client-authorization verdict. `allow` implies a resolved+matched peer AND a current credential. */
export type GateClientAuthDecision =
  | { allow: true; peerUid: number }
  | {
      allow: false;
      reason: GateClientDenyReason;
      /** Present only for a resolved-but-mismatched peer (observability). */
      peerUid?: number;
      peerPid?: number;
    };

/**
 * Pure fail-closed decision. Order: the PRIMARY bearer credential is checked
 * first (a missing/stale/bad credential denies before the peer lens even
 * matters), then the peer must RESOLVE and MATCH. A credential-ok request with
 * an unresolved or mismatched peer STILL denies -- bearer never overrides peer.
 */
export function decideGateClientAuth(input: {
  agentUid: number;
  peer: GatePeerResolution;
  credential: GateCredentialVerdict;
}): GateClientAuthDecision {
  if (!input.credential.ok) {
    return { allow: false, reason: input.credential.reason };
  }
  if (input.peer.kind !== "resolved") {
    // Both "unresolved" and "skipped_cap" deny; the distinct audit signal is
    // kept at the event layer, but the outcome is one reason here.
    return { allow: false, reason: "peer_unresolved" };
  }
  if (input.peer.uid !== input.agentUid) {
    return {
      allow: false,
      reason: "peer_uid_mismatch",
      peerUid: input.peer.uid,
      peerPid: input.peer.pid,
    };
  }
  return { allow: true, peerUid: input.peer.uid };
}

/**
 * The gate-side authenticator: the `gate-server.ts` fail-closed client-auth
 * hook. Present it and the gate DENIES any CONNECT that is not
 * credential-valid-AND-peer-matched.
 */
export interface GateClientAuthenticator {
  /** The single agent uid this gate serves (its channel is exclusive to one agent). */
  readonly agentUid: number;
  /**
   * Authorize one CONNECT. `credentialHeader` is the raw `Proxy-Authorization`
   * value (Node folds duplicates into an array, which is rejected). `peer` is
   * the gate's own capped loopback resolution.
   */
  authorize(input: {
    credentialHeader: string | string[] | undefined;
    peer: GatePeerResolution;
  }): Promise<GateClientAuthDecision>;
}

/**
 * Build a {@link GateClientAuthenticator} bound to one agent uid + accept-source.
 * Reads the CURRENT accept-state per CONNECT so a rotation (new generation)
 * propagates without a gate restart. Every failure path is a DENY:
 *   - a present-but-unparseable header -> `malformed_credential`;
 *   - an accept-source read error -> `accept_unreadable` (fail-closed, never
 *     default-allow);
 *   - otherwise the credential + peer decision above.
 */
export function createGateClientAuthenticator(input: {
  agentUid: number;
  acceptSource: GateAcceptSource;
}): GateClientAuthenticator {
  const { agentUid, acceptSource } = input;
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new Error(`gate client auth: refusing to bind to a non-positive/root agent uid ${String(agentUid)}`);
  }
  // BIND the accept-source method once at construction (Codex round-7): runtime
  // must not re-read `acceptSource.current` off the caller's object, or a
  // post-construction swap of `.current` could return a stale/removed accept
  // record and revive an old credential. Binding captures the method as it was.
  const acceptCurrent = acceptSource.current.bind(acceptSource);
  // FROZEN so the ADVERTISED `agentUid` (which the gate cross-checks against
  // policy.agent_uid at construction, gate-server.ts) cannot be reassigned or
  // mutated after construction to a value that passes the guard while the
  // runtime `authorize` still closes over the original `agentUid` (Codex
  // round-4 HIGH -- the same advertised-vs-enforced divergence class the
  // liveness probe was frozen against). The whole authenticator is immutable, so
  // the checked uid and the enforced uid are provably the same value.
  const authenticator: GateClientAuthenticator = {
    agentUid,
    async authorize({ credentialHeader, peer }): Promise<GateClientAuthDecision> {
      // Distinguish a present-but-garbage header (malformed) from an absent one
      // (no_credential) for a precise audit signal; both deny.
      const presented = parseGateCredentialHeader(credentialHeader);
      let credential: GateCredentialVerdict;
      if (presented === null && typeof credentialHeader === "string" && credentialHeader.trim() !== "") {
        credential = { ok: false, reason: "malformed_credential" };
      } else {
        let accept;
        try {
          accept = await acceptCurrent(agentUid);
        } catch {
          // A malformed/partial accept file is fail-closed: deny, never allow.
          return { allow: false, reason: "accept_unreadable" };
        }
        credential = verifyGateCredential(accept, presented);
      }
      return decideGateClientAuth({ agentUid, peer, credential });
    },
  };
  return Object.freeze(authenticator);
}
