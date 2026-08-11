/**
 * Sanctuary MCP Server — Federation MCP Tools
 *
 * MCP tool definitions for MCP-to-MCP federation.
 * Three tools cover the core federation operations:
 *   1. federation_peers — List and manage known federation peers
 *   2. federation_trust_evaluate — Evaluate trust for a peer
 *   3. federation_exchange_reputation — Exchange reputation data with a peer
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import { AGENT_UNKNOWN_ORIGIN } from "../handshake/tools.js";
import type { IdentityManager } from "../cognitive/tools.js";
import { publicKeyToDid, isLocallyHeldPublicKey } from "../core/identity.js";
import { fromBase64url } from "../core/encoding.js";
import { FederationRegistry } from "./registry.js";

export function createFederationTools(
  auditLog: AuditLog,
  handshakeResults: ReadonlyMap<string, HandshakeResult>,
  // REQUIRED (AGENTS.md rule 3: an optional security dependency that gates a
  // trust property must be required, never silently-disabling). Register-time
  // refuses a peer this fortress holds keys for, independent of the shared
  // producer chokepoint (recordHandshakeResult in handshake/tools.ts) that
  // already keeps `handshakeResults` free of such entries — this is
  // defense-in-depth, not the only layer, but it must never be inert.
  // Production wiring (index.ts) always supplies it; every test construction
  // must too (a test that omits it is testing a bypass, not a real config).
  identityManager: IdentityManager,
  // REQUIRED (AGENTS.md rule 3, MUST-FIX 2 RECHECK: an optional dependency
  // that gates a per-origin quota — a security property under rule 8 — must
  // be required, never silently-disabling). Fix-round-1 made this optional
  // on the theory that it "only" fed a DoS quota, not a trust decision; the
  // gate found that reasoning wrong for THIS quota specifically, because
  // the quota origin is the un-mintable agent-session principal (MUST-FIX
  // 1's spine) — omitting the map does not just lose fairness accounting,
  // it silently reopens the exact cross-session lockout MUST-FIX 1 closes
  // (an attacker whose registrations carry no origin attribution floods the
  // shared registry unbounded by any per-session quota).
  //
  // THE WRITER map, not the allocation map (MUST-FIX 2, fix-round-3):
  // production wiring (index.ts) supplies `createHandshakeTools`'s
  // `handshakeResultWriterOrigins` here — NOT its `handshakeResultOrigins`
  // (that one is `handshakeResults`'s own BoundedMap-internal, immutable,
  // first-writer accounting; see both fields' docs in handshake/tools.ts).
  // Charging registration to the FIRST previewer of a counterparty rather
  // than the session whose REAL verified handshake produced the result
  // being registered lets an attacker who has exhausted their own quota
  // with cheap unverified pre-previews deny an unrelated victim's later,
  // legitimate registration for the SAME counterparty (their pre-preview
  // permanently "claims" that counterparty_id's allocation origin; the
  // victim's real handshake is an UPDATE, which never reattributes it).
  // Every test construction must supply a real (or intentionally empty,
  // for tests that don't exercise per-origin fairness) map here too — a
  // test that omits it is testing a bypass, not a real config.
  handshakeResultWriterOrigins: ReadonlyMap<string, string>
): { tools: ToolDefinition[]; registry: FederationRegistry } {
  const registry = new FederationRegistry(auditLog);

  const tools: ToolDefinition[] = [
    // ─── Peer Management ──────────────────────────────────────────────

    {
      name: "federation_peers",
      description:
        "List known federation peers, register a peer from a completed handshake, " +
        "or remove a peer. Every peer MUST enter through a verified handshake " +
        "with a counterparty this fortress does not hold keys for.",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            enum: ["list", "register", "remove"],
            description: "Operation to perform on the peer registry",
          },
          peer_id: {
            type: "string",
            description: "Peer instance ID (required for register/remove)",
          },
          peer_did: {
            type: "string",
            description:
              "Peer DID. Optional: defaults to the did:key derived from the " +
              "public key that signed the handshake SHR. If supplied, it MUST " +
              "match that derived DID — a mismatched label is rejected.",
          },
          active_only: {
            type: "boolean",
            description: "When listing, only show peers with active handshakes",
          },
        },
        required: ["action"],
      },
      handler: async (args) => {
        const action = args.action as string;

        switch (action) {
          case "list": {
            const peers = registry.listPeers({
              active_only: args.active_only as boolean | undefined,
            });

            void auditLog.append("l4", "federation_peers_list", "system", {
              peer_count: peers.length,
            });

            return toolResult({
              peers: peers.map((p) => ({
                peer_id: p.peer_id,
                peer_did: p.peer_did,
                trust_tier: p.trust_tier,
                active: p.active,
                first_seen: p.first_seen,
                last_handshake: p.last_handshake,
                capabilities: p.capabilities,
              })),
              total: peers.length,
            });
          }

          case "register": {
            const peerId = args.peer_id as string;
            const suppliedDid = args.peer_did as string | undefined;

            if (!peerId) {
              return toolResult({
                error: "peer_id is required for registration.",
              });
            }

            // Peer MUST have a completed handshake
            const hsResult = handshakeResults.get(peerId);
            if (!hsResult) {
              return toolResult({
                error: `No completed handshake found for peer "${peerId}". ` +
                  "Complete a sovereignty handshake first using handshake_initiate.",
              });
            }

            if (!hsResult.verified) {
              return toolResult({
                error: `Handshake with "${peerId}" was not verified. ` +
                  "Only verified handshakes can establish federation.",
              });
            }

            // HS-3 fix part 1: a federation peer may ONLY be bound from a
            // handshake that proved counterparty liveness via the nonce-bearing
            // 4-step protocol. A `handshake_exchange` preview result
            // (liveness_proven:false) can never be promoted to a trusted peer,
            // even if somehow marked verified.
            if (!hsResult.liveness_proven) {
              return toolResult({
                error:
                  `Handshake with "${peerId}" did not prove liveness. ` +
                  "Only a live 4-step handshake (handshake_initiate / respond / " +
                  "complete) can establish a federation peer; a one-shot " +
                  "handshake_exchange preview is not sufficient.",
              });
            }

            // HS-3 fix part 2: bind peer_did to the key that actually signed
            // the handshake SHR. Derive the DID from signed_by; if the caller
            // supplied a DID, it MUST equal the derived one — preventing an
            // arbitrary/impersonating label from being attached to a verified
            // peer.
            let derivedDid: string;
            let signerPublicKey: Uint8Array;
            try {
              signerPublicKey = fromBase64url(hsResult.counterparty_shr.signed_by);
              derivedDid = publicKeyToDid(signerPublicKey);
            } catch (e) {
              return toolResult({
                error:
                  `Could not derive peer DID from the handshake SHR: ${(e as Error).message}`,
              });
            }

            if (suppliedDid && suppliedDid !== derivedDid) {
              return toolResult({
                error:
                  "peer_did does not match the key that signed the handshake. " +
                  "Omit peer_did to use the derived DID, or supply the correct one.",
              });
            }

            const peerDid = derivedDid;

            // Class-level self-vouch guard, defense-in-depth (register §Z
            // RECHECK / LD2-02): the shared producer chokepoint
            // (recordHandshakeResult in handshake/tools.ts) already refuses
            // to record a handshake result for a counterparty this fortress
            // holds keys for, so hsResult should never exist for a
            // self-vouched pair. This is a SECOND, independent check at the
            // registration boundary, reading identityManager.list() directly
            // rather than trusting that every past or future write into
            // `handshakeResults` routed through that chokepoint. Federation
            // must never trust a peer this fortress holds the private key
            // for, regardless of how its handshake entry arrived. Compares
            // DECODED KEY BYTES (isLocallyHeldPublicKey, core/identity.ts),
            // never the DID string — a persisted identity's `.did` can be in
            // the legacy base64url encoding while `derivedDid` above is
            // always canonical, so a DID-string comparison here would miss a
            // legacy-encoded local identity (the #1194-class defect).
            // `signerPublicKey` is already decoded above; reuse it rather
            // than re-deriving from `peerDid`.
            if (isLocallyHeldPublicKey(signerPublicKey, identityManager.list())) {
              void auditLog.append(
                "l4",
                "federation_peer_register_self_vouch_blocked",
                "system",
                { peer_id: peerId, peer_did: peerDid },
                "failure"
              );
              return toolResult({
                error:
                  "Cannot register a federation peer this fortress holds keys for.",
              });
            }

            // Per-origin quota (register LD2-04, MUST-FIX 1/2 RECHECK, split
            // fix-round-3): attribute this registration to the AGENT-SESSION
            // PRINCIPAL that recorded the VERIFIED handshake result CURRENTLY
            // stored for this peer (`handshakeResultWriterOrigins`, see that
            // map's doc in handshake/tools.ts — deliberately NOT
            // `handshakeResults`'s own first-writer allocation origin; using
            // that one here was itself the MUST-FIX 2 fix-round-3 defect: an
            // attacker's cheap unverified pre-preview of a victim's
            // counterparty permanently claims the allocation origin, and the
            // victim's later real handshake (an update) never displaces it),
            // so a flood of attacker-completed handshakes — even spread
            // across many MINTED local identities — cannot exhaust the
            // shared registry and lock out a DIFFERENT session's
            // registration. `handshakeResultWriterOrigins` is REQUIRED
            // (MUST-FIX 2) precisely so this line can never silently fall
            // back to "no origin, skip the quota"; a peerId genuinely absent
            // from the map (should not happen — every `recordHandshakeResult`
            // write supplies an origin) still falls into the shared
            // `AGENT_UNKNOWN_ORIGIN` bucket rather than escaping accounting.
            const origin = handshakeResultWriterOrigins.get(peerId) ?? AGENT_UNKNOWN_ORIGIN;
            const registration = await registry.registerFromHandshake(
              hsResult,
              peerDid,
              undefined,
              origin
            );

            // Bounded-collection guard (register LD2-04): the registry
            // refuses a new peer for one of FOUR typed reasons (MUST-FIX 2,
            // fix-round-4 — widened from a bare null/non-null result so the
            // AGENT-facing tool response is as accurate as the operator audit
            // trail already was via `onRefuse`, registry.ts): THIS identity's
            // own per-origin quota is exhausted (`origin_quota`), the shared
            // registry is at capacity and every existing slot holds a
            // currently-active peer (`capacity`), a capacity eviction was
            // decided but its durable audit write did not complete
            // (`audit_unavailable` — distinct from `capacity` because a
            // retry once the audit trail recovers should not be told "full"),
            // or the registry's own admission-lock waiter queue was already
            // at its cap (`admission_busy`, fix-round-6 — see
            // core/bounded-map.ts's `BoundedMapRefuseReason` doc). Either way
            // the registry never evicts a real trusted peer to make room.
            // Surface this as an explicit error, never a silently-dropped
            // "registered: true".
            if (!registration.ok) {
              // MUST-FIX 3, fix-round-5 (Codex): both messages below were
              // inaccurate about the underlying condition. (1) `origin_quota`
              // counts entries currently attributed to this origin, checked
              // BEFORE the capacity/eviction path ever runs (see
              // bounded-map.ts's `admitNewKey`) — an expired peer entry is
              // NOT deleted by expiry alone (only `getPeer`/`listPeers`
              // lazily flip `active`/`trust_tier` in place; `removePeer` or
              // a global-capacity eviction of THAT entry are the only things
              // that ever delete it), so "let an inactive peer expire"
              // never actually frees this quota — only an explicit
              // `action: "remove"` does. (2) `audit_unavailable` can only be
              // reached from INSIDE the capacity branch (`this.map.size >=
              // this.opts.maxSize`, bounded-map.ts) — the registry WAS at
              // capacity and an eviction WAS decided; it is a distinct
              // reason for the SAME "at capacity" condition, not a separate
              // "not full" one, so the two are never mutually exclusive.
              // (3) `admission_busy` (fix-round-6) is checked BEFORE
              // `origin_quota`/`capacity` ever run at all (bounded-map.ts's
              // `set()`) — it must not collapse into the `capacity` message
              // below, which would wrongly tell the agent "every peer is
              // active" for what is really "retry shortly."
              const error =
                registration.reason === "origin_quota"
                  ? "This identity has reached its federation peer " +
                    `registration quota (${registry.maxPeersPerOrigin()} peers). ` +
                    "A peer's registration continues to count against this " +
                    "quota even after its handshake expires; explicitly " +
                    "remove an existing peer (federation_peers action: " +
                    "\"remove\") to free a slot before registering another."
                  : registration.reason === "audit_unavailable"
                    // "failed or did not complete in time" (fix-round-7):
                    // bounded-map.ts's catch around the awaited onEvict
                    // covers BOTH an immediate rejection and a timeout —
                    // "did not complete in time" alone described only the
                    // second. Must match the handshake wording
                    // (SESSIONS_AUDIT_UNAVAILABLE_ERROR, handshake/tools.ts).
                    ? "Federation peer registry is at capacity and needed " +
                      "to evict an inactive peer to register this one, but " +
                      "the durable audit write for that eviction failed or " +
                      "did not complete in time; this is an audit-log " +
                      "availability issue, not a genuine \"every peer is " +
                      "active\" saturation. Retry once the audit log " +
                      "recovers."
                    : registration.reason === "admission_busy"
                      ? "Federation peer registry's admission queue is " +
                        "momentarily saturated with other concurrent peer " +
                        "registrations; retry shortly."
                      : "Federation peer registry is at capacity and every " +
                        "slot holds an active peer; cannot register a new " +
                        "peer until one expires, is removed, or one becomes " +
                        "inactive.";
              return toolResult({ error });
            }
            const peer = registration.peer;

            void auditLog.append("l4", "federation_peer_register", "system", {
              peer_id: peerId,
              peer_did: peerDid,
              trust_tier: peer.trust_tier,
            });

            return toolResult({
              registered: true,
              peer_id: peer.peer_id,
              peer_did: peer.peer_did,
              trust_tier: peer.trust_tier,
              active: peer.active,
              capabilities: peer.capabilities,
            });
          }

          case "remove": {
            const peerId = args.peer_id as string;
            if (!peerId) {
              return toolResult({ error: "peer_id is required for removal." });
            }

            const removed = registry.removePeer(peerId);

            void auditLog.append("l4", "federation_peer_remove", "system", {
              peer_id: peerId,
              removed,
            });

            return toolResult({
              removed,
              peer_id: peerId,
            });
          }

          default:
            return toolResult({ error: `Unknown action: ${action}` });
        }
      },
    },

    // ─── Trust Evaluation ─────────────────────────────────────────────

    {
      name: "federation_trust_evaluate",
      description:
        "Evaluate the trust level of a federation peer. " +
        "Considers handshake status, sovereignty tier, reputation score, " +
        "and mutual attestation history. Returns a composite trust assessment.",
      inputSchema: {
        type: "object",
        properties: {
          peer_id: {
            type: "string",
            description: "Peer instance ID to evaluate",
          },
          mutual_attestation_count: {
            type: "number",
            description: "Number of mutual attestations with this peer (0 if unknown)",
          },
          reputation_score: {
            type: "number",
            description: "Peer's weighted reputation score (from reputation_query_weighted)",
          },
        },
        required: ["peer_id"],
      },
      handler: async (args) => {
        const peerId = args.peer_id as string;
        const mutualCount = (args.mutual_attestation_count as number) ?? 0;
        const repScore = args.reputation_score as number | undefined;

        const evaluation = registry.evaluateTrust(peerId, mutualCount, repScore);

        void auditLog.append("l4", "federation_trust_evaluate", "system", {
          peer_id: peerId,
          trust_level: evaluation.trust_level,
          sovereignty_tier: evaluation.sovereignty_tier,
        });

        return toolResult(evaluation);
      },
    },

    // ─── Federation Status ────────────────────────────────────────────

    {
      name: "federation_status",
      description:
        "Overview of federation state: total peers, active connections, " +
        "trust distribution, and readiness for cross-instance operations.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const allPeers = registry.listPeers();
        const activePeers = registry.listPeers({ active_only: true });

        // Trust tier distribution
        const tierCounts: Record<string, number> = {
          "verified-sovereign": 0,
          "verified-degraded": 0,
          "self-attested": 0,
          "unverified": 0,
        };
        for (const peer of allPeers) {
          tierCounts[peer.trust_tier] = (tierCounts[peer.trust_tier] ?? 0) + 1;
        }

        // Capability summary
        const capCounts = {
          reputation_exchange: activePeers.filter((p) => p.capabilities.reputation_exchange).length,
          mutual_attestation: activePeers.filter((p) => p.capabilities.mutual_attestation).length,
          encrypted_channel: activePeers.filter((p) => p.capabilities.encrypted_channel).length,
        };

        void auditLog.append("l4", "federation_status", "system", {
          total_peers: allPeers.length,
          active_peers: activePeers.length,
        });

        return toolResult({
          total_peers: allPeers.length,
          active_peers: activePeers.length,
          expired_peers: allPeers.length - activePeers.length,
          trust_distribution: tierCounts,
          capability_coverage: capCounts,
          federation_ready: activePeers.length > 0,
          checked_at: new Date().toISOString(),
        });
      },
    },
  ];

  return { tools, registry };
}
