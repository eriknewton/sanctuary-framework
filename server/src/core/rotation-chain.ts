/**
 * Shared verifier for identity public-key rotation chains.
 *
 * A verified chain proves that each retired public key authorized the next key
 * for the same stable identity id. Callers may use retired keys only for the
 * narrow trust decision they are verifying, never as persisted accepted
 * signers.
 */

import { bytesToString, fromBase64url, stringToBytes } from "./encoding.js";
import {
  assertEd25519PublicKey,
  verify,
  type RotationEvent,
  type StoredIdentity,
} from "./identity.js";

// 64 = one monthly rotation for more than five years, enough operational headroom
// while bounding attacker-controlled chain verification work.
export const MAX_ROTATION_CHAIN_HOPS = 64;

export type RotationChainInvalidReason =
  | "rotation_history_not_array"
  | "rotation_history_over_cap"
  | "rotation_hop_malformed"
  | "rotation_chain_broken_contiguity"
  | "rotation_chain_non_terminating"
  | "rotation_chain_repeated_key"
  | "rotation_key_length_invalid"
  | "rotation_event_malformed"
  | "rotation_event_mismatch"
  | "rotation_signature_invalid";

export interface VerifiedRotationChain {
  identity_id: string;
  current_public_key: Uint8Array;
  /** Retired keys, newest first. Empty for a never-rotated identity. */
  retired: Array<{
    public_key: Uint8Array;
    public_key_base64url: string;
    retired_at: string;
    reason: string;
    /** true when this key was retired by a rotation whose reason declares compromise. */
    compromised: boolean;
  }>;
  hop_count: number;
}

export type RotationChainResult =
  | { status: "verified"; chain: VerifiedRotationChain }
  | {
      status: "invalid";
      reason: RotationChainInvalidReason;
      detail: string;
    };

type RotationHistoryEntry = StoredIdentity["rotation_history"][number];

function invalid(
  reason: RotationChainInvalidReason,
  detail: string
): RotationChainResult {
  return { status: "invalid", reason, detail };
}

function decodePublicKey(
  encoded: string,
  detail: string
): { ok: true; bytes: Uint8Array } | { ok: false; result: RotationChainResult } {
  try {
    const bytes = fromBase64url(encoded);
    assertEd25519PublicKey(bytes);
    return { ok: true, bytes };
  } catch {
    return {
      ok: false,
      result: invalid("rotation_key_length_invalid", detail),
    };
  }
}

function parseRotationEvent(
  encoded: string,
  hopIndex: number
): { ok: true; event: RotationEvent } | { ok: false; result: RotationChainResult } {
  try {
    const parsed = JSON.parse(bytesToString(fromBase64url(encoded))) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        ok: false,
        result: invalid(
          "rotation_event_malformed",
          `hop ${hopIndex}: rotation_event is not an object`
        ),
      };
    }
    const record = parsed as Record<string, unknown>;
    if (
      typeof record.old_public_key !== "string" ||
      typeof record.new_public_key !== "string" ||
      typeof record.identity_id !== "string" ||
      typeof record.reason !== "string" ||
      typeof record.rotated_at !== "string" ||
      typeof record.signature !== "string"
    ) {
      return {
        ok: false,
        result: invalid(
          "rotation_event_malformed",
          `hop ${hopIndex}: rotation_event is missing signed string fields`
        ),
      };
    }
    return {
      ok: true,
      event: {
        old_public_key: record.old_public_key,
        new_public_key: record.new_public_key,
        identity_id: record.identity_id,
        reason: record.reason,
        rotated_at: record.rotated_at,
        signature: record.signature,
      },
    };
  } catch {
    return {
      ok: false,
      result: invalid(
        "rotation_event_malformed",
        `hop ${hopIndex}: rotation_event is not valid base64url JSON`
      ),
    };
  }
}

export function rotationEventSigningBytes(event: RotationEvent): Uint8Array {
  // CONTRACT PIN (server/src/core/identity.ts `rotateKeys`): field order must
  // match the `eventData` object literal in `core/identity.ts` `rotateKeys`;
  // `JSON.stringify` is order-sensitive and this is a signature preimage.
  return stringToBytes(
    JSON.stringify({
      old_public_key: event.old_public_key,
      new_public_key: event.new_public_key,
      identity_id: event.identity_id,
      reason: event.reason,
      rotated_at: event.rotated_at,
    })
  );
}

export function verifyRotationChain(args: {
  identityId: string;
  currentPublicKey: string | Uint8Array;
  rotationHistory: unknown;
}): RotationChainResult {
  try {
    if (!Array.isArray(args.rotationHistory)) {
      return invalid(
        "rotation_history_not_array",
        `identity ${args.identityId}: rotation_history is not an array`
      );
    }
    if (args.rotationHistory.length > MAX_ROTATION_CHAIN_HOPS) {
      return invalid(
        "rotation_history_over_cap",
        `identity ${args.identityId}: rotation_history has ${args.rotationHistory.length} hops, cap is ${MAX_ROTATION_CHAIN_HOPS}`
      );
    }

    const currentPublicKey =
      typeof args.currentPublicKey === "string"
        ? decodePublicKey(
            args.currentPublicKey,
            `identity ${args.identityId}: current public key is not a 32-byte Ed25519 key`
          )
        : (() => {
            try {
              assertEd25519PublicKey(args.currentPublicKey);
              return { ok: true as const, bytes: args.currentPublicKey };
            } catch {
              return {
                ok: false as const,
                result: invalid(
                  "rotation_key_length_invalid",
                  `identity ${args.identityId}: current public key is not a 32-byte Ed25519 key`
                ),
              };
            }
          })();
    if (!currentPublicKey.ok) return currentPublicKey.result;

    const currentPublicKeyBase64url =
      typeof args.currentPublicKey === "string"
        ? args.currentPublicKey
        : undefined;
    if (args.rotationHistory.length === 0) {
      return {
        status: "verified",
        chain: {
          identity_id: args.identityId,
          current_public_key: currentPublicKey.bytes,
          retired: [],
          hop_count: 0,
        },
      };
    }

    const seenPublicKeys = new Set<string>();
    if (currentPublicKeyBase64url !== undefined) {
      seenPublicKeys.add(currentPublicKeyBase64url);
    }
    const retiredOldestFirst: VerifiedRotationChain["retired"] = [];
    let expectedOldPublicKey: string | null = null;
    let lastNewPublicKey: string | null = null;

    for (let i = 0; i < args.rotationHistory.length; i++) {
      const item = args.rotationHistory[i] as Partial<RotationHistoryEntry>;
      if (
        !item ||
        typeof item !== "object" ||
        typeof item.old_public_key !== "string" ||
        typeof item.new_public_key !== "string" ||
        typeof item.rotation_event !== "string" ||
        typeof item.rotated_at !== "string"
      ) {
        return invalid(
          "rotation_hop_malformed",
          `identity ${args.identityId} hop ${i}: rotation history entry is malformed`
        );
      }

      if (
        expectedOldPublicKey !== null &&
        item.old_public_key !== expectedOldPublicKey
      ) {
        return invalid(
          "rotation_chain_broken_contiguity",
          `identity ${args.identityId} hop ${i}: old_public_key does not match previous new_public_key`
        );
      }

      for (const [field, key] of [
        ["old_public_key", item.old_public_key],
        ["new_public_key", item.new_public_key],
      ] as const) {
        const decoded = decodePublicKey(
          key,
          `identity ${args.identityId} hop ${i}: ${field} is not a 32-byte Ed25519 key`
        );
        if (!decoded.ok) return decoded.result;
      }

      if (seenPublicKeys.has(item.old_public_key)) {
        return invalid(
          "rotation_chain_repeated_key",
          `identity ${args.identityId} hop ${i}: repeated old_public_key`
        );
      }
      seenPublicKeys.add(item.old_public_key);
      if (seenPublicKeys.has(item.new_public_key) && i < args.rotationHistory.length - 1) {
        return invalid(
          "rotation_chain_repeated_key",
          `identity ${args.identityId} hop ${i}: repeated new_public_key`
        );
      }

      const parsed = parseRotationEvent(item.rotation_event, i);
      if (!parsed.ok) return parsed.result;
      const event = parsed.event;
      if (
        event.identity_id !== args.identityId ||
        event.old_public_key !== item.old_public_key ||
        event.new_public_key !== item.new_public_key ||
        event.rotated_at !== item.rotated_at
      ) {
        return invalid(
          "rotation_event_mismatch",
          `identity ${args.identityId} hop ${i}: rotation_event fields do not match the history entry`
        );
      }

      let oldPublicKey: Uint8Array;
      let signature: Uint8Array;
      try {
        oldPublicKey = fromBase64url(event.old_public_key);
        signature = fromBase64url(event.signature);
      } catch {
        return invalid(
          "rotation_signature_invalid",
          `identity ${args.identityId} hop ${i}: signature or old_public_key is not base64url`
        );
      }
      // INVARIANT: each hop must be signed by the key being retired, or an
      // attacker can write a syntactically contiguous chain for keys they never held.
      if (!verify(rotationEventSigningBytes(event), signature, oldPublicKey)) {
        return invalid(
          "rotation_signature_invalid",
          `identity ${args.identityId} hop ${i}: rotation_event signature did not verify`
        );
      }

      retiredOldestFirst.push({
        public_key: oldPublicKey,
        public_key_base64url: event.old_public_key,
        retired_at: event.rotated_at,
        reason: event.reason,
        compromised: /\bcompromis(?:e|ed|ing)\b/i.test(event.reason),
      });
      expectedOldPublicKey = event.new_public_key;
      lastNewPublicKey = event.new_public_key;
    }

    // INVARIANT: a chain that does not terminate at the current key would let a
    // bundle author introduce keys the current identity never authorized.
    if (
      typeof args.currentPublicKey === "string" &&
      lastNewPublicKey !== args.currentPublicKey
    ) {
      return invalid(
        "rotation_chain_non_terminating",
        `identity ${args.identityId}: final new_public_key does not match current public key`
      );
    }

    return {
      status: "verified",
      chain: {
        identity_id: args.identityId,
        current_public_key: currentPublicKey.bytes,
        retired: retiredOldestFirst.reverse(),
        hop_count: args.rotationHistory.length,
      },
    };
  } catch (error) {
    return invalid(
      "rotation_event_malformed",
      `identity ${args.identityId}: rotation chain verifier caught ${error instanceof Error ? error.name : "unknown error"}`
    );
  }
}
