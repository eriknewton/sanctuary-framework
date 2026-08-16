import { describe, expect, it } from "vitest";
import {
  createIdentity,
  rotateKeys,
  sign,
  type StoredIdentity,
} from "../../src/core/identity.js";
import {
  verifyRotationChain,
  rotationEventSigningBytes,
  MAX_ROTATION_CHAIN_HOPS,
} from "../../src/core/rotation-chain.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";

function makeIdentity(): {
  identityEncKey: Uint8Array;
  identity: StoredIdentity;
} {
  const master = generateRandomKey();
  const identityEncKey = derivePurposeKey(master, "identity-encryption");
  return {
    identityEncKey,
    identity: createIdentity("rotation-chain", identityEncKey, "recovery-key")
      .storedIdentity,
  };
}

function rotateNTimes(
  identity: StoredIdentity,
  identityEncKey: Uint8Array,
  count: number,
): {
  finalIdentity: StoredIdentity;
  intermediates: StoredIdentity[];
} {
  let current = identity;
  const intermediates: StoredIdentity[] = [identity];
  for (let index = 0; index < count; index++) {
    const rotated = rotateKeys(current, identityEncKey, `routine ${index}`);
    current = rotated.updatedIdentity;
    intermediates.push(current);
  }
  return { finalIdentity: current, intermediates };
}

function verifyIdentity(identity: StoredIdentity) {
  return verifyRotationChain({
    identityId: identity.identity_id,
    currentPublicKey: identity.public_key,
    rotationHistory: identity.rotation_history,
  });
}

describe("verifyRotationChain", () => {
  it("verifies a never-rotated identity", () => {
    const { identity } = makeIdentity();

    const result = verifyIdentity(identity);

    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    expect(result.chain.hop_count).toBe(0);
    expect(result.chain.retired).toEqual([]);
  });

  it("verifies a real three-hop chain newest retired key first", () => {
    const { identity, identityEncKey } = makeIdentity();
    const { finalIdentity, intermediates } = rotateNTimes(
      identity,
      identityEncKey,
      3,
    );

    const result = verifyIdentity(finalIdentity);

    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    expect(result.chain.hop_count).toBe(3);
    expect(result.chain.retired.map((retired) => retired.public_key_base64url)).toEqual([
      intermediates[2]!.public_key,
      intermediates[1]!.public_key,
      intermediates[0]!.public_key,
    ]);
  });

  it.each([
    {
      name: "non-array",
      mutate: (identity: StoredIdentity) => ({
        identityId: identity.identity_id,
        currentPublicKey: identity.public_key,
        rotationHistory: null,
      }),
      reason: "rotation_history_not_array",
    },
    {
      name: "over cap",
      mutate: (identity: StoredIdentity) => ({
        identityId: identity.identity_id,
        currentPublicKey: identity.public_key,
        rotationHistory: Array.from(
          { length: MAX_ROTATION_CHAIN_HOPS + 1 },
          () => ({}),
        ),
      }),
      reason: "rotation_history_over_cap",
    },
    {
      name: "broken contiguity",
      mutate: (identity: StoredIdentity, encKey: Uint8Array) => {
        const { finalIdentity } = rotateNTimes(identity, encKey, 2);
        const history = finalIdentity.rotation_history.map((hop) => ({ ...hop }));
        history[1]!.old_public_key = identity.public_key;
        return {
          identityId: finalIdentity.identity_id,
          currentPublicKey: finalIdentity.public_key,
          rotationHistory: history,
        };
      },
      reason: "rotation_chain_broken_contiguity",
    },
    {
      name: "non-terminating",
      mutate: (identity: StoredIdentity, encKey: Uint8Array) => {
        const { finalIdentity } = rotateNTimes(identity, encKey, 1);
        const unrelated = createIdentity("unrelated", encKey, "recovery-key")
          .storedIdentity;
        return {
          identityId: finalIdentity.identity_id,
          currentPublicKey: unrelated.public_key,
          rotationHistory: finalIdentity.rotation_history,
        };
      },
      reason: "rotation_chain_non_terminating",
    },
    {
      name: "repeated key",
      mutate: (identity: StoredIdentity, encKey: Uint8Array) => {
        const { finalIdentity } = rotateNTimes(identity, encKey, 1);
        return {
          identityId: finalIdentity.identity_id,
          currentPublicKey: identity.public_key,
          rotationHistory: finalIdentity.rotation_history,
        };
      },
      reason: "rotation_chain_repeated_key",
    },
    {
      name: "wrong key length",
      mutate: (identity: StoredIdentity, encKey: Uint8Array) => {
        const { finalIdentity } = rotateNTimes(identity, encKey, 1);
        const history = finalIdentity.rotation_history.map((hop) => ({ ...hop }));
        history[0]!.old_public_key = toBase64url(new Uint8Array([1, 2, 3]));
        return {
          identityId: finalIdentity.identity_id,
          currentPublicKey: finalIdentity.public_key,
          rotationHistory: history,
        };
      },
      reason: "rotation_key_length_invalid",
    },
    {
      name: "bad hop signature",
      mutate: (identity: StoredIdentity, encKey: Uint8Array) => {
        const { finalIdentity } = rotateNTimes(identity, encKey, 1);
        const history = finalIdentity.rotation_history.map((hop) => ({ ...hop }));
        const event = JSON.parse(
          bytesToString(fromBase64url(history[0]!.rotation_event)),
        ) as Record<string, unknown>;
        event.signature = toBase64url(new Uint8Array(64));
        history[0]!.rotation_event = toBase64url(
          stringToBytes(JSON.stringify(event)),
        );
        return {
          identityId: finalIdentity.identity_id,
          currentPublicKey: finalIdentity.public_key,
          rotationHistory: history,
        };
      },
      reason: "rotation_signature_invalid",
    },
  ])("returns $reason for $name", ({ mutate, reason }) => {
    const { identity, identityEncKey } = makeIdentity();

    const result = verifyRotationChain(mutate(identity, identityEncKey));

    expect(result.status).toBe("invalid");
    if (result.status !== "invalid") return;
    expect(result.reason).toBe(reason);
  });

  it("rejects a tampered reason because it is inside the signature preimage", () => {
    const { identity, identityEncKey } = makeIdentity();
    const { finalIdentity } = rotateNTimes(identity, identityEncKey, 1);
    const history = finalIdentity.rotation_history.map((hop) => ({ ...hop }));
    const event = JSON.parse(
      bytesToString(fromBase64url(history[0]!.rotation_event)),
    ) as Record<string, unknown>;
    event.reason = "tampered";
    history[0]!.rotation_event = toBase64url(
      stringToBytes(JSON.stringify(event)),
    );

    const result = verifyRotationChain({
      identityId: finalIdentity.identity_id,
      currentPublicKey: finalIdentity.public_key,
      rotationHistory: history,
    });

    expect(result.status).toBe("invalid");
    if (result.status !== "invalid") return;
    expect(result.reason).toBe("rotation_signature_invalid");
  });

  it("agrees with rotateKeys signature preimage byte order", () => {
    const { identity, identityEncKey } = makeIdentity();
    const rotated = rotateKeys(identity, identityEncKey, "preimage check");
    const event = rotated.rotationEvent;
    const expectedSignature = sign(
      rotationEventSigningBytes(event),
      identity.encrypted_private_key,
      identityEncKey,
    );

    expect(toBase64url(expectedSignature)).toBe(event.signature);
  });

  it("returns invalid rather than throwing for malformed adversarial input", () => {
    const corpus = [
      undefined,
      null,
      7,
      "history",
      [{ old_public_key: {}, new_public_key: [], rotation_event: 1 }],
      [{ rotation_event: toBase64url(stringToBytes("{")) }],
      [{ deeply: { nested: { object: { without: "fields" } } } }],
    ];

    for (const rotationHistory of corpus) {
      expect(() =>
        verifyRotationChain({
          identityId: "adversarial",
          currentPublicKey: new Uint8Array(32),
          rotationHistory,
        }),
      ).not.toThrow();
      const result = verifyRotationChain({
        identityId: "adversarial",
        currentPublicKey: new Uint8Array(32),
        rotationHistory,
      });
      expect(result.status).toBe("invalid");
    }
  });
});
