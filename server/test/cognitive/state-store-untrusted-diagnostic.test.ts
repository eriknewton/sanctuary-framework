/**
 * Regression cover for register row STATE-STORE-ERRMSG-INTERP-01.
 *
 * PROPERTY UNDER TEST: whatever a persisted state entry holds in its fields,
 * the state store's refusal reaches the caller as its own typed, bounded
 * verdict. A malformed stored field must change WHAT the store reports, never
 * WHETHER the report arrives.
 *
 * These assert the mechanism (a typed refusal, with a length that does not
 * scale with the stored value), not merely that something threw.
 */
import { describe, expect, it } from "vitest";
import {
  rotateStateEntryBytes,
  RotationStateEntryError,
  StateStore,
  StateVerificationError,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { MAX_UNTRUSTED_DIAGNOSTIC_CHARS } from "../../src/errors/index.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

/**
 * A value that overflows the stack when `String()` walks it, because
 * `Array.prototype.toString` delegates to `join`, which recurses. 200_000 is
 * comfortably past any engine's stack limit while staying cheap to build.
 */
function deeplyNested(depth = 200_000): unknown {
  let value: unknown = "x";
  for (let index = 0; index < depth; index += 1) value = [value];
  return value;
}

/**
 * The longest message a converted site can produce is its own fixed prose plus
 * one bounded untrusted rendering. 1_000 is a generous ceiling over every such
 * fixed prefix in this file's call sites; the point of the assertion is that
 * the length does NOT scale with the stored value.
 */
const MESSAGE_CEILING = 1_000;

function entryWithKid(kid: unknown): StateEntry {
  return {
    v: 3,
    ver: 1,
    kid,
    sig: "AAAA",
    payload: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", tag: "AA" },
    integrity_hash: "unused",
    created_at: new Date().toISOString(),
    provenance_stamp: { class: "unused" },
  } as unknown as StateEntry;
}

function makeStore(): StateStore {
  return new StateStore(new MemoryStorage(), generateRandomKey());
}

describe("state-store diagnostics over untrusted stored fields", () => {
  it("reports kid_unknown for a deeply nested stored kid instead of overflowing the stack", async () => {
    const store = makeStore();

    // FAIL-BEFORE: confirmed failing against the pre-fix tree, where the
    // caller never received this typed verdict at all.
    const result = await store.remintVerifiedProvenanceStampForExport(
      entryWithKid(deeplyNested()),
      "ns",
      "key"
    );

    expect(result.status).toBe("verification_failed");
    if (result.status !== "verification_failed") throw new Error("unreachable");
    expect(result.error).toBeInstanceOf(StateVerificationError);
    expect(result.error.classification).toBe("kid_unknown");
    expect(result.error.message.length).toBeLessThan(MESSAGE_CEILING);
  });

  it("bounds the diagnostic for an enormous stored kid rather than echoing it", async () => {
    const store = makeStore();
    const huge = "A".repeat(5_000_000);

    const result = await store.remintVerifiedProvenanceStampForExport(
      entryWithKid(huge),
      "ns",
      "key"
    );

    expect(result.status).toBe("verification_failed");
    if (result.status !== "verification_failed") throw new Error("unreachable");
    expect(result.error.classification).toBe("kid_unknown");
    expect(result.error.message.length).toBeLessThan(MESSAGE_CEILING);
    // Non-deceptive: the operator is told the value was shortened.
    expect(result.error.message).toContain("truncated");
    expect(result.error.message).toContain(
      "A".repeat(MAX_UNTRUSTED_DIAGNOSTIC_CHARS)
    );
  });

  it("still renders an ordinary kid unchanged", async () => {
    const store = makeStore();

    const result = await store.remintVerifiedProvenanceStampForExport(
      entryWithKid("agent-7f3a"),
      "ns",
      "key"
    );

    expect(result.status).toBe("verification_failed");
    if (result.status !== "verification_failed") throw new Error("unreachable");
    expect(result.error.message).toContain("Writer key not found for agent-7f3a");
    expect(result.error.message).not.toContain("truncated");
  });

  it("refuses rotation of an entry whose stored kid is deeply nested, with a typed error", async () => {
    const namespaceKey = generateRandomKey();
    // The on-disk bytes are built textually: `JSON.stringify` recurses too, so
    // serializing the hostile value here would overflow the TEST's stack rather
    // than the code under test. An attacker writing the file never calls
    // stringify either.
    const depth = 200_000;
    const nestedJson = "[".repeat(depth) + '"x"' + "]".repeat(depth);
    const entryJson = JSON.stringify({
      ...entryWithKid("PLACEHOLDER_KID"),
      payload: encrypt(stringToBytes("plaintext"), namespaceKey),
    }).replace('"PLACEHOLDER_KID"', nestedJson);

    // FAIL-BEFORE: confirmed failing against the pre-fix tree, where the typed
    // rotation refusal was not what reached the caller.
    await expect(
      rotateStateEntryBytes({
        raw: stringToBytes(entryJson),
        namespace: "ns",
        key: "key",
        oldNamespaceKey: namespaceKey,
        newNamespaceKey: generateRandomKey(),
        resolveWriter: async () => null,
      })
    ).rejects.toBeInstanceOf(RotationStateEntryError);
  });
});
