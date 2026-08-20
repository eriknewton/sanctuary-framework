/**
 * Regression cover for register row STATE-STORE-ERRMSG-INTERP-01, wire variant.
 *
 * PROPERTY UNDER TEST: whatever a master-rotation bundle envelope carries on the
 * unicast path, the receiver's refusal reaches the caller as its own typed
 * `SecretBundleError`. A malformed wire field must change WHAT the receiver
 * reports, never WHETHER the report arrives.
 *
 * This is the shape a message-only fix does not reach: the envelope's fields are
 * consumed in comparisons and in AAD construction before anything is
 * authenticated, so the shape has to be established by a parse, not asserted by
 * a cast.
 */
import { describe, expect, it } from "vitest";
import {
  parseMasterRotationBundleEnvelope,
  unwrapMasterRotationBundle,
  SecretBundleError,
  type MasterRotationBundleEnvelope,
} from "../../src/mesh/recovery-flows/index.js";

/** Overflows the stack when String() walks it; see the helper's invariant. */
function deeplyNested(depth = 200_000): unknown {
  let value: unknown = "x";
  for (let index = 0; index < depth; index += 1) value = [value];
  return value;
}

function envelopeWith(
  overrides: Record<string, unknown>
): MasterRotationBundleEnvelope {
  return {
    kind: "master_rotation_bundle",
    target_node_id: "node-a",
    fortress_id: "fortress-a",
    ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: "t" },
    rotated_at: new Date().toISOString(),
    new_master_pubkey: "AAAA",
    ...overrides,
  } as unknown as MasterRotationBundleEnvelope;
}

function unwrap(envelope: MasterRotationBundleEnvelope): void {
  unwrapMasterRotationBundle({
    envelope,
    old_fortress_master_secret: new Uint8Array(32),
    this_node_id: "node-a",
    this_node_mode: "full" as never,
    this_fortress_id: "fortress-a",
  });
}

describe("master-rotation bundle envelope parse", () => {
  describe("refuses a malformed wire envelope with a typed error", () => {
    // FAIL-BEFORE: each of the first two rejected with
    // `RangeError: Maximum call stack size exceeded`, so the receiver never
    // reported the refusal it had correctly reached.
    const CASES: Array<[field: string, value: unknown]> = [
      ["target_node_id", deeplyNested()],
      ["fortress_id", deeplyNested()],
      ["target_node_id", 42],
      ["fortress_id", { nested: true }],
      ["rotated_at", []],
      ["new_master_pubkey", null],
      ["ciphertext", "not-an-object"],
      ["ciphertext", { v: "1", alg: 7, iv: null, ct: [] }],
    ];
    for (const [field, value] of CASES) {
      it(`refuses a malformed ${field} (${typeof value})`, () => {
        expect(() => unwrap(envelopeWith({ [field]: value }))).toThrow(
          SecretBundleError
        );
      });
    }
  });

  it("bounds the diagnostic for an enormous wire field", () => {
    try {
      unwrap(envelopeWith({ target_node_id: "A".repeat(5_000_000) }));
      throw new Error("expected a refusal");
    } catch (err) {
      expect(err).toBeInstanceOf(SecretBundleError);
      expect((err as Error).message.length).toBeLessThan(1_000);
    }
  });

  it("still names an ordinary mismatched node in full", () => {
    try {
      unwrap(envelopeWith({ target_node_id: "node-b" }));
      throw new Error("expected a refusal");
    } catch (err) {
      expect((err as Error).message).toContain("target_node_id=node-b");
    }
  });

  describe("the parse is the shared agreement", () => {
    it("accepts a well-formed envelope", () => {
      const result = parseMasterRotationBundleEnvelope(envelopeWith({}));
      expect(result.ok).toBe(true);
    });

    it("names the offending field rather than failing generically", () => {
      expect(parseMasterRotationBundleEnvelope(null)).toEqual({
        ok: false,
        reason: "envelope_not_object",
      });
      expect(parseMasterRotationBundleEnvelope([])).toEqual({
        ok: false,
        reason: "envelope_not_object",
      });
      expect(
        parseMasterRotationBundleEnvelope(envelopeWith({ kind: "other" }))
      ).toEqual({ ok: false, reason: "kind_invalid" });
      expect(
        parseMasterRotationBundleEnvelope(
          envelopeWith({ target_node_id: deeplyNested() })
        )
      ).toEqual({ ok: false, reason: "target_node_id_not_string" });
      expect(
        parseMasterRotationBundleEnvelope(envelopeWith({ ciphertext: 1 }))
      ).toEqual({ ok: false, reason: "ciphertext_not_object" });
    });

    it("never throws, whatever it is handed", () => {
      const hostile: unknown[] = [
        null,
        undefined,
        0,
        "",
        [],
        deeplyNested(),
        envelopeWith({ target_node_id: deeplyNested() }),
        new Proxy({}, { get() { throw new Error("hostile"); } }),
      ];
      for (const value of hostile) {
        expect(() => parseMasterRotationBundleEnvelope(value)).not.toThrow();
      }
    });
  });
});
