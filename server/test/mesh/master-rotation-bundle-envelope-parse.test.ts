/**
 * Regression cover for:
 *   - STATE-STORE-ERRMSG-INTERP-01 (wire variant): malformed envelope fields are
 *     refused with a typed SecretBundleError, not an unrelated RangeError.
 *   - WIRE-PARSE-SNAPSHOT-01: the returned envelope is a fresh plain object built
 *     from validated locals, not an alias of the untrusted input. A stateful
 *     accessor (Proxy, getter) that satisfies the validation read cannot deliver a
 *     different value on a later read from the snapshot.
 *
 * FAIL-BEFORE for WIRE-PARSE-SNAPSHOT-01: before this fix, parseEnvelopeFields
 * returned `{ ok: true, envelope: raw }` where `raw` is the original input
 * object. Every subsequent read of `envelope.field` re-read from that object.
 * A Proxy whose getter for `rotated_at` returned a valid ISO string on the first
 * call (validation) and returned a non-string on the second call (consumer re-read)
 * would pass parse and deliver the wrong value downstream — exactly the class
 * rule 11 (AGENTS.md) exists to close.
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
      // wrong version: v must be exactly 1
      ["ciphertext", { v: 2, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: "t" }],
      // wrong algorithm: alg must be exactly "aes-256-gcm"
      ["ciphertext", { v: 1, alg: "aes-128-gcm", iv: "AA", ct: "AA", ts: "t" }],
      // missing ts: ts is required (EncryptedPayload.ts is string, not optional)
      ["ciphertext", { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA" }],
      // non-string ts
      ["ciphertext", { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: 9 }],
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

    it("refuses wrong ciphertext version, wrong algorithm, and missing/non-string ts via typed parse", () => {
      // wrong version
      expect(
        parseMasterRotationBundleEnvelope(
          envelopeWith({ ciphertext: { v: 2, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: "t" } })
        )
      ).toEqual({ ok: false, reason: "ciphertext_field_invalid" });
      // wrong algorithm
      expect(
        parseMasterRotationBundleEnvelope(
          envelopeWith({ ciphertext: { v: 1, alg: "aes-128-gcm", iv: "AA", ct: "AA", ts: "t" } })
        )
      ).toEqual({ ok: false, reason: "ciphertext_field_invalid" });
      // missing ts
      expect(
        parseMasterRotationBundleEnvelope(
          envelopeWith({ ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA" } })
        )
      ).toEqual({ ok: false, reason: "ciphertext_field_invalid" });
      // non-string ts
      expect(
        parseMasterRotationBundleEnvelope(
          envelopeWith({ ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: 9 } })
        )
      ).toEqual({ ok: false, reason: "ciphertext_field_invalid" });
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

  // ─── WIRE-PARSE-SNAPSHOT-01 regressions ─────────────────────────────────────
  //
  // These tests prove the closed form of the aliasing class: the returned
  // envelope is a new plain object built only from validated locals. They must
  // FAIL on the pre-fix return `{ ok: true, envelope: raw }` and PASS on the
  // snapshot return.

  describe("WIRE-PARSE-SNAPSHOT-01: returned envelope is a snapshot, not an alias", () => {
    it("post-parse mutation of the input object does not change the snapshot", () => {
      // FAIL-BEFORE: envelope === raw (the input), so mutating raw.rotated_at
      // mutated envelope.rotated_at too.
      const input: Record<string, unknown> = {
        kind: "master_rotation_bundle",
        target_node_id: "node-a",
        fortress_id: "fortress-a",
        ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "BB", ts: "t" },
        rotated_at: "2026-01-01T00:00:00.000Z",
        new_master_pubkey: "AAAA",
      };
      const result = parseMasterRotationBundleEnvelope(input);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      input["rotated_at"] = "mutated-rotated-at";
      input["target_node_id"] = "mutated-node-id";
      // Snapshot must be unaffected.
      expect(result.envelope.rotated_at).toBe("2026-01-01T00:00:00.000Z");
      expect(result.envelope.target_node_id).toBe("node-a");
    });

    it("ciphertext sub-object mutation after parse does not affect the snapshot", () => {
      // FAIL-BEFORE: envelope.ciphertext === raw.ciphertext (same reference),
      // so mutating the ciphertext object mutated envelope.ciphertext too.
      const cipherObj: Record<string, unknown> = {
        v: 1,
        alg: "aes-256-gcm",
        iv: "AA",
        ct: "BB",
        ts: "t",
      };
      const input: Record<string, unknown> = {
        kind: "master_rotation_bundle",
        target_node_id: "node-a",
        fortress_id: "fortress-a",
        ciphertext: cipherObj,
        rotated_at: "2026-01-01T00:00:00.000Z",
        new_master_pubkey: "AAAA",
      };
      const result = parseMasterRotationBundleEnvelope(input);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      cipherObj["ct"] = "CC-mutated";
      // Snapshot must be unaffected.
      expect(result.envelope.ciphertext.ct).toBe("BB");
    });

    it("stateful accessor: the validated value is preserved in the snapshot (not re-read from Proxy)", () => {
      // FAIL-BEFORE: envelope === raw (the Proxy), so result.envelope.rotated_at
      // triggered the Proxy getter a second time and returned the alternate value.
      let rotatedAtReadCount = 0;
      const validRotatedAt = "2026-06-01T00:00:00.000Z";
      const proxy = new Proxy(
        {
          kind: "master_rotation_bundle",
          target_node_id: "node-a",
          fortress_id: "fortress-a",
          rotated_at: validRotatedAt,
          new_master_pubkey: "AAAA",
          ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: "t" },
        },
        {
          get(target, key, receiver) {
            if (key === "rotated_at") {
              rotatedAtReadCount += 1;
              // First read (validation): return valid string.
              // Any later read: return a non-string to detect re-reads.
              return rotatedAtReadCount === 1 ? validRotatedAt : 99999;
            }
            return Reflect.get(target, key, receiver);
          },
        }
      );

      const result = parseMasterRotationBundleEnvelope(proxy);
      // The Proxy returns a valid string on read #1, so the parse succeeds.
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      // Reading the snapshot must NOT trigger the Proxy getter again.
      // After the fix: envelope.rotated_at is the snapshotted "2026-06-01…"
      // Before the fix: envelope.rotated_at re-reads from the Proxy → 99999
      expect(typeof result.envelope.rotated_at).toBe("string");
      expect(result.envelope.rotated_at).toBe(validRotatedAt);
      // Prove the Proxy was read exactly once for this field.
      expect(rotatedAtReadCount).toBe(1);
    });

    it("each ciphertext field is read exactly once; returned ciphertext does not alias the Proxy", () => {
      // FAIL-BEFORE: the ciphertext sub-object was not snapshotted — the
      // returned envelope.ciphertext was the original ctRaw object (or a
      // Proxy thereof), so any field read from it triggered the Proxy getter
      // a second time.
      const ctFieldReads: Record<string, number> = {};
      const cipherTarget = { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "BB", ts: "t" };
      const cipherProxy = new Proxy(cipherTarget, {
        get(target, key, receiver) {
          if (typeof key === "string") {
            ctFieldReads[key] = (ctFieldReads[key] ?? 0) + 1;
          }
          return Reflect.get(target, key, receiver);
        },
      });
      const input: Record<string, unknown> = {
        kind: "master_rotation_bundle",
        target_node_id: "node-a",
        fortress_id: "fortress-a",
        ciphertext: cipherProxy,
        rotated_at: "2026-01-01T00:00:00.000Z",
        new_master_pubkey: "AAAA",
      };
      const result = parseMasterRotationBundleEnvelope(input);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      // Each ciphertext field must have been read exactly once during parsing.
      // Counts are checked before any snapshot access to avoid cross-contamination
      // from assertion machinery inspecting the proxy.
      for (const field of ["v", "alg", "iv", "ct", "ts"]) {
        expect(ctFieldReads[field] ?? 0, `ciphertext field "${field}" was read != 1 times`).toBe(1);
      }

      // Non-aliasing: mutating the Proxy's underlying target does not change the
      // snapshot — the snapshot captured primitive values, not a reference.
      cipherTarget.ct = "CC-mutated";
      expect(result.envelope.ciphertext.ct).toBe("BB");
      // Sanity: snapshot holds all validated field values.
      expect(result.envelope.ciphertext.v).toBe(1);
      expect(result.envelope.ciphertext.ts).toBe("t");
    });

    it("each envelope field is read at most once from the untrusted input", () => {
      // FAIL-BEFORE: parseEnvelopeFields returned the Proxy as envelope; every
      // subsequent access (target_node_id comparison, fortress_id comparison,
      // bundleAad rotated_at/new_master_pubkey reads, decrypt ciphertext read)
      // re-triggered the Proxy getter, so each field's count reached > 1.
      const fieldReads: Record<string, number> = {};
      const baseObj = {
        kind: "master_rotation_bundle",
        target_node_id: "node-a",
        fortress_id: "fortress-a",
        rotated_at: "2026-06-01T00:00:00.000Z",
        new_master_pubkey: "AAAA",
        ciphertext: { v: 1, alg: "aes-256-gcm", iv: "AA", ct: "AA", ts: "t" },
      };
      const proxy = new Proxy(baseObj, {
        get(target, key, receiver) {
          if (typeof key === "string") {
            fieldReads[key] = (fieldReads[key] ?? 0) + 1;
          }
          return Reflect.get(target, key, receiver);
        },
      });

      // Drive through the real consumer path. unwrapMasterRotationBundle
      // re-parses internally; because the ciphertext is fake it throws after
      // the parse — that is expected.
      try {
        unwrapMasterRotationBundle({
          envelope: proxy as unknown as MasterRotationBundleEnvelope,
          old_fortress_master_secret: new Uint8Array(32),
          this_node_id: "node-a",
          this_node_mode: "full" as never,
          this_fortress_id: "fortress-a",
        });
      } catch (e) {
        // Expected: AES-GCM or base64 failure, not a parse failure.
        expect(e).toBeInstanceOf(SecretBundleError);
      }

      // After the fix each top-level field is read exactly once (during the
      // internal parse); the snapshot is used for all subsequent reads.
      for (const field of [
        "kind",
        "target_node_id",
        "fortress_id",
        "rotated_at",
        "new_master_pubkey",
        "ciphertext",
      ]) {
        const reads = fieldReads[field] ?? 0;
        expect(reads, `field "${field}" was read more than once`).toBeLessThanOrEqual(1);
      }
    });
  });
});
