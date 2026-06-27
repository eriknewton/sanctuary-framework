/**
 * Sanctuary Composition v1.0 -- Sidecar Trust Boundary
 *
 * Closes Sanctuary Invariant #4 (never assume trust across the
 * Sanctuary-Concordia boundary). Sidecar JSON-RPC responses cross a
 * process boundary; tsc cannot prove their structure. The adapters
 * MUST validate runtime shape before returning typed values.
 *
 * v1.1 pre-tag fix wave Fix #1.
 */

import { describe, it, expect } from "vitest";
import {
  packConcordiaReceipt,
  verifyConcordiaReceipt,
  verifyMandate,
} from "../../src/composition/concordia-adapter.js";
import { SidecarResponseShapeError } from "../../src/composition/errors.js";
import {
  clearPublishedSignals,
  getPublishedSignals,
} from "../../src/composition/verascore-hook.js";
import {
  assertBoolean,
  assertChecksRecord,
  assertNonEmptyString,
  assertOptionalPlainObject,
  assertOptionalString,
  assertPlainObject,
  isPlainObject,
} from "../../src/composition/assert-shape.js";
import type { CommitmentEvent, ConcordiaReceipt, SidecarResponse } from "../../src/composition/types.js";
import type { SidecarRpcClient } from "../../src/composition/sidecar-rpc.js";

function makeRpcClient(response: SidecarResponse): SidecarRpcClient {
  return {
    call: async () => response,
  } as unknown as SidecarRpcClient;
}

const baseEvent: CommitmentEvent = {
  event_id: "evt-1",
  event_type: "test_commitment",
  agent_id: "agent-a",
  counterparty_id: "agent-b",
  commitment_class: "delivery",
  fortress_id: "fortress-x",
  emitter_node: "node-1",
  emitted_at: "2026-04-25T00:00:00Z",
};

const baseReceipt: ConcordiaReceipt = {
  receipt_id: "rcpt-1",
  schema_urn: "urn:concordia:receipt:v1",
  source_event_id: "evt-1",
  source_event_type: "test_commitment",
  agent_id: "agent-a",
  counterparty_id: "agent-b",
  commitment_class: "delivery",
  references: [],
  signature: "sig",
  signature_scheme: "ed25519-v1",
  packed_at: "2026-04-25T00:00:00Z",
};

function makePackResponse(
  attestation_metadata?: Record<string, unknown>
): SidecarResponse {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      receipt_id: "rcpt-1",
      signature: "sig",
      packed_at: "2026-04-25T00:00:00Z",
      ...(attestation_metadata === undefined ? {} : { attestation_metadata }),
    },
  };
}

describe("composition: sidecar trust boundary (#1)", () => {
  describe("packConcordiaReceipt runtime shape validation", () => {
    it("throws SidecarResponseShapeError when receipt_id is missing", async () => {
      const rpc = makeRpcClient({ jsonrpc: "2.0", id: 1, result: { signature: "sig" } });
      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("throws SidecarResponseShapeError when receipt_id has wrong type", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        result: { receipt_id: 42, signature: "sig" },
      });
      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("throws SidecarResponseShapeError when signature is null", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        result: { receipt_id: "rcpt-1", signature: null },
      });
      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("throws SidecarResponseShapeError when result is not an object", async () => {
      const rpc = makeRpcClient({ jsonrpc: "2.0", id: 1, result: "not-an-object" });
      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("passes allowlisted behavioral attestation metadata unchanged", async () => {
      const metadata = {
        commitment_class: "delivery",
        references_count: 2,
        counterparty_count: 1,
        offers_made: 3,
        concession_magnitude: 0.25,
        reasoning_provided: true,
      };
      const rpc = makeRpcClient(makePackResponse(metadata));

      const receipt = await packConcordiaReceipt(rpc, baseEvent);

      expect(receipt.attestation_metadata).toEqual(metadata);
    });

    it("rejects raw-term attestation metadata keys before Verascore emission", async () => {
      clearPublishedSignals();
      const rawTermKeys = [
        "price",
        "amount",
        "quantity",
        "total",
        "terms",
        "currency",
      ];

      for (const rawKey of rawTermKeys) {
        const rpc = makeRpcClient(makePackResponse({ [rawKey]: "private-term" }));
        await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
          SidecarResponseShapeError
        );
      }
      expect(getPublishedSignals()).toHaveLength(0);
    });

    it("rejects raw-term attestation metadata keys without echoing key or value", async () => {
      const rpc = makeRpcClient(makePackResponse({ price: 999 }));

      const error = await packConcordiaReceipt(rpc, baseEvent).then(
        () => undefined,
        (caught: unknown) => caught
      );

      expect(error).toBeInstanceOf(SidecarResponseShapeError);
      expect((error as Error).message).toContain(
        "Concordia sidecar attestation_metadata contains a disallowed field"
      );
      expect((error as Error).message).not.toContain("price");
      expect((error as Error).message).not.toContain("999");
    });

    it("rejects non-allowlisted attestation metadata keys fail-closed", async () => {
      const rpc = makeRpcClient(
        makePackResponse({
          commitment_class: "delivery",
          negotiation_notes: "behavioral note",
        })
      );

      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("rejects raw-term-like attestation metadata values", async () => {
      const rpc = makeRpcClient(
        makePackResponse({
          commitment_class: "delivery for $100",
          references_count: 1,
        })
      );

      await expect(packConcordiaReceipt(rpc, baseEvent)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });
  });

  describe("verifyConcordiaReceipt runtime shape validation", () => {
    it("throws SidecarResponseShapeError when valid is missing", async () => {
      const rpc = makeRpcClient({ jsonrpc: "2.0", id: 1, result: {} });
      await expect(verifyConcordiaReceipt(rpc, baseReceipt)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("throws SidecarResponseShapeError when valid is a string instead of boolean", async () => {
      const rpc = makeRpcClient({ jsonrpc: "2.0", id: 1, result: { valid: "true" } });
      await expect(verifyConcordiaReceipt(rpc, baseReceipt)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("returns false when sidecar surfaces an RPC error (no shape exception)", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: "unrelated failure" },
      });
      await expect(verifyConcordiaReceipt(rpc, baseReceipt)).resolves.toBe(false);
    });
  });

  describe("verifyMandate runtime shape validation", () => {
    const mandate = { mandate_id: "m-1", issuer: "i", subject: "s", delegation_chain: [] };

    it("throws SidecarResponseShapeError when checks field is missing", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        result: { valid: true, status: "active" },
      });
      await expect(verifyMandate(rpc, mandate)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("throws SidecarResponseShapeError when a required check flag is non-boolean", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        result: {
          valid: true,
          status: "active",
          checks: {
            signature_valid: true,
            chain_valid: true,
            not_expired: true,
            not_revoked: true,
            constraints_valid: "yes",
          },
        },
      });
      await expect(verifyMandate(rpc, mandate)).rejects.toBeInstanceOf(
        SidecarResponseShapeError
      );
    });

    it("falls back to active status when status field is malformed", async () => {
      const rpc = makeRpcClient({
        jsonrpc: "2.0",
        id: 1,
        result: {
          valid: true,
          status: "garbage",
          checks: {
            signature_valid: true,
            chain_valid: true,
            not_expired: true,
            not_revoked: true,
            constraints_valid: true,
          },
        },
      });
      const result = await verifyMandate(rpc, mandate);
      expect(result.status).toBe("active");
    });
  });

  describe("assertShape primitives", () => {
    it("isPlainObject rejects null", () => {
      expect(isPlainObject(null)).toBe(false);
    });

    it("isPlainObject rejects arrays", () => {
      expect(isPlainObject([])).toBe(false);
    });

    it("isPlainObject accepts objects", () => {
      expect(isPlainObject({})).toBe(true);
    });

    it("assertNonEmptyString rejects empty string", () => {
      expect(() => assertNonEmptyString("test", { x: "" }, "x")).toThrow(
        SidecarResponseShapeError
      );
    });

    it("assertOptionalString accepts undefined", () => {
      expect(assertOptionalString("test", {}, "x")).toBeUndefined();
    });

    it("assertOptionalString rejects non-string", () => {
      expect(() => assertOptionalString("test", { x: 42 }, "x")).toThrow(
        SidecarResponseShapeError
      );
    });

    it("assertOptionalPlainObject rejects array", () => {
      expect(() => assertOptionalPlainObject("test", { x: [] }, "x")).toThrow(
        SidecarResponseShapeError
      );
    });

    it("assertBoolean rejects non-boolean", () => {
      expect(() => assertBoolean("test", { x: 1 }, "x")).toThrow(
        SidecarResponseShapeError
      );
    });

    it("assertChecksRecord rejects missing flag", () => {
      expect(() =>
        assertChecksRecord("test", { x: { a: true } }, "x", ["a", "b"])
      ).toThrow(SidecarResponseShapeError);
    });

    it("assertPlainObject rejects null", () => {
      expect(() => assertPlainObject("test", null)).toThrow(SidecarResponseShapeError);
    });
  });
});
