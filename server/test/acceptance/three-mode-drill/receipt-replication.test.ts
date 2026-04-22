/**
 * §12.5 — Receipt replicates cleanly across all three nodes.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.5,
 *       §5.5 (receipt replication), §4.2 (signed-event envelope)
 *
 *   "A receipt produced on one node lands on every operator-designated
 *    replica. Any replica can serve the same bytes to a verifier."
 *
 * The v0.1 mesh reserves `receipt_replicate` as a unicast event type but
 * ships no per-node receipt store — the operator-configured replica policy
 * lives outside this drill thread (§5.5 decisions for Follow-up #3). For
 * §12.5 acceptance, the harness proves receipt REPLICATION — that the same
 * signed receipt bytes, once emitted, reach every node in the fortress — by
 * broadcasting through gossipsub and capturing at each transport. This
 * demonstrates the byte-equivalence contract the receipt-replication logic
 * will consume.
 *
 * The test uses `packSignedEvent` + `transport.broadcast` directly because
 * the MeshNode class does not yet expose `publishReceipt`. Flagged in the
 * handoff — every other signed-event class already has a publish helper.
 */

import { afterEach, describe, expect, it } from "vitest";

import { packSignedEvent } from "../../../src/mesh/envelope.js";
import type {
  ReceiptReplicatePayload,
  SignedEvent,
} from "../../../src/mesh/types.js";
import { randomBytes } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";

import { bootThreeModeDrill, type ThreeModeDrillHandle, waitFor } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.5 — receipt replicates byte-identical across all three nodes", () => {
  it(
    "receipt emitted on B reaches A and C; all three hold byte-identical receipt bytes",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // Three transport-level collectors — one per node.
      const collected: Record<string, SignedEvent<ReceiptReplicatePayload>[]> =
        { A: [], B: [], C: [] };

      drill.transportA.subscribe((evt) => {
        if (evt.event_type === "receipt_replicate") {
          collected.A.push(evt as SignedEvent<ReceiptReplicatePayload>);
        }
      });
      drill.transportB.subscribe((evt) => {
        if (evt.event_type === "receipt_replicate") {
          collected.B.push(evt as SignedEvent<ReceiptReplicatePayload>);
        }
      });
      drill.transportC.subscribe((evt) => {
        if (evt.event_type === "receipt_replicate") {
          collected.C.push(evt as SignedEvent<ReceiptReplicatePayload>);
        }
      });

      // Emit a real signed receipt_replicate from B. The receipt_bytes
      // are an opaque base64 payload — the verifier semantics are
      // Concordia's concern; the mesh proves byte-identity of the
      // envelope, not receipt semantics.
      const receiptBytes = toBase64url(randomBytes(128));
      const payload: ReceiptReplicatePayload = {
        receipt_id: "drill-receipt-§12.5-" + Date.now(),
        originating_agent_id: "drill-agent-receipts",
        receipt_bytes: receiptBytes,
      };
      const evt = packSignedEvent<ReceiptReplicatePayload>({
        event_type: "receipt_replicate",
        emitter_node: drill.nodeIdB,
        emitter_principal: drill.root_principal_cert.principal_id,
        fortress_id: drill.fortressId,
        payload,
        monotonic_seq: Date.now(), // test-local monotonic; not a counter collision
        node_private_key: drill.nodeKpB.privateKey,
        principal_private_key: drill.root_principal_keypair.privateKey,
      });
      expect(evt.node_signature).toBeTruthy();

      await drill.transportB.broadcast(evt);

      // A and C each see it on their transport; B does not (gossipsub does
      // not echo to the publisher). The emitter holds the event directly.
      await waitFor(
        () => collected.A.length >= 1 && collected.C.length >= 1,
        10_000,
        25,
        "receipt reaches A and C"
      );

      // ── Byte-identity across all three "copies" ──────────────────────
      // Emitter-side copy: the original event B just published.
      // Receiver-side copies: what A and C deserialized off the wire.
      const copyB = evt;
      const copyA = collected.A[0];
      const copyC = collected.C[0];

      const fingerprint = (e: SignedEvent<ReceiptReplicatePayload>) => ({
        event_id: e.event_id,
        event_type: e.event_type,
        emitter_node: e.emitter_node,
        fortress_id: e.fortress_id,
        payload_hash: e.payload_hash,
        node_signature: e.node_signature,
        principal_signature: e.principal_signature,
        receipt_id: e.payload.receipt_id,
        receipt_bytes: e.payload.receipt_bytes,
      });

      expect(fingerprint(copyA)).toEqual(fingerprint(copyB));
      expect(fingerprint(copyC)).toEqual(fingerprint(copyB));
      // Any verifier querying A, B, or C gets back the same bytes.
      expect(copyA.payload.receipt_bytes).toBe(receiptBytes);
      expect(copyB.payload.receipt_bytes).toBe(receiptBytes);
      expect(copyC.payload.receipt_bytes).toBe(receiptBytes);
    },
    60_000
  );
});
