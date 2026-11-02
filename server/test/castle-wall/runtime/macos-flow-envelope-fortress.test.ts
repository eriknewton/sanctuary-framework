// fail-before-exempt: the existing adapter already uses constructor fortress scope; a manifest-scope mutation exercises this carry-over guard.
import { expect, it, vi } from "vitest";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import { AuditConsumer } from "../../../src/castle-wall/runtime/audit-consumer.js";

it("uses constructor fortress scope in the producer envelope independently of manifest scope", async () => {
  const ingest = vi.spyOn(AuditConsumer.prototype, "ingestCritical").mockResolvedValue(undefined);
  try {
    const consumer = new MacOSFlowEventConsumer({
      fortressId: "configured-fortress", defaultApprovalTimeoutSeconds: 30, // ordinary approval timeout, unused by a recorded decision
      pinnedProducerKeyB64url: Buffer.alloc(32, 1).toString("base64url"), // isolated public key shape; the consumer handoff is observed directly
      auditSink: { append() {}, async flush() {} }, approvalQueue: { async enqueue() {} },
      manifestProvider: { currentSnapshot: () => ({ rules: [], signed_manifest: {
        manifest: { schema_version: 1, fortress_id: "manifest-fortress", issued_at: "2026-06-14T00:00:00Z", rules: [] },
        signature: { signature_scheme: "ed25519-v1", signing_key_id: "fixture", signature_b64url: "fixture" },
      } }) },
    });
    const auditToken = Buffer.from(new Uint32Array([0, 501, 501, 501, 501, 123, 1, 1]).buffer).toString("hex"); // eight Darwin audit-token words, ruid 501
    await consumer.handleFlowDecisionRecorded({ type: "flow_decision_recorded", decision: "drop", recorded_at: "2026-06-14T00:00:00Z",
      agent: { id: auditToken, template: "test" }, destination: { host: null, ip: "192.0.2.1", port: 443, protocol: "tcp", hostname_source: null, opaque: false },
    });
    expect(ingest).toHaveBeenCalledOnce();
    expect(ingest.mock.calls[0]![0].event.fortress_id).toBe("configured-fortress");
    expect(ingest.mock.calls[0]![0].producerSubjectBinding).toEqual({ kind: "macos_audit_token", fortressId: "configured-fortress" });
  } finally { ingest.mockRestore(); }
});
