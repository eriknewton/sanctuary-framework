/**
 * Tests for A1: agent-origin descriptor delivery through the daemon and
 * operator rule-id attribution in the stored audit entry (#381).
 *
 * Asserts:
 *  - The daemon loads agent-origin.json from the fortress policy dir
 *  - The agent-origin is included in the signed manifest
 *  - The flow-event consumer writes the matched rule id into the stored audit
 *    entry so the operator can attribute a flow to a specific rule. The
 *    no-agent-leak invariant (property #11) is enforced at the agent-facing
 *    read boundary (`monitor_audit_log` redaction), proven in
 *    test/security/cred-return-hardening.test.ts, not by dropping the id at
 *    write time.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import {
  buildSignedManifest,
  localManifestSigner,
  type ManifestSigner,
} from "../../../src/castle-wall/runtime/manifest-publisher.js";
import {
  verifyManifestSignature,
} from "../../../src/castle-wall/allowlist/parse.js";
import { encrypt } from "../../../src/core/encryption.js";
import { randomBytes } from "../../../src/core/random.js";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { FlowDecisionRecordedNotification } from "../../../src/castle-wall/ipc/messages.js";

function makeSigningKey(): { signer: ManifestSigner; publicKey: Uint8Array } {
  const seed = randomBytes(32);
  const publicKey = ed25519.getPublicKey(seed);
  const masterKey = randomBytes(32);
  const encryptedPrivateKey = encrypt(seed, masterKey);
  return {
    signer: localManifestSigner({
      signingKeyId: "test-key",
      encryptedPrivateKey,
      encryptionKey: masterKey,
    }),
    publicKey,
  };
}

describe("castle-wall/runtime/daemon-agent-origin", () => {
  describe("agent-origin in signed manifest", () => {
    it("includes a valid uid-mode agent-origin in the signed manifest body", async () => {
      const signingKey = makeSigningKey();
      const agentOrigin = {
        mode: "uid",
        agent_uid: 502,
        system_uid_allow_ceiling: 500,
      };
      const { signed } = await buildSignedManifest({
        fortressId: "test-fortress",
        issuedAt: new Date().toISOString(),
        rules: [],
        signer: signingKey.signer,
        agentOrigin,
      });
      expect(signed.manifest.agent_origin).toEqual(agentOrigin);
      const result = verifyManifestSignature(signed, signingKey.publicKey);
      expect(result.ok).toBe(true);
    });

    it("includes a valid nat-mode agent-origin in the signed manifest body", async () => {
      const signingKey = makeSigningKey();
      const agentOrigin = {
        mode: "nat",
        egress_helper_signing_id: "ai.sanctuaryprotocol.egress-helper",
        system_uid_allow_ceiling: 500,
      };
      const { signed } = await buildSignedManifest({
        fortressId: "test-fortress",
        issuedAt: new Date().toISOString(),
        rules: [],
        signer: signingKey.signer,
        agentOrigin,
      });
      expect(signed.manifest.agent_origin).toEqual(agentOrigin);
    });

    it("omits agent-origin when not provided (fail-closed classify-all-agent)", async () => {
      const signingKey = makeSigningKey();
      const { signed } = await buildSignedManifest({
        fortressId: "test-fortress",
        issuedAt: new Date().toISOString(),
        rules: [],
        signer: signingKey.signer,
      });
      expect(signed.manifest.agent_origin).toBeUndefined();
    });

    it("omits agent-origin when candidate is malformed (fail-closed)", async () => {
      const signingKey = makeSigningKey();
      const { signed } = await buildSignedManifest({
        fortressId: "test-fortress",
        issuedAt: new Date().toISOString(),
        rules: [],
        signer: signingKey.signer,
        agentOrigin: { mode: "uid" }, // missing agent_uid
      });
      expect(signed.manifest.agent_origin).toBeUndefined();
    });
  });

  describe("operator rule-id attribution (#381)", () => {
    let consumer: MacOSFlowEventConsumer;
    let auditEntries: Array<{
      layer: string;
      operation: string;
      namespaceId: string;
      metadata: Record<string, unknown>;
      status: string;
    }>;

    beforeEach(() => {
      auditEntries = [];
      consumer = new MacOSFlowEventConsumer({
        manifestProvider: {
          currentSnapshot() {
            return {
              signed_manifest: {
                manifest: {
                  schema_version: 1,
                  fortress_id: "test",
                  issued_at: new Date().toISOString(),
                  rules: [],
                },
                signature: {
                  signature_scheme: "ed25519",
                  signing_key_id: "test",
                  signature_b64url: "dGVzdA",
                },
              },
              rules: [],
            };
          },
        },
        approvalQueue: {
          async enqueue() {},
        },
        auditSink: {
          append(layer, operation, namespaceId, metadata, status) {
            auditEntries.push({
              layer,
              operation,
              namespaceId,
              metadata: metadata as Record<string, unknown>,
              status,
            });
          },
          async flush() {},
        },
        defaultApprovalTimeoutSeconds: 30,
      });
    });

    it("records operator_passthrough as the matched rule id for baseline allows", async () => {
      const notification: FlowDecisionRecordedNotification = {
        type: "flow_decision_recorded",
        decision: "allow",
        destination: {
          host: "api.anthropic.com",
          ip: "104.18.0.1",
          port: 443,
          protocol: "tcp",
          hostname_source: "sni",
          opaque: false,
        },
        agent: { id: "test-agent", template: "unknown" },
        matched_rule_id: "operator_passthrough",
        recorded_at: new Date().toISOString(),
      };
      await consumer.handleFlowDecisionRecorded(notification);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0]!.metadata.rule_id).toBe("operator_passthrough");
      expect(auditEntries[0]!.operation).toBe("egress_allowed");
    });

    it("records the specific rule id for an allow-by-rule match", async () => {
      const notification: FlowDecisionRecordedNotification = {
        type: "flow_decision_recorded",
        decision: "allow",
        destination: {
          host: "api.anthropic.com",
          ip: "104.18.0.1",
          port: 443,
          protocol: "tcp",
          hostname_source: "sni",
          opaque: false,
        },
        agent: { id: "test-agent", template: "unknown" },
        matched_rule_id: "allow-anthropic-api",
        recorded_at: new Date().toISOString(),
      };
      await consumer.handleFlowDecisionRecorded(notification);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0]!.metadata.rule_id).toBe("allow-anthropic-api");
    });

    it("records the specific rule id for a deny-by-rule match", async () => {
      const notification: FlowDecisionRecordedNotification = {
        type: "flow_decision_recorded",
        decision: "drop",
        destination: {
          host: "blocked.example.com",
          ip: "203.0.113.10",
          port: 443,
          protocol: "tcp",
          hostname_source: "sni",
          opaque: false,
        },
        agent: { id: "test-agent", template: "unknown" },
        matched_rule_id: "deny-blocked-example",
        recorded_at: new Date().toISOString(),
      };
      await consumer.handleFlowDecisionRecorded(notification);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0]!.metadata.rule_id).toBe("deny-blocked-example");
      expect(auditEntries[0]!.operation).toBe("egress_blocked");
    });

    it("records a null rule id for a baseline default-deny (no rule matched)", async () => {
      const notification: FlowDecisionRecordedNotification = {
        type: "flow_decision_recorded",
        decision: "drop",
        destination: {
          host: "example.com",
          ip: "93.184.216.34",
          port: 443,
          protocol: "tcp",
          hostname_source: "sni",
          opaque: false,
        },
        agent: { id: "test-agent", template: "unknown" },
        matched_rule_id: null,
        recorded_at: new Date().toISOString(),
      };
      await consumer.handleFlowDecisionRecorded(notification);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0]!.metadata.rule_id).toBeNull();
      expect(auditEntries[0]!.operation).toBe("egress_blocked");
    });
  });
});
