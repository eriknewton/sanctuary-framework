/**
 * Castle Wall `audit-verify` CLI verb tests (Slice M / Slice R reader leg).
 *
 * `audit-verify` is the read-side TAMPER-EVIDENCE reader: unlike `audit-dump`
 * (which surfaces the recorded, forgeable `cw_source` marker and makes no
 * authenticity claim), this verb CRYPTOGRAPHICALLY RE-VERIFIES each enforcement
 * entry's persisted producer signature against the daemon's pinned producer
 * public key, reusing the exact `reverifyEntryProducerSignature()` gate the
 * posture surface runs.
 *
 * The genuine producer-signed entries here are persisted by driving the REAL
 * `MacOSFlowEventConsumer` (with a pinned key) into a REAL encrypted `AuditLog`
 * - the same path production uses - so the test exercises the true persisted
 * detail-key shape (`cw_producer_sig`, `cw_producer_signed_canonical`,
 * `cw_producer_captured_at_ms`, `cw_evidence_basis`), not a hand-rolled mock.
 *
 * Coverage:
 *   - a genuine extension-signed entry RE-VERIFIES (verified=1).
 *   - a forged/tampered entry (claims producer_signed, signature does not match
 *     the canonical body) is REJECTED (rejected=1) and a tamper WARNING is
 *     emitted - the core forgery-rejection property.
 *   - a GENUINE signed tuple RELABELED under a different top-level operation
 *     (signature re-verifies, but the signed body attests a different op) is
 *     REJECTED, not verified - the operation-binding guard, parity with the
 *     posture / feature-health green-light surfaces.
 *   - DUPLICATED genuine entries (one real tuple re-appended N times) collapse to
 *     a single verified count, with the extras surfaced as `duplicates` - the
 *     replay-dedup guard, parity with the sibling surfaces.
 *   - with NO published producer key, the verb reports the honest
 *     channel-authenticated floor and makes no per-producer claim (channel>0,
 *     verified=0), never faking a verified count.
 *   - a present-but-unreadable producer key (wrong length) FAILS (exit 1)
 *     rather than silently dropping to the channel basis (fail-closed).
 *   - --json emits the machine-readable tally.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hashToString } from "../../src/core/hashing.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { runAuditVerify } from "../../src/cli/castle-wall.js";
import { MacOSFlowEventConsumer } from "../../src/castle-wall/runtime/macos-flow-events.js";
import {
  producerSigningBytes,
  resolveProducerPubKeyPath,
} from "../../src/castle-wall/runtime/producer-signature.js";
import { canonicalize } from "../../src/mesh/canonical-json.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../../src/castle-wall/constants.js";
import type { FlowDecisionRecordedNotification } from "../../src/castle-wall/ipc/messages.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("castle-wall audit-verify", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-verify-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(masterKey)),
    );
    return { fortressPath, masterKey, recoveryKey };
  }

  function notificationFor(
    decision: "allow" | "drop",
    recordedAt: string,
  ): FlowDecisionRecordedNotification {
    return {
      type: "flow_decision_recorded",
      decision,
      destination: { host: "api.anthropic.com", ip: "1.2.3.4", port: 443, protocol: "tcp" },
      agent: { id: "agent-1", template: "coding-assistant" },
      matched_rule_id: decision === "allow" ? "allow-anthropic" : null,
      // The audit consumer enforces signature FRESHNESS (5-min default max age
      // vs Date.now()), so a genuine signed entry must be recorded "now".
      recorded_at: recordedAt,
    };
  }

  /** Build the genuine extension producer tuple the signing key would emit. */
  function signedProducerFor(
    notification: FlowDecisionRecordedNotification,
    privateKey: Uint8Array,
    seq: number,
  ): NonNullable<FlowDecisionRecordedNotification["producer"]> {
    const capturedAtUnixMs = Date.parse(notification.recorded_at);
    const operation = notification.decision === "allow" ? "egress_approved" : "egress_blocked";
    const result = notification.decision === "allow" ? "success" : "blocked";
    const details: Record<string, unknown> = {
      agent_id: notification.agent.id,
      agent_template: notification.agent.template,
      dest_ip: notification.destination.ip,
      dest_port: notification.destination.port,
      dest_protocol: notification.destination.protocol,
      decision: notification.decision,
      prior_sha256_hex: null,
      rule_id: notification.matched_rule_id ?? null,
      seq,
      source: "macos_extension",
    };
    if (notification.destination.host !== null) {
      details.dest_host = notification.destination.host;
    }
    const eventCanonicalJson = canonicalize({
      timestamp: notification.recorded_at,
      layer: "l1",
      operation,
      identity_id: notification.agent.id,
      result,
      details,
    });
    const signature = ed25519.sign(
      producerSigningBytes(eventCanonicalJson, capturedAtUnixMs, seq),
      privateKey,
    );
    return {
      event_canonical_json: eventCanonicalJson,
      captured_at_unix_ms: capturedAtUnixMs,
      seq,
      prior_sha256_hex: null,
      signature_b64url: toBase64url(signature),
      key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    };
  }

  /**
   * Persist a genuine producer-signed enforcement entry the same way the daemon
   * does: a real `MacOSFlowEventConsumer` (pinned key) writing into a real
   * encrypted `AuditLog`. Returns the published producer public key bytes.
   */
  async function seedGenuineSignedEntry(
    fortressPath: string,
    masterKey: Uint8Array,
  ): Promise<Uint8Array> {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: { currentSnapshot: () => ({ signed_manifest: {} as never, rules: [] }) },
      approvalQueue: { async enqueue() {} },
      auditSink: {
        append: (layer, operation, identityId, details, result) =>
          auditLog.append(layer, operation, identityId, details, result),
        flush: () => auditLog.flush(),
      },
      defaultApprovalTimeoutSeconds: 30,
      pinnedProducerKeyB64url: toBase64url(publicKey),
    });
    const notification = notificationFor("drop", new Date().toISOString());
    notification.producer = signedProducerFor(notification, privateKey, 0);
    await consumer.handleFlowDecisionRecorded(notification);
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    return publicKey;
  }

  async function publishProducerKey(fortressPath: string, publicKey: Uint8Array): Promise<void> {
    const pubPath = resolveProducerPubKeyPath(fortressPath);
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
    await writeFile(pubPath, publicKey);
  }

  it("re-verifies a genuine extension-signed enforcement entry (verified=1)", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const publicKey = await seedGenuineSignedEntry(fortressPath, masterKey);
    await publishProducerKey(fortressPath, publicKey);

    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text().trim());
    expect(report.producer_key_present).toBe(true);
    expect(report.reader_basis).toBe("per_producer_reverified");
    expect(report.enforcement_entries).toBe(1);
    expect(report.verified).toBe(1);
    expect(report.rejected).toBe(0);
    expect(report.channel_authenticated).toBe(0);
  });

  it("REJECTS a forged entry that claims producer_signed but has a bad signature", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const publicKey = await seedGenuineSignedEntry(fortressPath, masterKey);
    await publishProducerKey(fortressPath, publicKey);

    // Forge a SECOND entry directly via AuditLog.append: it carries the correct
    // marker + the producer_signed basis + a plausible canonical body, but the
    // signature is garbage (the forger does not hold the producer private key).
    // This is exactly the in-process marker-forgery the reader must catch.
    const forgedNotification = notificationFor("drop", new Date().toISOString());
    const forgedCanonical = canonicalize({
      timestamp: forgedNotification.recorded_at,
      layer: "l1",
      operation: "egress_blocked",
      identity_id: forgedNotification.agent.id,
      result: "blocked",
      details: { decision: "drop", seq: 1, prior_sha256_hex: null, source: "macos_extension" },
    });
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    await auditLog.append(
      "l1",
      "egress_blocked",
      "agent-1",
      {
        decision: "drop",
        seq: 1,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(new Uint8Array(64)),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: forgedCanonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: Date.parse(forgedNotification.recorded_at),
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      "failure",
    );
    await auditLog.flush();

    // JSON run: the tamper finding lands in the structured report.
    const out = new CaptureStream();
    const jsonCode = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    // Still exit 0 - this is a diagnostic; a tamper finding is REPORTED, not
    // swallowed by a non-zero exit a script might ignore.
    expect(jsonCode).toBe(0);
    const report = JSON.parse(out.text().trim());
    expect(report.verified).toBe(1); // the genuine entry still verifies
    expect(report.rejected).toBe(1); // the forgery is caught
    expect(report.rejected_samples).toHaveLength(1);

    // Human run: the operator-facing warning channel surfaces the forgery.
    const humanOut = new CaptureStream();
    const errStream = new CaptureStream();
    await runAuditVerify(["--fortress", fortressPath], {
      out: humanOut,
      err: errStream,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(errStream.text()).toContain("did NOT count as verified");
  });

  /**
   * Persist a GENUINE producer-signed tuple directly via `AuditLog.append`,
   * letting the caller choose the top-level `operation` the entry is FILED under
   * independently of the operation the signature actually attests to. This is the
   * in-process replay/relabel capability the reader must defend against: the
   * signature re-verifies, but the top-level operation can be chosen freely by an
   * actor holding the AuditLog handle. Returns the published producer public key.
   */
  async function seedSignedTupleUnderOperation(
    fortressPath: string,
    masterKey: Uint8Array,
    privateKey: Uint8Array,
    signedDecision: "allow" | "drop",
    fileUnderOperation: "egress_allowed" | "egress_blocked",
    seq: number,
  ): Promise<void> {
    const notification = notificationFor(signedDecision, new Date().toISOString());
    const producer = signedProducerFor(notification, privateKey, seq);
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    await auditLog.append(
      "l1",
      fileUnderOperation,
      notification.agent.id,
      {
        decision: notification.decision,
        seq,
        prior_sha256_hex: null,
        source: "macos_extension",
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: producer.signature_b64url,
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: producer.key_id,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: producer.event_canonical_json,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: producer.captured_at_unix_ms,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      signedDecision === "allow" ? "success" : "failure",
    );
    await auditLog.flush();
  }

  it("REJECTS a genuine signed tuple RELABELED under a different top-level operation (not verified)", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    // The signature attests to an "allow" (egress_approved -> egress_allowed),
    // but the entry is FILED under egress_blocked to manufacture a fake block.
    // The signature re-verifies, so a reader that only checks the signature would
    // wrongly count this as a verified BLOCK.
    await seedSignedTupleUnderOperation(
      fortressPath,
      masterKey,
      privateKey,
      "allow",
      "egress_blocked",
      7,
    );
    await publishProducerKey(fortressPath, publicKey);

    const out = new CaptureStream();
    const errStream = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      err: errStream,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text().trim());
    // The relabeled tuple must NOT inflate the verified count: it is a rejection.
    expect(report.verified).toBe(0);
    expect(report.rejected).toBe(1);
    expect(report.rejected_samples).toHaveLength(1);
    expect(report.rejected_samples[0].reason).toContain("operation mismatch");

    // Human run names the relabel rejection honestly.
    const humanErr = new CaptureStream();
    await runAuditVerify(["--fortress", fortressPath], {
      out: new CaptureStream(),
      err: humanErr,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(humanErr.text()).toContain("operation mismatch");
  });

  it("does NOT let duplicated genuine entries inflate the verified count", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    // Build ONE genuine signed block tuple (seq 3) and persist THREE identical
    // copies. Each re-verifies identically; without dedup all three would read as
    // distinct verified enforcement events. They must collapse to ONE.
    const notification = notificationFor("drop", new Date().toISOString());
    const producer = signedProducerFor(notification, privateKey, 3);
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    const dupDetails = {
      decision: "drop",
      seq: 3,
      prior_sha256_hex: null,
      source: "macos_extension",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: producer.signature_b64url,
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: producer.key_id,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: producer.event_canonical_json,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: producer.captured_at_unix_ms,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    };
    for (let i = 0; i < 3; i++) {
      await auditLog.append("l1", "egress_blocked", notification.agent.id, { ...dupDetails }, "failure");
    }
    await auditLog.flush();
    await publishProducerKey(fortressPath, publicKey);

    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text().trim());
    expect(report.enforcement_entries).toBe(3);
    // One genuine event -> verified counts ONCE; the two replays are duplicates.
    expect(report.verified).toBe(1);
    expect(report.duplicates).toBe(2);
    expect(report.rejected).toBe(0);
  });

  it("reports the honest channel-authenticated floor when no producer key is published", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    // Seed a channel-unsigned enforcement entry (the macOS pre-Slice-M floor).
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    await auditLog.append(
      "l1",
      "egress_blocked",
      "agent-1",
      { decision: "drop", [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
      "failure",
    );
    await auditLog.flush();
    // NO producer key published.

    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text().trim());
    expect(report.producer_key_present).toBe(false);
    expect(report.reader_basis).toBe("channel_authenticated_only");
    expect(report.verified).toBe(0);
    expect(report.channel_authenticated).toBe(1);
  });

  it("FAILS closed when an expected producer key is present but unreadable (wrong length)", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    await seedGenuineSignedEntry(fortressPath, masterKey);
    // Publish a malformed (non-32-byte) key file. A key is EXPECTED here, so
    // the verb must fail honestly rather than silently dropping to channel.
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
    await writeFile(resolveProducerPubKeyPath(fortressPath), new Uint8Array(16));

    const errStream = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath], {
      err: errStream,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(1);
    expect(errStream.text()).toContain("expected 32");
  });

  it("emits a human summary by default (no --json) and names the no-trust marker", async () => {
    const { fortressPath, masterKey, recoveryKey } = await makeFortress();
    const publicKey = await seedGenuineSignedEntry(fortressPath, masterKey);
    await publishProducerKey(fortressPath, publicKey);

    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath], {
      out,
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    const text = out.text();
    expect(text).toContain("producer_signed_verified : 1");
    expect(text).toContain("Re-verifying");
  });
});
