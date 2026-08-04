// fail-before-exempt: helper-extraction only — the signed-report builders moved to availability-report-helper.ts for reuse by lease-delivery-watchdog.test.ts; no assertion changed, so this file correctly passes against pre-fix source. The new behavior fails-before in lease-delivery-watchdog.test.ts (W1/W4/W6 RED on base).
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";

import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import type {
  EnforcementAvailabilitySnapshot,
  FlowDecisionRecordedNotification,
  ManifestSubscribeRequest,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";
import {
  producerSigningBytes,
  toBase64url,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  EnforcementAvailabilityStore,
  queryMacOSEnforcementAvailability,
} from "../../../src/castle-wall/runtime/enforcement-availability.js";
import { frame } from "../../../src/castle-wall/ipc/framing.js";
import {
  MacOSFlowEventConsumer,
  type AuditSink,
  type MacOSApprovalQueue,
  type MacOSManifestProvider,
  type MacOSSubscriber,
} from "../../../src/castle-wall/runtime/index.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import {
  availabilitySnapshot as greenSnapshot,
  signAvailabilityReport,
} from "./availability-report-helper.js";

const FORTRESS_ID = "fortress-test";
const NOW = 1_780_000_000_000;
const FRESHNESS_MS = 30_000;

const SAMPLE_RULE: AllowlistRule = {
  id: "rule-allow-anthropic",
  schema_version: 1,
  created_at: "2026-07-30T00:00:00.000Z",
  match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
  scope: { template_ids: ["coding-assistant"] },
  disposition: "allow",
};

const SIGNED_MANIFEST: SignedManifest = {
  manifest: {
    schema_version: 1,
    fortress_id: FORTRESS_ID,
    issued_at: "2026-07-30T00:00:00.000Z",
    rules: [{ rule_id: SAMPLE_RULE.id, file: "rules/sample.json", sha256: "a".repeat(64) }],
  },
  signature: {
    signature_scheme: "ed25519-v1",
    signing_key_id: "test-key",
    signature_b64url: "sig",
  },
};

function makeManifestProvider(): MacOSManifestProvider {
  return {
    currentSnapshot() {
      return { signed_manifest: SIGNED_MANIFEST, rules: [SAMPLE_RULE] };
    },
  };
}

function makeApprovalQueue(): MacOSApprovalQueue {
  return {
    async enqueue() {
      // no-op
    },
  };
}

function makeNoopSink(): AuditSink {
  return {
    async append() {
      // no-op
    },
    async flush() {
      // no-op
    },
  };
}

function makeSubscriber(subscriberId: string): MacOSSubscriber {
  return {
    subscriberId,
    async emitManifestUpdate() {
      // no-op
    },
  };
}

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

function signedFlowWithAvailability(input: {
  report: EnforcementAvailabilitySnapshot;
  privateKey: Uint8Array;
  seq: number;
  capturedAtUnixMs: number;
}): FlowDecisionRecordedNotification {
  const notification: FlowDecisionRecordedNotification = {
    type: "flow_decision_recorded",
    decision: "drop",
    destination: {
      host: "api.anthropic.com",
      ip: "104.18.32.10",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      opaque: false,
    },
    agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
    matched_rule_id: "missing-lease",
    recorded_at: new Date(input.capturedAtUnixMs).toISOString(),
    enforcement: input.report,
  };
  const details: Record<string, unknown> = {
    agent_id: notification.agent.id,
    agent_template: notification.agent.template,
    dest_host: notification.destination.host,
    dest_ip: notification.destination.ip,
    dest_port: notification.destination.port,
    dest_protocol: notification.destination.protocol,
    decision: notification.decision,
    prior_sha256_hex: null,
    rule_id: notification.matched_rule_id ?? null,
    seq: input.seq,
    source: "macos_extension",
    enforcement: input.report,
  };
  const eventCanonicalJson = canonicalize({
    timestamp: notification.recorded_at,
    layer: "l1",
    operation: "egress_blocked",
    identity_id: notification.agent.id,
    result: "blocked",
    details,
  });
  const signature = ed25519.sign(
    producerSigningBytes(eventCanonicalJson, input.capturedAtUnixMs, input.seq),
    input.privateKey,
  );
  return {
    ...notification,
    producer: {
      event_canonical_json: eventCanonicalJson,
      captured_at_unix_ms: input.capturedAtUnixMs,
      seq: input.seq,
      prior_sha256_hex: null,
      signature_b64url: toBase64url(signature),
      key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
  };
}

function makeConsumer(input: {
  publicKeyB64url: string;
  now?: () => number;
  sink?: AuditSink;
}): MacOSFlowEventConsumer {
  const consumer = new MacOSFlowEventConsumer({
    manifestProvider: makeManifestProvider(),
    approvalQueue: makeApprovalQueue(),
    auditSink: input.sink ?? makeNoopSink(),
    defaultApprovalTimeoutSeconds: 30,
    pinnedProducerKeyB64url: input.publicKeyB64url,
    fortressId: FORTRESS_ID,
    now: input.now ?? (() => NOW),
  });
  consumer.registerSubscriber(makeSubscriber("ext-1"));
  return consumer;
}

describe("level-triggered enforcement availability store", () => {
  it("I1/I4/I6: absence is undetermined, live needs a fresh consumer-observed positive assertion", () => {
    const store = new EnforcementAvailabilityStore({
      freshnessWindowMs: FRESHNESS_MS,
    });
    expect(store.resolve(NOW).status).toBe("undetermined");

    store.registerConnection("ext-1");
    const noReport = store.resolve(NOW);
    expect(noReport.status).toBe("undetermined");
    expect(noReport.reason).toBe("no_report");

    store.recordValidReport(
      "ext-1",
      greenSnapshot({ producer_claimed_at: "1999-01-01T00:00:00.000Z" }),
      NOW,
    );
    const live = store.resolve(NOW + 10_000);
    expect(live.status).toBe("live");
    expect(live.observed_at).toBe(new Date(NOW).toISOString());

    const stale = store.resolve(NOW + FRESHNESS_MS + 1);
    expect(stale.status).toBe("undetermined");
    expect(stale.reason).toBe("stale_report");
  });

  it("invalid reports cannot create live state or preserve already-stale verified state", () => {
    let now = NOW;
    const store = new EnforcementAvailabilityStore({
      freshnessWindowMs: FRESHNESS_MS,
      now: () => now,
    });

    store.recordInvalidReport("ext-1", "producer_sequence_replay");
    const invalidOnly = store.resolve();
    expect(invalidOnly.status).toBe("undetermined");
    expect(invalidOnly.reason).toBe("producer_sequence_replay");
    expect(invalidOnly.observed_at).toBeNull();

    store.recordValidReport("ext-1", greenSnapshot(), NOW);
    now = NOW + FRESHNESS_MS + 1;
    const staleBeforeInvalid = store.resolve();
    expect(staleBeforeInvalid.status).toBe("undetermined");
    expect(staleBeforeInvalid.reason).toBe("stale_report");

    store.recordInvalidReport("ext-1", "producer_sequence_replay");
    const staleAfterInvalid = store.resolve();
    expect(staleAfterInvalid.status).toBe("undetermined");
    expect(staleAfterInvalid.reason).toBe("producer_sequence_replay");
    expect(staleAfterInvalid.observed_at).toBeNull();
  });

  it("I8/I11: every non-live lease algebra and provider_bound=false is non-green", () => {
    const cases: Array<[string, Partial<EnforcementAvailabilitySnapshot>]> = [
      ["missing lease", { lease_state: "missing", lease_reason: "arm_lease_missing" }],
      ["unarmed lease", { lease_state: "unarmed", lease_reason: "not_armed" }],
      ["revoked lease", { lease_state: "failed_open", lease_reason: "lease_revoked" }],
      ["ttl expired", { lease_state: "failed_open", lease_reason: "ttl_expired" }],
      ["heartbeat stopped", { lease_state: "failed_open", lease_reason: "heartbeat_stopped" }],
      ["manifest absent", { manifest_state: "absent", manifest_signature_b64url: null }],
      ["provider unbound", { provider_bound: false }],
    ];
    for (const [name, overrides] of cases) {
      const store = new EnforcementAvailabilityStore({
        freshnessWindowMs: FRESHNESS_MS,
      });
      store.registerConnection("ext-1");
      store.recordValidReport("ext-1", greenSnapshot(overrides), NOW);
      const resolved = store.resolve(NOW);
      expect(resolved.status, name).toBe("non_green");
      expect(resolved.reason, name).not.toBe("ok");
    }
  });

  it("I3/acceptance-8.1: continuous fail-closed reports past the old ten-minute window never clear to green", () => {
    const store = new EnforcementAvailabilityStore({
      freshnessWindowMs: FRESHNESS_MS,
    });
    store.registerConnection("ext-1");
    for (let minute = 0; minute <= 12; minute += 1) {
      const observedAt = NOW + minute * 60_000;
      store.recordValidReport(
        "ext-1",
        greenSnapshot({
          lease_state: "missing",
          lease_reason: "arm_lease_missing",
        }),
        observedAt,
      );
      const resolved = store.resolve(observedAt);
      expect(resolved.status, `minute ${minute}`).toBe("non_green");
      expect(resolved.reason, `minute ${minute}`).toBe("lease:arm_lease_missing");
    }
  });

  it("I12: least-green-of-fresh wins across live connections and disconnect removes that connection", () => {
    const store = new EnforcementAvailabilityStore({
      freshnessWindowMs: FRESHNESS_MS,
    });
    store.registerConnection("green-ext");
    store.registerConnection("unarmed-ext");
    store.recordValidReport("green-ext", greenSnapshot(), NOW);
    store.recordValidReport(
      "unarmed-ext",
      greenSnapshot({ lease_state: "unarmed", lease_reason: "not_armed" }),
      NOW,
    );

    expect(store.resolve(NOW).status).toBe("non_green");
    expect(store.resolve(NOW).reason).toBe("lease:not_armed");

    store.unregisterConnection("unarmed-ext");
    expect(store.resolve(NOW).status).toBe("live");
  });

  it("I6: malformed castle.sock availability answers are rejected as undetermined input", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-availability-"));
    const socketPath = join(dir, "castle.sock");
    const server = createServer((socket) => {
      socket.once("data", () => {
        socket.write(
          frame(
            JSON.stringify({
              jsonrpc: "2.0",
              params: {
                type: "enforcement_availability_response",
                request_id: "req-malformed",
                availability: {
                  status: "live",
                  reason: "ok",
                  observed_at: new Date(NOW).toISOString(),
                  freshness_window_ms: 30_000,
                  active_connection_count: "one",
                },
              },
            }),
          ),
        );
      });
    });
    // port-discipline: ignore - Unix domain socket path, not a TCP port.
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      await expect(
        queryMacOSEnforcementAvailability(socketPath, {
          timeoutMs: 100,
          generateRequestId: () => "req-malformed",
        }),
      ).rejects.toThrow(/malformed enforcement availability response/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("macOS extension-origin enforcement availability reports", () => {
  it("I2/I10: unsigned, wrong-key, and signed-body-mismatched green reports do not move the surface green", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const wrongPrivateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const consumer = makeConsumer({ publicKeyB64url });

    await consumer.handleEnforcementAvailabilityReport(
      {
        type: "enforcement_availability_report",
        enforcement: greenSnapshot(),
        producer: null,
      },
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("undetermined");

    await consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: greenSnapshot(),
        privateKey: wrongPrivateKey,
        seq: 1,
      }),
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("undetermined");

    await consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: greenSnapshot(),
        signedReport: greenSnapshot({ provider_bound: false }),
        privateKey,
        seq: 2,
      }),
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("undetermined");
  });

  it("I4: producer_claimed_at is diagnostic only; consumer observed_at is the freshness clock", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });

    await consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: greenSnapshot({
          producer_claimed_at: "2099-01-01T00:00:00.000Z",
        }),
        privateKey,
      }),
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("live");
    expect(consumer.resolveEnforcementAvailability().observed_at).toBe(
      new Date(NOW).toISOString(),
    );

    now = NOW + FRESHNESS_MS + 1;
    const stale = consumer.resolveEnforcementAvailability();
    expect(stale.status).toBe("undetermined");
    expect(stale.reason).toBe("stale_report");
  });

  it("§4.1/§8.1: flow-decision carriage preserves non-green for a lease-less continuous stream past ten minutes", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    let now = NOW;
    const consumer = makeConsumer({
      publicKeyB64url,
      now: () => now,
      sink: log as unknown as AuditSink,
    });

    for (let minute = 0; minute <= 12; minute += 1) {
      now = NOW + minute * 60_000;
      await consumer.handleFlowDecisionRecorded(
        signedFlowWithAvailability({
          report: greenSnapshot({
            lease_state: "missing",
            lease_reason: "arm_lease_missing",
          }),
          privateKey,
          seq: minute,
          capturedAtUnixMs: now,
        }),
        "ext-1",
      );
      const resolved = consumer.resolveEnforcementAvailability();
      expect(resolved.status, `minute ${minute}`).toBe("non_green");
      expect(resolved.reason, `minute ${minute}`).toBe("lease:arm_lease_missing");
    }
  });

  it("§4.1: flow-decision carriage can green only when the signed body contains the same live enforcement block", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    const consumer = makeConsumer({
      publicKeyB64url,
      sink: log as unknown as AuditSink,
    });

    await consumer.handleFlowDecisionRecorded(
      signedFlowWithAvailability({
        report: greenSnapshot(),
        privateKey,
        seq: 0,
        capturedAtUnixMs: NOW,
      }),
      "ext-1",
    );

    expect(consumer.resolveEnforcementAvailability().status).toBe("live");
  });

  it("F-AVAIL-SEQ-FLAP repro: a dedicated report signed earlier but delivered after a flow-carried report on the same producer counter is accepted, not misread as replay", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    const consumer = makeConsumer({
      publicKeyB64url,
      sink: log as unknown as AuditSink,
    });

    // Flow-carried availability signed at producer seq 5 arrives first.
    await consumer.handleFlowDecisionRecorded(
      signedFlowWithAvailability({
        report: greenSnapshot(),
        privateKey,
        seq: 5,
        capturedAtUnixMs: NOW,
      }),
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("live");

    // Dedicated availability report signed EARLIER (seq 3) on the same
    // producer counter, delivered later via the async dedicated path. This is
    // out-of-order delivery from one signing counter across two paths, not a
    // replay: seq 3 has never been seen on the dedicated stream.
    await consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: greenSnapshot(),
        privateKey,
        seq: 3,
      }),
      "ext-1",
    );

    const resolved = consumer.resolveEnforcementAvailability();
    expect(resolved.reason).toBe("ok");
    expect(resolved.status).toBe("live");
    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(2);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(0);
  });

  it("rejected same-stream replay preserves the previous verified fresh availability report", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });

    const report = signAvailabilityReport({
      visibleReport: greenSnapshot(),
      privateKey,
      seq: 3,
    });
    await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
    const firstResolved = consumer.resolveEnforcementAvailability();
    expect(firstResolved.status).toBe("live");
    expect(firstResolved.observed_at).toBe(new Date(NOW).toISOString());

    now = NOW + 10_000;
    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      expect(replayError).not.toHaveBeenCalled();
    } finally {
      replayError.mockRestore();
    }

    const replayResolved = consumer.resolveEnforcementAvailability();
    expect(replayResolved.status).toBe("live");
    expect(replayResolved.reason).toBe("ok");
    expect(replayResolved.observed_at).toBe(new Date(NOW).toISOString());
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(1);
  });

  it("F-AVAIL-REJECT-CLOBBER: duplicate redelivery is rolled up while same-stream reorder remains individually visible", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });

    const report = signAvailabilityReport({
      visibleReport: greenSnapshot(),
      privateKey,
      seq: 3,
    });
    await consumer.handleEnforcementAvailabilityReport(report, "ext-1");

    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      for (let i = 0; i < 99; i += 1) {
        now += 1;
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      }
      expect(replayError).not.toHaveBeenCalled();

      now += 1;
      await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      expect(replayError).toHaveBeenCalledTimes(1);
      expect(replayError).toHaveBeenNthCalledWith(
        1,
        "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=100 distinct_seqs=1 seq_range=[3,3] floor_range=[3,3] window_ms=99",
      );

      now += 1;
      await consumer.handleEnforcementAvailabilityReport(
        signAvailabilityReport({
          visibleReport: greenSnapshot(),
          privateKey,
          seq: 2,
        }),
        "ext-1",
      );
      expect(replayError).toHaveBeenCalledTimes(2);
      expect(replayError).toHaveBeenNthCalledWith(
        2,
        "[castle-wall] enforcement availability replay reorder rejected stream=dedicated_report rejected_seq=2 floor=3 delta=1",
      );
    } finally {
      replayError.mockRestore();
    }

    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(1);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(101);
  });

  it("F-AVAIL-DUP-WINDOW: distinct-seq duplicate flood is bounded to count-window summaries", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });
    let duplicateLines: string[] = [];

    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      for (let seq = 1; seq <= 300; seq += 1) {
        now = NOW + seq;
        const report = signAvailabilityReport({
          visibleReport: greenSnapshot(),
          privateKey,
          seq,
        });
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      }
      duplicateLines = replayError.mock.calls
        .map(([line]) => String(line))
        .filter((line) => line.includes("duplicate replays suppressed"));
    } finally {
      replayError.mockRestore();
    }

    expect(duplicateLines).toHaveLength(3);
    expect(duplicateLines[0]).toBe(
      "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=100 distinct_seqs=100 seq_range=[1,100] floor_range=[1,100] window_ms=99",
    );
    expect(duplicateLines[1]).toBe(
      "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=100 distinct_seqs=100 seq_range=[101,200] floor_range=[101,200] window_ms=99",
    );
    expect(duplicateLines[2]).toBe(
      "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=100 distinct_seqs=100 seq_range=[201,300] floor_range=[201,300] window_ms=99",
    );
    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(300);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(300);
  });

  it("F-AVAIL-DUP-WINDOW: interval expiry flushes the prior under-threshold distinct-seq window", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });
    let duplicateLines: string[] = [];

    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      for (let seq = 1; seq <= 5; seq += 1) {
        now = NOW + seq;
        const report = signAvailabilityReport({
          visibleReport: greenSnapshot(),
          privateKey,
          seq,
        });
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      }
      expect(replayError).not.toHaveBeenCalled();

      now = NOW + 60_011;
      const nextReport = signAvailabilityReport({
        visibleReport: greenSnapshot(),
        privateKey,
        seq: 6,
      });
      await consumer.handleEnforcementAvailabilityReport(nextReport, "ext-1");
      await consumer.handleEnforcementAvailabilityReport(nextReport, "ext-1");
      duplicateLines = replayError.mock.calls
        .map(([line]) => String(line))
        .filter((line) => line.includes("duplicate replays suppressed"));
    } finally {
      replayError.mockRestore();
    }

    expect(duplicateLines).toEqual([
      "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=5 distinct_seqs=5 seq_range=[1,5] floor_range=[1,5] window_ms=4",
    ]);
  });

  it("F-AVAIL-DUP-WINDOW: duplicate summary reports the floor range when floors vary", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });
    let duplicateLines: string[] = [];

    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      for (let seq = 10; seq <= 11; seq += 1) {
        now = NOW + seq;
        const report = signAvailabilityReport({
          visibleReport: greenSnapshot(),
          privateKey,
          seq,
        });
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
        await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
      }

      now = NOW + 60_011;
      const nextReport = signAvailabilityReport({
        visibleReport: greenSnapshot(),
        privateKey,
        seq: 12,
      });
      await consumer.handleEnforcementAvailabilityReport(nextReport, "ext-1");
      await consumer.handleEnforcementAvailabilityReport(nextReport, "ext-1");
      duplicateLines = replayError.mock.calls
        .map(([line]) => String(line))
        .filter((line) => line.includes("duplicate replays suppressed"));
    } finally {
      replayError.mockRestore();
    }

    expect(duplicateLines).toEqual([
      "[castle-wall] enforcement availability duplicate replays suppressed stream=dedicated_report count=2 distinct_seqs=2 seq_range=[10,11] floor_range=[10,11] window_ms=1",
    ]);
  });

  it("F-AVAIL-SEQ-FLAP negative: the SAME dedicated report delivered twice is rejected without refreshing live state", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });

    const report = signAvailabilityReport({
      visibleReport: greenSnapshot(),
      privateKey,
      seq: 3,
    });
    await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
    expect(consumer.resolveEnforcementAvailability().status).toBe("live");

    now = NOW + 10_000;
    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await consumer.handleEnforcementAvailabilityReport(report, "ext-1");
    } finally {
      replayError.mockRestore();
    }
    const resolved = consumer.resolveEnforcementAvailability();
    expect(resolved.status).toBe("live");
    expect(resolved.reason).toBe("ok");
    expect(resolved.observed_at).toBe(new Date(NOW).toISOString());
    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(1);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(1);
  });

  it("F-AVAIL-SEQ-FLAP negative: the SAME flow-carried availability delivered twice is rejected without refreshing live state", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    let now = NOW;
    const consumer = makeConsumer({
      publicKeyB64url,
      now: () => now,
      sink: log as unknown as AuditSink,
    });

    const flow = signedFlowWithAvailability({
      report: greenSnapshot(),
      privateKey,
      seq: 5,
      capturedAtUnixMs: NOW,
    });
    await consumer.handleFlowDecisionRecorded(flow, "ext-1");
    expect(consumer.resolveEnforcementAvailability().status).toBe("live");

    now = NOW + 10_000;
    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await consumer.handleFlowDecisionRecorded(flow, "ext-1");
    } finally {
      replayError.mockRestore();
    }
    const resolved = consumer.resolveEnforcementAvailability();
    expect(resolved.status).toBe("live");
    expect(resolved.reason).toBe("ok");
    expect(resolved.observed_at).toBe(new Date(NOW).toISOString());
    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(1);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(1);
  });

  it("F-AVAIL-SEQ-FLAP negative: within the dedicated stream, a lower-seq report after a higher-seq report is still rejected (per-stream monotonicity holds)", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    let now = NOW;
    const consumer = makeConsumer({ publicKeyB64url, now: () => now });

    await consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: greenSnapshot(),
        privateKey,
        seq: 4,
      }),
      "ext-1",
    );
    expect(consumer.resolveEnforcementAvailability().status).toBe("live");

    // A distinct, validly-signed dedicated report at a LOWER seq. Hardware
    // has shown rare same-stream reordering, and stale reports must not
    // overwrite fresher verified state.
    now = NOW + 10_000;
    const replayError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await consumer.handleEnforcementAvailabilityReport(
        signAvailabilityReport({
          visibleReport: greenSnapshot(),
          privateKey,
          seq: 2,
        }),
        "ext-1",
      );
      expect(replayError).toHaveBeenCalledWith(
        "[castle-wall] enforcement availability replay reorder rejected stream=dedicated_report rejected_seq=2 floor=4 delta=2",
      );
    } finally {
      replayError.mockRestore();
    }
    const resolved = consumer.resolveEnforcementAvailability();
    expect(resolved.status).toBe("live");
    expect(resolved.reason).toBe("ok");
    expect(resolved.observed_at).toBe(new Date(NOW).toISOString());
    expect(consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(1);
    expect(consumer.getStats().enforcementAvailabilityReportsRejected).toBe(1);
  });

  it("I7: a subscribed older extension with no v3 report remains undetermined", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const consumer = makeConsumer({ publicKeyB64url });
    const request: ManifestSubscribeRequest = {
      type: "manifest_subscribe",
      request_id: "subscribe-old-extension",
    };

    await consumer.handleManifestSubscribe(request, "ext-1");

    const resolved = consumer.resolveEnforcementAvailability();
    expect(resolved.status).toBe("undetermined");
    expect(resolved.reason).toBe("no_report");
  });
});
