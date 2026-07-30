/**
 * Castle Wall macOS IPC listener tests.
 *
 * Drives the UDS listener against a real `net.createConnection` client
 * that speaks the same JSON-RPC over LSP-framed wire format. No mocks at
 * the socket boundary; the listener binds a temp UDS path, accepts the
 * connection, sends its handshake_challenge, and the test asserts:
 *
 *   - Bind / unbind cleans up the socket file.
 *   - Every new connection receives a `handshake_challenge` frame.
 *   - `manifest_subscribe` from the extension produces an immediate
 *     `manifest_updated` emit back to that connection.
 *   - `flow_decision_recorded` dispatches into the consumer's audit
 *     sink (one entry per inbound).
 *   - `flow_pending_approval` dispatches into the consumer's approval
 *     queue (one enqueue per inbound).
 *   - Re-bind on an existing socket path succeeds by unlinking the
 *     stale file (operator workflow: stop and restart the runtime).
 *   - Broadcast fans the current snapshot to every active connection.
 *   - Stats counters move under successful + malformed traffic.
 *   - Malformed frames (bad JSON, wrong jsonrpc, wrong namespace) are
 *     counted as rejected but do not crash the connection.
 *   - Subscriber unregister on socket close prevents leaks.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createConnection, type Socket } from "node:net";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type {
  CastleWallMessage,
  EnforcementAvailabilityReportNotification,
  EnforcementAvailabilitySnapshot,
  FlowDecisionRecordedNotification,
  FlowPendingApprovalNotification,
  ManifestSubscribeRequest,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  MacOSFlowEventConsumer,
  MacOSFlowIpcListener,
  type AuditSink,
  type MacOSApprovalQueue,
  type MacOSManifestProvider,
} from "../../../src/castle-wall/runtime/index.js";
import {
  producerSigningBytes,
  toBase64url,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";
import {
  ENFORCEMENT_AVAILABILITY_REPORT_OPERATION,
} from "../../../src/castle-wall/runtime/enforcement-availability.js";
import { protectionSubjectForUid } from "../../../src/castle-wall/subject-binding.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";

const FORTRESS_ID = "fortress-test";

const SAMPLE_RULE: AllowlistRule = {
  id: "rule-allow-anthropic",
  schema_version: 1,
  created_at: "2026-05-12T00:00:00Z",
  match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
  scope: { template_ids: ["coding-assistant"] },
  disposition: "allow",
};

interface AuditEntry {
  layer: "l1";
  operation: string;
  identityId: string;
  details?: Record<string, unknown>;
}

function makeAuditSink(): { sink: AuditSink; entries: AuditEntry[] } {
  const entries: AuditEntry[] = [];
  const sink: AuditSink = {
    append(layer, operation, identityId, details) {
      entries.push({ layer, operation, identityId, details });
    },
    async flush() {
      // no-op
    },
  };
  return { sink, entries };
}

function makeApprovalQueue(): {
  queue: MacOSApprovalQueue;
  enqueued: Array<{ requestId: string; agentId: string; destinationHost: string | null }>;
} {
  const enqueued: Array<{ requestId: string; agentId: string; destinationHost: string | null }> = [];
  const queue: MacOSApprovalQueue = {
    async enqueue(input) {
      enqueued.push({
        requestId: input.requestId,
        agentId: input.agent.id,
        destinationHost: input.destination.host ?? null,
      });
    },
  };
  return { queue, enqueued };
}

function subjectForUid(uid: number): string {
  const subject = protectionSubjectForUid(FORTRESS_ID, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
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

const AGENT_TEST_TOKEN = auditTokenForRuid(503);
const AGENT_TEST_SUBJECT = subjectForUid(503);
const AGENT_PENDING_TOKEN = auditTokenForRuid(504);
const AGENT_COUNTER_TOKEN = auditTokenForRuid(505);

function makeManifestProvider(rules: AllowlistRule[]): MacOSManifestProvider {
  return {
    currentSnapshot() {
      return {
        signed_manifest: makeSignedManifest(rules, "sig-test"),
        rules,
      };
    },
  };
}

function makeSignedManifest(rules: AllowlistRule[], signature: string): SignedManifest {
  return {
    manifest: {
      schema_version: 1,
      fortress_id: FORTRESS_ID,
      issued_at: "2026-05-14T00:00:00Z",
      rules: rules.map((rule) => ({
        rule_id: rule.id,
        file: `${rule.id}.json`,
        sha256: "0".repeat(64),
      })),
    },
    signature: {
      signature_scheme: "ed25519-v1",
      signing_key_id: "test-key",
      signature_b64url: signature,
    },
  };
}

function envelope(message: CastleWallMessage): Uint8Array {
  return frame(
    JSON.stringify({
      jsonrpc: "2.0",
      method: `castle-wall.${message.type}`,
      params: message,
    }),
  );
}

function availabilitySnapshot(
  overrides: Partial<EnforcementAvailabilitySnapshot> = {},
): EnforcementAvailabilitySnapshot {
  return {
    protocol_version: 1,
    source: "macos_extension",
    lease_state: "live",
    lease_reason: "ok",
    manifest_state: "applied",
    manifest_signature_b64url: "manifest-sig",
    provider_bound: true,
    producer_claimed_at: "1970-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function availabilityIsGreen(snapshot: EnforcementAvailabilitySnapshot): boolean {
  return (
    snapshot.protocol_version === 1 &&
    snapshot.source === "macos_extension" &&
    snapshot.lease_state === "live" &&
    snapshot.lease_reason === "ok" &&
    snapshot.manifest_state === "applied" &&
    typeof snapshot.manifest_signature_b64url === "string" &&
    snapshot.provider_bound === true
  );
}

function signAvailabilityReport(input: {
  visibleReport: EnforcementAvailabilitySnapshot;
  privateKey: Uint8Array;
  seq?: number;
  capturedAtUnixMs?: number;
}): EnforcementAvailabilityReportNotification {
  const seq = input.seq ?? 0;
  const capturedAtUnixMs = input.capturedAtUnixMs ?? 1_780_000_000_000;
  const eventCanonicalJson = canonicalize({
    timestamp:
      input.visibleReport.producer_claimed_at ??
      new Date(capturedAtUnixMs).toISOString(),
    layer: "l1",
    operation: ENFORCEMENT_AVAILABILITY_REPORT_OPERATION,
    identity_id: FORTRESS_ID,
    result: availabilityIsGreen(input.visibleReport) ? "success" : "failure",
    details: {
      seq,
      prior_sha256_hex: null,
      enforcement: input.visibleReport,
    },
  });
  const signature = ed25519.sign(
    producerSigningBytes(eventCanonicalJson, capturedAtUnixMs, seq),
    input.privateKey,
  );
  return {
    type: "enforcement_availability_report",
    enforcement: input.visibleReport,
    producer: {
      event_canonical_json: eventCanonicalJson,
      captured_at_unix_ms: capturedAtUnixMs,
      seq,
      prior_sha256_hex: null,
      signature_b64url: toBase64url(signature),
      key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
  };
}

/**
 * Persistent buffer attached to a client socket. The single permanent
 * data listener accumulates inbound bytes into `bytes` regardless of
 * whether anyone is currently waiting on `nextMessage`. Detaching the
 * data listener between awaits would put the socket into paused mode
 * and risk dropping in-kernel buffered data, so the test fixture
 * keeps one listener for the lifetime of the connection.
 */
interface ClientBuffer {
  bytes: Uint8Array;
  /** Resolver queued by `nextMessage` waiting for the next frame. */
  pending: ((m: CastleWallMessage) => void) | null;
  /** Rejecter paired with `pending`. */
  pendingReject: ((err: Error) => void) | null;
}

function attachPersistentBuffer(socket: Socket): ClientBuffer {
  const buf: ClientBuffer = {
    bytes: new Uint8Array(0),
    pending: null,
    pendingReject: null,
  };
  const flush = (): void => {
    if (!buf.pending) return;
    const step = parseFrame(buf.bytes);
    if (step.kind === "need_more") return;
    if (step.kind === "error") {
      const reject = buf.pendingReject!;
      buf.pending = null;
      buf.pendingReject = null;
      reject(new Error(`framing error: ${step.reason}`));
      return;
    }
    buf.bytes = buf.bytes.slice(step.consumedBytes);
    const resolve = buf.pending;
    buf.pending = null;
    buf.pendingReject = null;
    try {
      const env = JSON.parse(step.body) as { params: CastleWallMessage };
      resolve(env.params);
    } catch (e) {
      buf.pendingReject?.(e as Error);
    }
  };
  socket.on("data", (chunk: Buffer) => {
    const merged = new Uint8Array(buf.bytes.length + chunk.length);
    merged.set(buf.bytes, 0);
    merged.set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length), buf.bytes.length);
    buf.bytes = merged;
    flush();
  });
  socket.on("error", (err: Error) => {
    if (buf.pendingReject) {
      const reject = buf.pendingReject;
      buf.pending = null;
      buf.pendingReject = null;
      reject(err);
    }
  });
  return buf;
}

/** Wait for the next decoded inbound message on the client socket. */
async function nextMessage(buf: ClientBuffer): Promise<CastleWallMessage> {
  return await new Promise((resolve, reject) => {
    // Attempt synchronous parse off any buffered bytes first so callers
    // that did not race the data event still see the next frame.
    const step = parseFrame(buf.bytes);
    if (step.kind === "complete") {
      buf.bytes = buf.bytes.slice(step.consumedBytes);
      try {
        const env = JSON.parse(step.body) as { params: CastleWallMessage };
        resolve(env.params);
        return;
      } catch (e) {
        reject(e as Error);
        return;
      }
    }
    if (step.kind === "error") {
      reject(new Error(`framing error: ${step.reason}`));
      return;
    }
    if (buf.pending) {
      reject(new Error("only one nextMessage call may be pending at a time per buffer"));
      return;
    }
    buf.pending = resolve;
    buf.pendingReject = reject;
  });
}

interface Harness {
  socketPath: string;
  consumer: MacOSFlowEventConsumer;
  listener: MacOSFlowIpcListener;
  audit: { sink: AuditSink; entries: AuditEntry[] };
  approvals: ReturnType<typeof makeApprovalQueue>;
}

async function newHarness(
  rules: AllowlistRule[] = [SAMPLE_RULE],
  opts: { pinnedProducerKeyB64url?: string | null } = {},
): Promise<Harness> {
  const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
  const socketPath = join(dir, "castle.sock");
  const audit = makeAuditSink();
  const approvals = makeApprovalQueue();
  const consumer = new MacOSFlowEventConsumer({
    manifestProvider: makeManifestProvider(rules),
    approvalQueue: approvals.queue,
    auditSink: audit.sink,
    defaultApprovalTimeoutSeconds: 30,
    pinnedProducerKeyB64url: opts.pinnedProducerKeyB64url ?? null,
    fortressId: FORTRESS_ID,
  });
  const listener = new MacOSFlowIpcListener({
    socketPath,
    consumer,
    generateNonce: () => new Uint8Array(32),
  });
  await listener.start();
  return { socketPath, consumer, listener, audit, approvals };
}

async function connectClient(socketPath: string): Promise<{ socket: Socket; buf: ClientBuffer }> {
  const socket = createConnection(socketPath);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  const buf = attachPersistentBuffer(socket);
  return { socket, buf };
}

async function tick(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

async function availabilityRequest(
  socket: Socket,
  buf: ClientBuffer,
  requestId: string,
): Promise<CastleWallMessage> {
  socket.write(
    envelope({
      type: "enforcement_availability_request",
      request_id: requestId,
    }),
  );
  for (;;) {
    const msg = await nextMessage(buf);
    if (msg.type !== "handshake_challenge" && msg.type !== "handshake_response") {
      return msg;
    }
  }
}

describe("MacOSFlowIpcListener", () => {
  const tmpDirs: string[] = [];
  const liveListeners: MacOSFlowIpcListener[] = [];
  const liveSockets: Socket[] = [];

  afterEach(async () => {
    for (const s of liveSockets) {
      s.destroy();
    }
    liveSockets.length = 0;
    for (const l of liveListeners) {
      await l.stop().catch(() => undefined);
    }
    liveListeners.length = 0;
    for (const dir of tmpDirs) {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
    tmpDirs.length = 0;
  });

  function registerHarness(h: Harness): void {
    liveListeners.push(h.listener);
    tmpDirs.push(h.socketPath.replace(/\/castle\.sock$/, ""));
  }

  function track(socket: Socket): void {
    liveSockets.push(socket);
  }

  it("binds the UDS path and creates the socket file", async () => {
    const h = await newHarness();
    registerHarness(h);
    const info = await stat(h.socketPath);
    expect(info.isSocket()).toBe(true);
    expect(h.listener.getStats().isListening).toBe(true);
  });

  it("re-owns the socket to socketOwnerUid while keeping mode 0o600 (#450 item 3)", async () => {
    // The safe-mode boot daemon runs as root and would bind a root-owned
    // socket the operator CLI dead-man lever cannot reach. socketOwnerUid
    // re-owns it to the operator. We can only chown to a uid we are allowed to
    // (self, unless root), so assert the round-trip against the current uid.
    const selfUid = process.getuid?.();
    if (selfUid === undefined) return; // non-POSIX; nothing to assert
    const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
    tmpDirs.push(dir);
    const socketPath = join(dir, "castle.sock");
    const audit = makeAuditSink();
    const approvals = makeApprovalQueue();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE]),
      approvalQueue: approvals.queue,
      auditSink: audit.sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    const listener = new MacOSFlowIpcListener({
      socketPath,
      consumer,
      socketOwnerUid: selfUid,
    });
    liveListeners.push(listener);
    await listener.start();
    const info = await stat(socketPath);
    expect(info.uid).toBe(selfUid);
    // chown preserves the 0o600 set by the prior chmod (no widening).
    expect(info.mode & 0o777).toBe(0o600);
  });

  it("does not abort startup when the operator chown cannot apply (best-effort lever)", async () => {
    // A chown to a uid we cannot grant (an arbitrary other uid, as non-root)
    // fails — but the daemon must still come up enforcing; the GUI toggle is the
    // backstop. Skip if running as root (where the chown would actually succeed).
    const selfUid = process.getuid?.();
    if (selfUid === undefined || selfUid === 0) return;
    const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
    tmpDirs.push(dir);
    const socketPath = join(dir, "castle.sock");
    const audit = makeAuditSink();
    const approvals = makeApprovalQueue();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE]),
      approvalQueue: approvals.queue,
      auditSink: audit.sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    const listener = new MacOSFlowIpcListener({
      socketPath,
      consumer,
      socketOwnerUid: 1, // not grantable as a normal user
    });
    liveListeners.push(listener);
    // start() resolves (does not throw) and the socket is listening.
    await listener.start();
    expect(listener.getStats().isListening).toBe(true);
    const info = await stat(socketPath);
    expect(info.isSocket()).toBe(true);
  });

  it("sends a handshake_challenge to every new connection", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    const challenge = await nextMessage(buf);
    expect(challenge.type).toBe("handshake_challenge");
    expect((challenge as { type: string; nonce_b64url: string }).nonce_b64url).toBeTypeOf("string");
    expect(h.listener.getStats().handshakesSent).toBe(1);
    expect(h.listener.getStats().activeConnections).toBe(1);
  });

  it("enforcement_availability_request does not register the admin query socket as an extension", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const h = await newHarness([SAMPLE_RULE], {
      pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(privateKey)),
    });
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    expect((await nextMessage(buf)).type).toBe("handshake_challenge");

    const response = await availabilityRequest(socket, buf, "avail-req-1");

    expect(response.type).toBe("enforcement_availability_response");
    if (response.type !== "enforcement_availability_response") {
      throw new Error("expected enforcement_availability_response");
    }
    expect(response.availability.status).toBe("undetermined");
    expect(response.availability.reason).toBe("no_extension_connection");
    expect(h.consumer.getStats().subscribers).toBe(0);
  });

  it("rejects an unsigned forged green availability report over castle.sock", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const h = await newHarness([SAMPLE_RULE], {
      pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(privateKey)),
    });
    registerHarness(h);
    const ext = await connectClient(h.socketPath);
    const admin = await connectClient(h.socketPath);
    track(ext.socket);
    track(admin.socket);
    expect((await nextMessage(ext.buf)).type).toBe("handshake_challenge");
    expect((await nextMessage(admin.buf)).type).toBe("handshake_challenge");

    ext.socket.write(
      envelope({
        type: "enforcement_availability_report",
        enforcement: availabilitySnapshot(),
        producer: null,
      }),
    );
    await tick();

    const response = await availabilityRequest(admin.socket, admin.buf, "avail-req-2");
    expect(response.type).toBe("enforcement_availability_response");
    if (response.type !== "enforcement_availability_response") {
      throw new Error("expected enforcement_availability_response");
    }
    expect(response.availability.status).toBe("undetermined");
    expect(response.availability.reason).toBe("producer_signature_missing");
  });

  it("folds least-green across fresh extension connections and removes disconnected reports immediately", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const h = await newHarness([SAMPLE_RULE], {
      pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(privateKey)),
    });
    registerHarness(h);
    const greenExt = await connectClient(h.socketPath);
    const unarmedExt = await connectClient(h.socketPath);
    const admin = await connectClient(h.socketPath);
    track(greenExt.socket);
    track(unarmedExt.socket);
    track(admin.socket);
    expect((await nextMessage(greenExt.buf)).type).toBe("handshake_challenge");
    expect((await nextMessage(unarmedExt.buf)).type).toBe("handshake_challenge");
    expect((await nextMessage(admin.buf)).type).toBe("handshake_challenge");

    greenExt.socket.write(
      envelope(
        signAvailabilityReport({
          visibleReport: availabilitySnapshot(),
          privateKey,
          seq: 0,
        }),
      ),
    );
    unarmedExt.socket.write(
      envelope(
        signAvailabilityReport({
          visibleReport: availabilitySnapshot({
            lease_state: "unarmed",
            lease_reason: "not_armed",
          }),
          privateKey,
          seq: 0,
        }),
      ),
    );
    await tick();

    const nonGreen = await availabilityRequest(admin.socket, admin.buf, "avail-req-3");
    expect(nonGreen.type).toBe("enforcement_availability_response");
    if (nonGreen.type !== "enforcement_availability_response") {
      throw new Error("expected enforcement_availability_response");
    }
    expect(nonGreen.availability.status).toBe("non_green");
    expect(nonGreen.availability.reason).toBe("lease:not_armed");

    unarmedExt.socket.destroy();
    await tick();
    await tick();

    const live = await availabilityRequest(admin.socket, admin.buf, "avail-req-4");
    expect(live.type).toBe("enforcement_availability_response");
    if (live.type !== "enforcement_availability_response") {
      throw new Error("expected enforcement_availability_response");
    }
    expect(live.availability.status).toBe("live");
    expect(live.availability.reason).toBe("ok");
  });

  it("sends a signed handshake_response when a signer is configured", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
    tmpDirs.push(dir);
    const audit = makeAuditSink();
    const approvals = makeApprovalQueue();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE]),
      approvalQueue: approvals.queue,
      auditSink: audit.sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    let signedNonce: Uint8Array | null = null;
    const listener = new MacOSFlowIpcListener({
      socketPath: join(dir, "castle.sock"),
      consumer,
      generateNonce: () => new Uint8Array(32).fill(0x5a),
      handshakeSigner: {
        fortressId: FORTRESS_ID,
        signingKeyId: "identity-v1",
        signNonce: (nonce) => {
          signedNonce = nonce;
          return new Uint8Array(64).fill(0x7b);
        },
      },
    });
    await listener.start();
    liveListeners.push(listener);

    const { socket, buf } = await connectClient(join(dir, "castle.sock"));
    track(socket);
    const challenge = await nextMessage(buf);
    const response = await nextMessage(buf);

    expect(challenge.type).toBe("handshake_challenge");
    expect(response).toMatchObject({
      type: "handshake_response",
      fortress_id: FORTRESS_ID,
      signing_key_id: "identity-v1",
    });
    expect((response as { nonce_signature_b64url: string }).nonce_signature_b64url).toBe(
      Buffer.from(new Uint8Array(64).fill(0x7b)).toString("base64url"),
    );
    expect(signedNonce).toEqual(new Uint8Array(32).fill(0x5a));
  });

  it("emits an immediate manifest_updated in response to manifest_subscribe", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    // Drain the handshake challenge before subscribing so the test
    // unambiguously waits for the manifest snapshot.
    await nextMessage(buf);

    const subscribe: ManifestSubscribeRequest = {
      type: "manifest_subscribe",
      request_id: "req-1",
    };
    socket.write(envelope(subscribe));

    const reply = await nextMessage(buf);
    expect(reply.type).toBe("manifest_updated");
    const updated = reply as {
      type: string;
      rules: AllowlistRule[];
      signature: { signature_b64url: string };
    };
    expect(updated.rules).toHaveLength(1);
    expect(updated.rules[0]?.id).toBe(SAMPLE_RULE.id);
    expect(updated.signature.signature_b64url).toBe("sig-test");
  });

  it("dispatches flow_decision_recorded into the consumer's audit sink", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    await nextMessage(buf);

    const notif: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "drop",
      destination: {
        host: "evil.example.com",
        ip: "1.2.3.4",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: AGENT_TEST_TOKEN, template: "coding-assistant" },
      matched_rule_id: null,
      recorded_at: "2026-05-12T13:00:00Z",
    };
    socket.write(envelope(notif));

    // Allow event-loop drain so the consumer side runs.
    await new Promise((r) => setTimeout(r, 50));
    expect(h.audit.entries).toHaveLength(1);
    expect(h.audit.entries[0]?.operation).toBe("egress_blocked");
    expect(h.audit.entries[0]?.identityId).toBe(AGENT_TEST_SUBJECT);
    expect(h.listener.getStats().framesDecoded).toBeGreaterThanOrEqual(1);
  });

  it("dispatches flow_pending_approval into the consumer's approval queue", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    await nextMessage(buf);

    const notif: FlowPendingApprovalNotification = {
      type: "flow_pending_approval",
      request_id: "req-pending-1",
      surface: "egress",
      destination: {
        host: "unknown.example.com",
        ip: "5.6.7.8",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: AGENT_PENDING_TOKEN, template: "coding-assistant" },
      expires_in_seconds: 60,
    };
    socket.write(envelope(notif));

    await new Promise((r) => setTimeout(r, 50));
    expect(h.approvals.enqueued).toHaveLength(1);
    expect(h.approvals.enqueued[0]?.requestId).toBe("req-pending-1");
    expect(h.approvals.enqueued[0]?.agentId).toBe(AGENT_PENDING_TOKEN);
  });

  it("unregisters subscribers when the socket closes", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    await nextMessage(buf);
    expect(h.listener.getStats().activeConnections).toBe(1);

    socket.destroy();
    // Allow event-loop drain for the close event to fire.
    await new Promise((r) => setTimeout(r, 50));
    expect(h.listener.getStats().activeConnections).toBe(0);
  });

  it("broadcastManifestUpdate fans out to every active subscriber", async () => {
    const h = await newHarness();
    registerHarness(h);
    // Two simultaneous connections; both subscribe.
    const { socket: socketA, buf: bufA } = await connectClient(h.socketPath);
    track(socketA);
    await nextMessage(bufA);
    socketA.write(envelope({ type: "manifest_subscribe", request_id: "req-a" }));
    await nextMessage(bufA);

    const { socket: socketB, buf: bufB } = await connectClient(h.socketPath);
    track(socketB);
    await nextMessage(bufB);
    socketB.write(envelope({ type: "manifest_subscribe", request_id: "req-b" }));
    await nextMessage(bufB);

    // Sanity check: both subscribers are registered before broadcast.
    expect(h.listener.getStats().activeConnections).toBe(2);
    expect(h.consumer.getStats().subscribers).toBe(2);
    const fanCount = await h.listener.broadcastManifestUpdate();
    expect(fanCount).toBe(2);
    // Each subscriber receives a follow-up manifest_updated.
    const broadcastA = await nextMessage(bufA);
    const broadcastB = await nextMessage(bufB);
    expect(broadcastA.type).toBe("manifest_updated");
    expect(broadcastB.type).toBe("manifest_updated");
  });

  it("re-binds successfully when a stale socket file exists at the path", async () => {
    const h = await newHarness();
    registerHarness(h);
    await h.listener.stop();

    // Recreate listener on the same path; should unlink the stale socket
    // file (if any) and bind cleanly.
    const audit = makeAuditSink();
    const approvals = makeApprovalQueue();
    const consumer2 = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE]),
      approvalQueue: approvals.queue,
      auditSink: audit.sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    const listener2 = new MacOSFlowIpcListener({
      socketPath: h.socketPath,
      consumer: consumer2,
      generateNonce: () => new Uint8Array(32),
    });
    await listener2.start();
    liveListeners.push(listener2);
    const info = await stat(h.socketPath);
    expect(info.isSocket()).toBe(true);
    expect(listener2.getStats().isListening).toBe(true);
  });

  it("rejects malformed frames without crashing the connection", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    await nextMessage(buf);

    // Write a syntactically valid LSP frame whose body is malformed JSON.
    socket.write(frame("not valid json {{"));
    // Then write a wrong-jsonrpc envelope.
    socket.write(frame(JSON.stringify({ jsonrpc: "1.0", method: "castle-wall.flow_decision_recorded", params: {} })));
    // Then write a wrong-namespace envelope.
    socket.write(frame(JSON.stringify({ jsonrpc: "2.0", method: "other-namespace.foo", params: {} })));

    await new Promise((r) => setTimeout(r, 50));
    const stats = h.listener.getStats();
    expect(stats.framesRejected).toBeGreaterThanOrEqual(2);
    // Connection survives malformed traffic and is still counted active.
    expect(stats.activeConnections).toBe(1);
  });

  it("escapes control characters in listener route error logs", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
      tmpDirs.push(dir);
      const approvals = makeApprovalQueue();
      const throwingAuditSink: AuditSink = {
        append() {
          throw new Error("bad input\nforged log line\rwith bell\u0007");
        },
        async flush() {
          // no-op
        },
      };
      const consumer = new MacOSFlowEventConsumer({
        manifestProvider: makeManifestProvider([SAMPLE_RULE]),
        approvalQueue: approvals.queue,
        auditSink: throwingAuditSink,
        defaultApprovalTimeoutSeconds: 30,
      });
      const listener = new MacOSFlowIpcListener({
        socketPath: join(dir, "castle.sock"),
        consumer,
        generateNonce: () => new Uint8Array(32),
      });
      await listener.start();
      liveListeners.push(listener);

      const { socket, buf } = await connectClient(join(dir, "castle.sock"));
      track(socket);
      await nextMessage(buf);

      const notif: FlowDecisionRecordedNotification = {
        type: "flow_decision_recorded",
        decision: "drop",
        destination: {
          host: "evil.example.com",
          ip: "1.2.3.4",
          port: 443,
          protocol: "tcp",
          hostname_source: "sni",
          opaque: false,
        },
        agent: { id: AGENT_TEST_TOKEN, template: "coding-assistant" },
        matched_rule_id: null,
        recorded_at: "2026-05-12T13:00:00Z",
      };
      socket.write(envelope(notif));

      await new Promise((r) => setTimeout(r, 50));
      expect(errorSpy).toHaveBeenCalled();
      const line = String(errorSpy.mock.calls.at(-1)?.[0] ?? "");
      expect(line).toContain("\\n");
      expect(line).toContain("\\r");
      expect(line).toContain("\\x07");
      expect(line).not.toMatch(/[\r\n\u0007]/);
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("fails fast when start() is called twice without stop()", async () => {
    const h = await newHarness();
    registerHarness(h);
    await expect(h.listener.start()).rejects.toThrow(/already started/);
  });

  it("getStats counters increment under traffic", async () => {
    const h = await newHarness();
    registerHarness(h);
    const { socket, buf } = await connectClient(h.socketPath);
    track(socket);
    await nextMessage(buf);

    const flow: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: AGENT_COUNTER_TOKEN, template: "coding-assistant" },
      matched_rule_id: "rule-allow-anthropic",
      recorded_at: "2026-05-12T13:00:00Z",
    };
    for (let i = 0; i < 5; i++) {
      socket.write(envelope(flow));
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(h.listener.getStats().framesDecoded).toBe(5);
    expect(h.audit.entries.filter((e) => e.operation === "egress_allowed")).toHaveLength(5);
  });

  it("clamps connections to maxConnections", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-macos-listener-"));
    tmpDirs.push(dir);
    const audit = makeAuditSink();
    const approvals = makeApprovalQueue();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE]),
      approvalQueue: approvals.queue,
      auditSink: audit.sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    const listener = new MacOSFlowIpcListener({
      socketPath: join(dir, "castle.sock"),
      consumer,
      maxConnections: 2,
      generateNonce: () => new Uint8Array(32),
    });
    await listener.start();
    liveListeners.push(listener);

    const sockets: Socket[] = [];
    for (let i = 0; i < 3; i++) {
      const s = createConnection(join(dir, "castle.sock"));
      // Give the server a tick to accept (or refuse) the connection.
      await new Promise((r) => setTimeout(r, 25));
      sockets.push(s);
      liveSockets.push(s);
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(listener.getStats().activeConnections).toBeLessThanOrEqual(2);
  });
});
