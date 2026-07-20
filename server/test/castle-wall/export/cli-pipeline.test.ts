/**
 * Hermetic tests for the CLI export pipeline wiring (`runExportPipeline`) + the
 * Tier-1 classification the CLI relies on.
 *
 * The pipeline is fully injectable, so these never touch a real ~/.sanctuary or
 * the network. The two load-bearing CLI guarantees:
 *   1. The DEFAULT (file sink) touches NO network and needs NO approval.
 *   2. Arming the OUTBOUND push requires the Tier-1 approval gate: a denial
 *      refuses and pushes nothing; an approval arms the pinned collector.
 *
 * A third test proves the classification the production CLI depends on:
 * `enforcement_export_enabled` classifies Tier-1 under a stock policy (an unknown
 * operator-side op fails closed to require approval), so the gate-backed approver
 * the CLI wires for the http lane really does prompt the operator.
 */

import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import type { AuditEntry } from "../../../src/operational/audit-log.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import {
  ENFORCEMENT_EXPORT_ENABLED,
  EXPORT_CURSOR_START,
  type ExportApprover,
  type ExportAudit,
  type ExportCursorReadResult,
  type ExportCursorState,
  type ExportCursorStore,
  type VerifiedChainSource,
} from "../../../src/castle-wall/export/index.js";
import { runExportPipeline } from "../../../src/cli/cortex-export.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";

import { ApprovalGate } from "../../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../../src/principal-policy/baseline.js";
import { AutoApproveChannel } from "../../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

const PRODUCER_PRIV = ed25519.utils.randomPrivateKey();
const PRODUCER_PUB_B64 = toBase64url(ed25519.getPublicKey(PRODUCER_PRIV));
const SIGNED_AT_MS = 1_777_777_777_777;
const SIGNED_MAP_OPTIONS = {
  pinnedProducerKeyB64url: PRODUCER_PUB_B64,
  subjectFortressId: "fortress:test",
};

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function withProducerSignature(entry: AuditEntry, identityId: string): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 31;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    PRODUCER_PRIV,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

class MemoryCursorStore implements ExportCursorStore {
  state: ExportCursorState;
  constructor(sequence: number = EXPORT_CURSOR_START) {
    this.state = { sequence, entryHash: sequence === EXPORT_CURSOR_START ? null : `eh-${sequence}` };
  }
  get value(): number {
    return this.state.sequence;
  }
  async read(): Promise<ExportCursorReadResult> {
    return { state: { ...this.state }, reset: null };
  }
  async write(state: ExportCursorState): Promise<void> {
    this.state = { ...state };
  }
}

function egressChain(): VerifiedChainSource {
  const entry = withProducerSignature({
    timestamp: "2026-07-10T00:00:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "claude-code-1",
    result: "failure",
    details: { destination: { host: "evil.example", port: 443, protocol: "tcp" }, rule_id: "r0" },
  }, "claude-code-1");
  return {
    async streamVerifiedChain(consumer) {
      consumer.onEntry({ sequence: 0, entry_hash: "eh-0", entry });
    },
  };
}

const noopAudit: ExportAudit = async () => {};

describe("CLI export pipeline: safe default (no network, no approval)", () => {
  it("the default file sink touches no network and never calls approve or fetch", async () => {
    const approve = vi.fn(async () => ({ allowed: true as const }));
    const fetchSpy = vi.fn();
    const lines: string[] = [];
    const result = await runExportPipeline({
      config: { sink: "file", enabled: false },
      approve: approve as unknown as ExportApprover,
      audit: noopAudit,
      source: egressChain(),
      cursor: new MemoryCursorStore(),
      fileWriter: (line) => {
        lines.push(line);
      },
      fetchImpl: fetchSpy as unknown as typeof fetch,
      mapOptions: SIGNED_MAP_OPTIONS,
      sleep: async () => {},
    });
    expect(result.status).toBe("ran");
    if (result.status === "ran") {
      expect(result.touchesNetwork).toBe(false);
      expect(result.stream.delivered).toBe(1);
    }
    expect(approve).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(lines).toHaveLength(1);
  });
});

describe("CLI export pipeline: outbound push requires the Tier-1 gate", () => {
  const httpConfig = {
    sink: "http" as const,
    enabled: true,
    destination_url: "https://collector.example/xsiam",
  };

  it("refuses and pushes nothing when the Tier-1 approval is denied", async () => {
    const deny: ExportApprover = async () => ({ allowed: false, reason: "operator denied" });
    const fetchSpy = vi.fn();
    const result = await runExportPipeline({
      config: httpConfig,
      approve: deny,
      audit: noopAudit,
      source: egressChain(),
      cursor: new MemoryCursorStore(),
      fetchImpl: fetchSpy as unknown as typeof fetch,
      mapOptions: SIGNED_MAP_OPTIONS,
      sleep: async () => {},
    });
    expect(result.status).toBe("refused");
    if (result.status === "refused") expect(result.reason).toMatch(/denied/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("arms the pinned collector and delivers only mapped metadata on approval", async () => {
    const approve: ExportApprover = async () => ({ allowed: true });
    const bodies: string[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      bodies.push(String(init.body));
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    const result = await runExportPipeline({
      config: httpConfig,
      approve,
      audit: noopAudit,
      source: egressChain(),
      cursor: new MemoryCursorStore(),
      fetchImpl,
      mapOptions: SIGNED_MAP_OPTIONS,
      sleep: async () => {},
    });
    expect(result.status).toBe("ran");
    if (result.status === "ran") expect(result.touchesNetwork).toBe(true);
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]!).events[0].destination_host).toBe("evil.example");
  });
});

describe("enforcement_export_enabled is a force-pinned Tier-1 op the CLI relies on", () => {
  it("a stock ApprovalGate classifies the exporter enable op Tier-1 (always requires approval)", () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      new BaselineTracker(storage, masterKey),
      new AutoApproveChannel(),
      new AuditLog(storage, masterKey),
    );
    // Force-pinned Tier-1: the gate-backed approver the CLI wires for the http
    // lane ALWAYS prompts the operator. Never auto-allowed, never anomaly-gated.
    expect(gate.classifyRiskTier(ENFORCEMENT_EXPORT_ENABLED, {})).toBe(1);
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(ENFORCEMENT_EXPORT_ENABLED);
  });
});
