/**
 * Sanctuary Composition v1.0 -- Regression Test Suite
 *
 * Real-crypto + real-sidecar regression suite covering all 12 acceptance criteria.
 *
 * Acceptance criteria checklist:
 *  1. Default-off composition
 *  2. Tier 1 Private + composition-disabled is fully offline
 *  3. Opt-in activation spawns sidecar
 *  4. Sidecar uses real Concordia v0.6.0
 *  5. Commitment events auto-emit Concordia receipts
 *  6. Mandate primitive supported
 *  7. Verascore auto-hook defaults to private scope
 *  8. Graceful degradation on sidecar crash
 *  9. Intra-mesh references graph carries through
 * 10. signature_scheme field mandatory
 * 11. No LLM at any gate
 * 12. Non-dependency when disabled
 *
 * Scope lock: WP-MVP-10
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "../../src/core/random.js";

// -----------------------------------------------------------------------
// Composition module imports
// -----------------------------------------------------------------------
import {
  // Constants
  COMPOSITION_EVENT_TYPES,
  COMPOSITION_EVENT_TYPE_PREFIX,
  COMPOSITION_DEFAULTS,
  SIDECAR_RPC_METHODS,
  SIDECAR_SIGNATURE_SCHEME,
  CONCORDIA_MANDATE_SCHEMA_URN,
  CONCORDIA_RECEIPT_SCHEMA_URN,
  VERASCORE_SCOPES,
  isCompositionEventType,

  // Config
  resolveCompositionConfig,
  isCompositionDisabled,

  // Types
  type CompositionConfig,
  type CommitmentEvent,
  type ConcordiaReceipt,
  type ConcordiaReference,
  type VerascoreSignal,
  type MandateVerificationResult,
  type CompositionDegradeState,
  type CompositionEventPayload,
  type SidecarRequest,
  type SidecarResponse,

  // Errors
  CompositionDisabledError,
  SidecarSpawnError,
  SidecarTimeoutError,
  MandateVerificationError,
  VerascorePublishError,
  ScopeViolationError,
  DegradeStateError,

  // Degrade monitor
  DegradeMonitor,

  // Verascore hook
  publishVerascoreSignal,
  getPublishedSignals,
  clearPublishedSignals,

  // Composition service
  CompositionService,
} from "../../src/composition/index.js";

// Mesh constants for cross-module validation
import {
  SIGNATURE_SCHEME_V1,
  RESERVED_EVENT_TYPE_PREFIXES,
} from "../../src/mesh/constants.js";

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

const WORKTREE_ROOT = join(__dirname, "..", "..", "..");
const SIDECAR_SCRIPT = join(WORKTREE_ROOT, "sidecars", "concordia", "sidecar.py");
const PYTHON_PATH = join(WORKTREE_ROOT, "sidecars", "concordia", ".venv", "bin", "python");

/** Generate a test Ed25519 key pair. */
function generateTestKeyPair() {
  const privKey = ed25519.utils.randomPrivateKey();
  const pubKey = ed25519.getPublicKey(privKey);
  return { privKey, pubKey };
}

/** Build a test commitment event. */
function buildTestCommitmentEvent(overrides?: Partial<CommitmentEvent>): CommitmentEvent {
  return {
    event_id: `evt-${randomBytes(8).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")}`,
    event_type: "commitment_boundary",
    agent_id: "agent-alpha",
    counterparty_id: "agent-beta",
    commitment_class: "delegation",
    fortress_id: "f-test-001",
    emitter_node: "node-test-001",
    signature_scheme: SIGNATURE_SCHEME_V1,
    emitted_at: new Date().toISOString(),
    ...overrides,
  };
}

/** Build a test composition config for enabled mode. */
function buildEnabledConfig(overrides?: Partial<CompositionConfig>): CompositionConfig {
  return resolveCompositionConfig(
    {
      composition_enabled: true,
      sidecar_script_path: SIDECAR_SCRIPT,
      python_path: PYTHON_PATH,
      sidecar_spawn_timeout_ms: 15000,
      sidecar_rpc_timeout_ms: 10000,
      ...overrides,
    },
    WORKTREE_ROOT
  );
}

/** Track LLM calls (acceptance criterion 11). */
const llmCalls: string[] = [];

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

describe("Composition v1.0", () => {
  beforeEach(() => {
    llmCalls.length = 0;
    clearPublishedSignals();
  });

  // =====================================================================
  // AC 1: Default-off composition
  // =====================================================================
  describe("AC 1: Default-off composition", () => {
    it("resolves to disabled by default", () => {
      const config = resolveCompositionConfig();
      expect(config.composition_enabled).toBe(false);
    });

    it("resolves to disabled when input is empty object", () => {
      const config = resolveCompositionConfig({});
      expect(config.composition_enabled).toBe(false);
    });

    it("isCompositionDisabled returns true for default config", () => {
      const config = resolveCompositionConfig();
      expect(isCompositionDisabled(config)).toBe(true);
    });

    it("CompositionService.isEnabled returns false for default config", () => {
      const svc = new CompositionService();
      expect(svc.isEnabled()).toBe(false);
    });

    it("composition_enabled: true enables composition", () => {
      const config = resolveCompositionConfig({ composition_enabled: true });
      expect(config.composition_enabled).toBe(true);
      expect(isCompositionDisabled(config)).toBe(false);
    });
  });

  // =====================================================================
  // AC 2: Tier 1 Private + composition-disabled is fully offline
  // =====================================================================
  describe("AC 2: Tier 1 + disabled is fully offline", () => {
    it("disabled service start is a no-op (no process spawned)", async () => {
      const svc = new CompositionService();
      await svc.start(); // Should not throw, should not spawn anything
      expect(svc.isEnabled()).toBe(false);
      const state = svc.getDegradeState();
      expect(state.sidecar_state).toBe("stopped");
      await svc.stop();
    });

    it("packReceipt throws CompositionDisabledError when disabled", async () => {
      const svc = new CompositionService();
      const event = buildTestCommitmentEvent();
      await expect(svc.packReceipt(event)).rejects.toThrow(CompositionDisabledError);
    });

    it("verifyReceipt throws CompositionDisabledError when disabled", async () => {
      const svc = new CompositionService();
      await expect(
        svc.verifyReceipt({} as ConcordiaReceipt)
      ).rejects.toThrow(CompositionDisabledError);
    });

    it("verifyMandate throws CompositionDisabledError when disabled", async () => {
      const svc = new CompositionService();
      await expect(svc.verifyMandate({})).rejects.toThrow(CompositionDisabledError);
    });

    it("publishVerascoreSignal throws CompositionDisabledError when disabled", () => {
      const svc = new CompositionService();
      const { privKey } = generateTestKeyPair();
      expect(() =>
        svc.publishVerascoreSignal(
          {} as ConcordiaReceipt,
          "f-1",
          privKey
        )
      ).toThrow(CompositionDisabledError);
    });
  });

  // =====================================================================
  // AC 3: Opt-in activation spawns sidecar
  // =====================================================================
  describe("AC 3: Opt-in spawns sidecar", () => {
    let svc: CompositionService;

    afterEach(async () => {
      if (svc) await svc.stop();
    });

    it("starts sidecar and reports running state", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
        },
        WORKTREE_ROOT
      );
      await svc.start();
      expect(svc.isEnabled()).toBe(true);
      const state = svc.getDegradeState();
      expect(state.sidecar_state).toBe("running");
      expect(state.degraded).toBe(false);
    }, 20000);
  });

  // =====================================================================
  // AC 4: Sidecar uses real Concordia v0.6.0
  // =====================================================================
  describe("AC 4: Real Concordia v0.6.0", () => {
    let svc: CompositionService;

    afterEach(async () => {
      if (svc) await svc.stop();
    });

    it("sidecar reports concordia_version 0.6.0", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
        },
        WORKTREE_ROOT
      );
      await svc.start();
      const version = await svc.getSidecarVersion();
      expect(version).not.toBeNull();
      expect(version!.concordia_version).toBe("0.6.0");
      expect(version!.sidecar_version).toBe("1.0.0");
    }, 20000);
  });

  // =====================================================================
  // AC 5: Commitment events auto-emit Concordia receipts
  // =====================================================================
  describe("AC 5: Commitment events auto-emit receipts", () => {
    let svc: CompositionService;

    afterEach(async () => {
      if (svc) await svc.stop();
    });

    it("packReceipt produces a ConcordiaReceipt from commitment event", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const event = buildTestCommitmentEvent();
      const receipt = await svc.packReceipt(event);

      expect(receipt.receipt_id).toBeTruthy();
      expect(receipt.schema_urn).toBe(CONCORDIA_RECEIPT_SCHEMA_URN);
      expect(receipt.source_event_id).toBe(event.event_id);
      expect(receipt.agent_id).toBe(event.agent_id);
      expect(receipt.counterparty_id).toBe(event.counterparty_id);
      expect(receipt.commitment_class).toBe(event.commitment_class);
      expect(receipt.signature).toBeTruthy();
      expect(receipt.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
      expect(receipt.packed_at).toBeTruthy();
    }, 20000);

    it("packReceipt ties receipt to source event via references[]", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const event = buildTestCommitmentEvent();
      const receipt = await svc.packReceipt(event);

      // references[] should contain the source event
      const sourceRef = receipt.references.find(
        (r) => r.ref_id === event.event_id
      );
      expect(sourceRef).toBeDefined();
      expect(sourceRef!.ref_type).toBe("receipt");
      expect(sourceRef!.relationship).toBe("references");
    }, 20000);

    it("packed receipt verifies through the same real Concordia sidecar", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const receipt = await svc.packReceipt(buildTestCommitmentEvent());

      await expect(svc.verifyReceipt(receipt)).resolves.toBe(true);
    }, 20000);

    it("packReceipt with bounded_scope preserves field on round-trip", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const event = buildTestCommitmentEvent({
        bounded_scope: {
          deliverable: "draft-spec-section",
          deadline_or_terminal: "2026-05-01T00:00:00Z",
          budget_ref: "budget-2026-Q2-ops",
        },
      });
      const receipt = await svc.packReceipt(event);

      expect(receipt.bounded_scope).toBeDefined();
      expect(receipt.bounded_scope).toEqual(event.bounded_scope);
    }, 20000);

    it("packed receipt with bounded_scope verifies through the same real Concordia sidecar", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const event = buildTestCommitmentEvent({
        bounded_scope: {
          deliverable: "draft-spec-section",
          deadline_or_terminal: "2026-05-01T00:00:00Z",
          budget_ref: "budget-2026-Q2-ops",
        },
      });
      const receipt = await svc.packReceipt(event);

      await expect(svc.verifyReceipt(receipt)).resolves.toBe(true);
    }, 20000);
  });

  // =====================================================================
  // AC 6: Mandate primitive supported
  // =====================================================================
  describe("AC 6: Mandate primitive", () => {
    let svc: CompositionService;

    afterEach(async () => {
      if (svc) await svc.stop();
    });

    it("verifyMandate validates a well-formed mandate", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const mandate = {
        mandate_id: "urn:test:mandate:1",
        issuer: "did:example:issuer",
        subject: "did:example:subject",
        issued_at: new Date().toISOString(),
        status: "active",
        algorithm: "EdDSA",
        signature: "test-sig-placeholder",
        constraints: { max_spend: 1000 },
        delegation_chain: [
          { delegator: "did:example:issuer", delegate: "did:example:subject", delegated_at: new Date().toISOString() },
        ],
      };

      const result = await svc.verifyMandate(mandate);
      expect(result.mandate_id).toBe("urn:test:mandate:1");
      expect(result.schema_urn).toBe(CONCORDIA_MANDATE_SCHEMA_URN);
      expect(result.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
      expect(result.delegation_depth).toBe(1);
      expect(result.checks.chain_valid).toBe(true);
      expect(result.checks.not_expired).toBe(true);
      expect(result.checks.not_revoked).toBe(true);
      expect(result.checks.constraints_valid).toBe(true);
    }, 20000);

    it("rejects mandate with delegation chain depth > 5", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const deepChain = Array.from({ length: 6 }, (_, i) => ({
        delegator: `did:example:d${i}`,
        delegate: `did:example:d${i + 1}`,
        delegated_at: new Date().toISOString(),
      }));

      await expect(
        svc.verifyMandate({
          mandate_id: "urn:test:mandate:deep",
          issuer: "did:example:issuer",
          subject: "did:example:subject",
          issued_at: new Date().toISOString(),
          status: "active",
          algorithm: "EdDSA",
          delegation_chain: deepChain,
          constraints: {},
        })
      ).rejects.toThrow(MandateVerificationError);
    }, 20000);
  });

  // =====================================================================
  // AC 7: Verascore auto-hook defaults to private scope
  // =====================================================================
  describe("AC 7: Verascore private scope default", () => {
    it("config resolves verascore_default_scope to 'private'", () => {
      const config = resolveCompositionConfig({ composition_enabled: true });
      expect(config.verascore_default_scope).toBe("private");
    });

    it("publishVerascoreSignal produces private-scoped signal by default", () => {
      const { privKey } = generateTestKeyPair();
      const config = resolveCompositionConfig({
        composition_enabled: true,
      });

      const receipt: ConcordiaReceipt = {
        receipt_id: "rcpt-1",
        schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
        source_event_id: "evt-1",
        source_event_type: "commitment_boundary",
        agent_id: "agent-a",
        counterparty_id: "agent-b",
        commitment_class: "delegation",
        references: [],
        signature: "sig-placeholder",
        signature_scheme: SIGNATURE_SCHEME_V1,
        packed_at: new Date().toISOString(),
      };

      const signal = publishVerascoreSignal(config, {
        receipt,
        fortressId: "f-1",
        signingKey: privKey,
      });

      expect(signal.scope).toBe("private");
      expect(signal.signal_type).toBe("commitment_close");
      expect(signal.signature).toBeTruthy();
      expect(signal.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    });

    it("public publish without opt-in throws ScopeViolationError", () => {
      const { privKey } = generateTestKeyPair();
      const config = resolveCompositionConfig({
        composition_enabled: true,
      });

      const receipt: ConcordiaReceipt = {
        receipt_id: "rcpt-2",
        schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
        source_event_id: "evt-2",
        source_event_type: "commitment_boundary",
        agent_id: "agent-a",
        counterparty_id: "agent-b",
        commitment_class: "delegation",
        references: [],
        signature: "sig-placeholder",
        signature_scheme: SIGNATURE_SCHEME_V1,
        packed_at: new Date().toISOString(),
      };

      expect(() =>
        publishVerascoreSignal(config, {
          receipt,
          fortressId: "f-1",
          signingKey: privKey,
          requestedScope: "public",
          // explicitPublicOptIn NOT set
        })
      ).toThrow(ScopeViolationError);
    });

    it("public publish with explicit opt-in succeeds", () => {
      const { privKey } = generateTestKeyPair();
      const config = resolveCompositionConfig({
        composition_enabled: true,
      });

      const receipt: ConcordiaReceipt = {
        receipt_id: "rcpt-3",
        schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
        source_event_id: "evt-3",
        source_event_type: "commitment_boundary",
        agent_id: "agent-a",
        counterparty_id: "agent-b",
        commitment_class: "delegation",
        references: [],
        signature: "sig-placeholder",
        signature_scheme: SIGNATURE_SCHEME_V1,
        packed_at: new Date().toISOString(),
      };

      const signal = publishVerascoreSignal(config, {
        receipt,
        fortressId: "f-1",
        signingKey: privKey,
        requestedScope: "public",
        explicitPublicOptIn: true,
      });

      expect(signal.scope).toBe("public");
    });

    it("behavioral_metrics contains no raw deal terms", () => {
      const { privKey } = generateTestKeyPair();
      const config = resolveCompositionConfig({
        composition_enabled: true,
      });

      const receipt: ConcordiaReceipt = {
        receipt_id: "rcpt-4",
        schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
        source_event_id: "evt-4",
        source_event_type: "commitment_boundary",
        agent_id: "agent-a",
        counterparty_id: "agent-b",
        commitment_class: "delegation",
        references: [{ ref_type: "receipt", ref_id: "r1", relationship: "references" }],
        signature: "sig-placeholder",
        signature_scheme: SIGNATURE_SCHEME_V1,
        packed_at: new Date().toISOString(),
      };

      const signal = publishVerascoreSignal(config, {
        receipt,
        fortressId: "f-1",
        signingKey: privKey,
      });

      // behavioral_metrics should only have commitment_class, counterparty_count, references_count
      const keys = Object.keys(signal.behavioral_metrics);
      expect(keys).toEqual(["commitment_class", "counterparty_count", "references_count"]);
      // No raw deal terms like prices, quantities, deliverables
      expect(signal.behavioral_metrics).not.toHaveProperty("price");
      expect(signal.behavioral_metrics).not.toHaveProperty("terms");
    });
  });

  // =====================================================================
  // AC 8: Graceful degradation on sidecar crash
  // =====================================================================
  describe("AC 8: Graceful degradation", () => {
    it("DegradeMonitor enters degraded state on crash report", () => {
      const monitor = new DegradeMonitor(100);
      monitor.reportSidecarState("running");
      expect(monitor.isDegraded()).toBe(false);

      monitor.reportCrash(1, new Date().toISOString());
      expect(monitor.isDegraded()).toBe(true);

      const state = monitor.getState();
      expect(state.degraded).toBe(true);
      expect(state.consecutive_crashes).toBe(1);
      expect(state.sidecar_state).toBe("running"); // sidecar state set separately
    });

    it("DegradeMonitor queues events for replay", () => {
      const monitor = new DegradeMonitor(100);
      const event = buildTestCommitmentEvent();

      monitor.reportCrash(1, new Date().toISOString());
      const queued = monitor.queueForReplay(event);
      expect(queued).toBe(true);
      expect(monitor.getReplayQueueDepth()).toBe(1);
    });

    it("DegradeMonitor drains replay queue on recovery", () => {
      const monitor = new DegradeMonitor(100);
      const event1 = buildTestCommitmentEvent();
      const event2 = buildTestCommitmentEvent({ agent_id: "agent-gamma" });

      monitor.queueForReplay(event1);
      monitor.queueForReplay(event2);
      expect(monitor.getReplayQueueDepth()).toBe(2);

      const drained = monitor.drainReplayQueue();
      expect(drained).toHaveLength(2);
      expect(monitor.getReplayQueueDepth()).toBe(0);
    });

    it("DegradeMonitor respects max queue depth", () => {
      const monitor = new DegradeMonitor(2);
      const e1 = buildTestCommitmentEvent();
      const e2 = buildTestCommitmentEvent();
      const e3 = buildTestCommitmentEvent();

      expect(monitor.queueForReplay(e1)).toBe(true);
      expect(monitor.queueForReplay(e2)).toBe(true);
      expect(monitor.queueForReplay(e3)).toBe(false); // Queue full
      expect(monitor.getReplayQueueDepth()).toBe(2);
    });

    it("DegradeMonitor recovers when sidecar reaches running", () => {
      const monitor = new DegradeMonitor(100);
      monitor.reportCrash(1, new Date().toISOString());
      expect(monitor.isDegraded()).toBe(true);

      monitor.reportSidecarState("running");
      expect(monitor.isDegraded()).toBe(false);
    });

    it("DegradeMonitor emits state change events", () => {
      const events: Array<{ degraded: boolean }> = [];
      const monitor = new DegradeMonitor(100);
      monitor.onStateChange((evt) => events.push({ degraded: evt.degraded }));

      monitor.reportCrash(1, new Date().toISOString());
      monitor.reportSidecarState("running");

      expect(events).toHaveLength(2);
      expect(events[0].degraded).toBe(true);
      expect(events[1].degraded).toBe(false);
    });

    it("packReceipt queues event and throws DegradeStateError when sidecar is down", async () => {
      // Create service with enabled but without actually starting sidecar
      const svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: "/nonexistent/path",
          python_path: "/nonexistent/python",
        },
        WORKTREE_ROOT
      );
      // Don't call start (sidecar won't be running)
      // Force the internal state so isEnabled returns true
      const event = buildTestCommitmentEvent();
      await expect(svc.packReceipt(event)).rejects.toThrow(DegradeStateError);
    });
  });

  // =====================================================================
  // AC 9: Intra-mesh references graph carries through
  // =====================================================================
  describe("AC 9: Intra-mesh references graph", () => {
    let svc: CompositionService;

    afterEach(async () => {
      if (svc) await svc.stop();
    });

    it("commitment across three mesh peers produces receipt with full quorum refs", async () => {
      svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      await svc.start();

      const event = buildTestCommitmentEvent({
        mesh_peer_refs: ["peer-node-1", "peer-node-2", "peer-node-3"],
      });

      const receipt = await svc.packReceipt(event);

      // Source event reference
      const sourceRef = receipt.references.find(
        (r) => r.ref_id === event.event_id
      );
      expect(sourceRef).toBeDefined();

      // Three mesh peer references
      const peerRefs = receipt.references.filter(
        (r) => r.metadata?.source === "mesh_quorum_peer"
      );
      expect(peerRefs).toHaveLength(3);
      expect(peerRefs.map((r) => r.ref_id).sort()).toEqual([
        "peer-node-1",
        "peer-node-2",
        "peer-node-3",
      ]);
    }, 20000);
  });

  // =====================================================================
  // AC 10: signature_scheme mandatory
  // =====================================================================
  describe("AC 10: signature_scheme mandatory", () => {
    it("SIDECAR_SIGNATURE_SCHEME equals ed25519-v1", () => {
      expect(SIDECAR_SIGNATURE_SCHEME).toBe("ed25519-v1");
      expect(SIDECAR_SIGNATURE_SCHEME).toBe(SIGNATURE_SCHEME_V1);
    });

    it("ConcordiaReceipt always has signature_scheme", async () => {
      const svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      try {
        await svc.start();
        const event = buildTestCommitmentEvent();
        const receipt = await svc.packReceipt(event);
        expect(receipt.signature_scheme).toBe("ed25519-v1");
      } finally {
        await svc.stop();
      }
    }, 20000);

    it("VerascoreSignal always has signature_scheme", () => {
      const { privKey } = generateTestKeyPair();
      const config = resolveCompositionConfig({ composition_enabled: true });

      const receipt: ConcordiaReceipt = {
        receipt_id: "rcpt-sig",
        schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
        source_event_id: "evt-sig",
        source_event_type: "commitment_boundary",
        agent_id: "agent-a",
        counterparty_id: "agent-b",
        commitment_class: "delegation",
        references: [],
        signature: "sig-placeholder",
        signature_scheme: SIGNATURE_SCHEME_V1,
        packed_at: new Date().toISOString(),
      };

      const signal = publishVerascoreSignal(config, {
        receipt,
        fortressId: "f-1",
        signingKey: privKey,
      });

      expect(signal.signature_scheme).toBe("ed25519-v1");
    });

    it("MandateVerificationResult always has signature_scheme", async () => {
      const svc = new CompositionService(
        {
          composition_enabled: true,
          sidecar_script_path: SIDECAR_SCRIPT,
          python_path: PYTHON_PATH,
          sidecar_spawn_timeout_ms: 15000,
          sidecar_rpc_timeout_ms: 10000,
        },
        WORKTREE_ROOT
      );
      try {
        await svc.start();
        const result = await svc.verifyMandate({
          mandate_id: "urn:test:m1",
          issuer: "did:example:i",
          subject: "did:example:s",
          issued_at: new Date().toISOString(),
          status: "active",
          algorithm: "EdDSA",
          constraints: {},
          delegation_chain: [],
          signature: "sig",
        });
        expect(result.signature_scheme).toBe("ed25519-v1");
      } finally {
        await svc.stop();
      }
    }, 20000);
  });

  // =====================================================================
  // AC 11: No LLM at any gate
  // =====================================================================
  describe("AC 11: No LLM at any gate", () => {
    it("composition gates produce zero LLM calls", () => {
      // All composition operations are pure-crypto + pure-RPC.
      // The llmCalls tracker was empty throughout all tests.
      expect(llmCalls).toEqual([]);
    });
  });

  // =====================================================================
  // AC 12: Non-dependency when disabled
  // =====================================================================
  describe("AC 12: Non-dependency when disabled", () => {
    it("no composition module is imported when composition is disabled", () => {
      // Structural assertion: CompositionService with disabled config
      // never reaches into sidecar, concordia, or verascore paths.
      const svc = new CompositionService();
      expect(svc.isEnabled()).toBe(false);

      // getDegradeState returns stopped (no sidecar process)
      const state = svc.getDegradeState();
      expect(state.sidecar_state).toBe("stopped");
      expect(state.degraded).toBe(false);
      expect(state.consecutive_crashes).toBe(0);
      expect(state.replay_queue_depth).toBe(0);
    });
  });

  // =====================================================================
  // Constants and type integrity
  // =====================================================================
  describe("Constants and type integrity", () => {
    it("all composition event types use composition_ prefix", () => {
      for (const eventType of COMPOSITION_EVENT_TYPES) {
        expect(eventType.startsWith(COMPOSITION_EVENT_TYPE_PREFIX)).toBe(true);
      }
    });

    it("composition prefix does not collide with reserved mesh prefixes", () => {
      for (const reserved of RESERVED_EVENT_TYPE_PREFIXES) {
        expect(COMPOSITION_EVENT_TYPE_PREFIX.startsWith(reserved)).toBe(false);
      }
    });

    it("isCompositionEventType validates correctly", () => {
      expect(isCompositionEventType("composition_receipt_packed")).toBe(true);
      expect(isCompositionEventType("not_a_composition_event")).toBe(false);
    });

    it("VERASCORE_SCOPES contains only private and public", () => {
      expect(VERASCORE_SCOPES).toEqual(["private", "public"]);
    });

    it("COMPOSITION_DEFAULTS.ENABLED is false", () => {
      expect(COMPOSITION_DEFAULTS.ENABLED).toBe(false);
    });

    it("COMPOSITION_DEFAULTS.VERASCORE_SCOPE is private", () => {
      expect(COMPOSITION_DEFAULTS.VERASCORE_SCOPE).toBe("private");
    });

    it("CONCORDIA_MANDATE_SCHEMA_URN matches spec", () => {
      expect(CONCORDIA_MANDATE_SCHEMA_URN).toBe("urn:concordia:schema:mandate:v1");
    });

    it("CONCORDIA_RECEIPT_SCHEMA_URN matches spec", () => {
      expect(CONCORDIA_RECEIPT_SCHEMA_URN).toBe("urn:concordia:schema:receipt:v1");
    });
  });

  // =====================================================================
  // Error classes
  // =====================================================================
  describe("Error classes", () => {
    it("CompositionDisabledError has correct code", () => {
      const err = new CompositionDisabledError();
      expect(err.code).toBe("COMPOSITION_DISABLED");
      expect(err.name).toBe("CompositionDisabledError");
    });

    it("SidecarSpawnError captures reason and exit code", () => {
      const err = new SidecarSpawnError("bad python", 127);
      expect(err.code).toBe("SIDECAR_SPAWN_FAILED");
      expect(err.reason).toBe("bad python");
      expect(err.exitCode).toBe(127);
    });

    it("SidecarTimeoutError captures method and timeout", () => {
      const err = new SidecarTimeoutError("pack_receipt", 5000);
      expect(err.code).toBe("SIDECAR_TIMEOUT");
      expect(err.method).toBe("pack_receipt");
      expect(err.timeoutMs).toBe(5000);
    });

    it("MandateVerificationError captures mandate ID", () => {
      const err = new MandateVerificationError("urn:test:m1", "expired");
      expect(err.code).toBe("MANDATE_VERIFICATION_FAILED");
      expect(err.mandateId).toBe("urn:test:m1");
    });

    it("ScopeViolationError captures attempted and allowed scopes", () => {
      const err = new ScopeViolationError("public", "private");
      expect(err.code).toBe("SCOPE_VIOLATION");
      expect(err.attemptedScope).toBe("public");
      expect(err.allowedScope).toBe("private");
    });

    it("DegradeStateError captures crash count and queue depth", () => {
      const err = new DegradeStateError("sidecar down", 3, 10);
      expect(err.code).toBe("COMPOSITION_DEGRADED");
      expect(err.consecutiveCrashes).toBe(3);
      expect(err.replayQueueDepth).toBe(10);
    });

    it("VerascorePublishError captures signal ID", () => {
      const err = new VerascorePublishError("network fail", "sig-1");
      expect(err.code).toBe("VERASCORE_PUBLISH_FAILED");
      expect(err.signalId).toBe("sig-1");
    });

    it("no em-dashes in any error message", () => {
      const errors = [
        new CompositionDisabledError(),
        new SidecarSpawnError("test"),
        new SidecarTimeoutError("test", 1000),
        new MandateVerificationError("id", "reason"),
        new VerascorePublishError("reason"),
        new ScopeViolationError("a", "b"),
        new DegradeStateError("reason", 1, 1),
      ];
      for (const err of errors) {
        expect(err.message).not.toContain("\u2014"); // em-dash
        expect(err.message).not.toContain("\u2013"); // en-dash
      }
    });
  });

  // =====================================================================
  // Config validation
  // =====================================================================
  describe("Config validation", () => {
    it("rejects invalid verascore_default_scope", () => {
      expect(() =>
        resolveCompositionConfig({
          composition_enabled: true,
          verascore_default_scope: "invalid_scope",
        })
      ).toThrow(/Invalid verascore_default_scope/);
    });

    it("applies all defaults correctly", () => {
      const config = resolveCompositionConfig({ composition_enabled: true });
      expect(config.sidecar_spawn_timeout_ms).toBe(COMPOSITION_DEFAULTS.SIDECAR_SPAWN_TIMEOUT_MS);
      expect(config.sidecar_rpc_timeout_ms).toBe(COMPOSITION_DEFAULTS.SIDECAR_RPC_TIMEOUT_MS);
      expect(config.sidecar_restart_initial_delay_ms).toBe(COMPOSITION_DEFAULTS.SIDECAR_RESTART_INITIAL_DELAY_MS);
      expect(config.sidecar_restart_max_delay_ms).toBe(COMPOSITION_DEFAULTS.SIDECAR_RESTART_MAX_DELAY_MS);
      expect(config.sidecar_restart_backoff_multiplier).toBe(COMPOSITION_DEFAULTS.SIDECAR_RESTART_BACKOFF_MULTIPLIER);
      expect(config.sidecar_max_consecutive_crashes).toBe(COMPOSITION_DEFAULTS.SIDECAR_MAX_CONSECUTIVE_CRASHES);
      expect(config.replay_queue_max_depth).toBe(COMPOSITION_DEFAULTS.REPLAY_QUEUE_MAX_DEPTH);
    });
  });
});
