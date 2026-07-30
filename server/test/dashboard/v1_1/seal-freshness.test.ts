/**
 * Sanctuary v1.1 Dashboard - top-bar seal freshness tests.
 *
 * The seal must never render a confident Protected claim from an absent,
 * unparseable, or stale enforcement timestamp. Fresh evidence must carry its
 * own visible age.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import {
  getClientScript,
  renderDashboardV11Html,
} from "../../../src/dashboard/v1_1/index.js";
import {
  buildSovereigntyRoutePayload,
  type SovereigntyRoutePayload,
} from "../../../src/principal-policy/dashboard.js";
import {
  buildCastleWallPosture,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  type CastleWallPosture,
} from "../../../src/principal-policy/posture.js";
import { protectionSubjectFromMacOSAuditToken } from "../../../src/castle-wall/subject-binding.js";
import { NODE_TRUST_BOUNDARY_VERSION } from "../../../src/mesh/node-posture.js";
import type { SignedSHR } from "../../../src/shr/types.js";
import type { FederationPostureSummary } from "../../../src/v1/federation.js";

interface SealHarness {
  state: {
    tier1: { lockdown: { state: string } };
    posture: { data: unknown };
  };
  deriveSeal: () => {
    tone: string;
    word: string;
    arm: string | null;
    freshness: {
      state: string;
      current: boolean;
      inline: string;
      detail: string;
      windowLabel: string;
      windowKnown: boolean;
      refreshAt: number | null;
      what: string;
    };
    title: string;
  };
  renderPostureSeal: () => void;
  elements: Record<string, {
    textContent: string;
    hidden: boolean;
    attrs: Record<string, string>;
    classList: {
      add: (...names: string[]) => void;
      remove: (...names: string[]) => void;
      has: (name: string) => boolean;
    };
  }>;
  rerenderCount: () => number;
}

const FORTRESS = "fortress:test";

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

const CLAIM_TOKEN = auditTokenForRuid(503);
const CLAIM_SUBJECT = protectionSubjectFromMacOSAuditToken(FORTRESS, CLAIM_TOKEN);
if (CLAIM_SUBJECT === null) throw new Error("test subject could not be derived");

function functionSource(src: string, name: string): string {
  const marker = `function ${name}(`;
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`${name} not found in client script`);
  const brace = src.indexOf("{", start);
  if (brace < 0) throw new Error(`${name} has no body`);
  let depth = 0;
  for (let i = brace; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error(`${name} body did not close`);
}

function testShr(): SignedSHR {
  return {
    body: {
      shr_version: "1.0",
      implementation: {
        sanctuary_version: "test",
        node_version: "test",
        generated_by: "sanctuary-mcp-server",
      },
      instance_id: FORTRESS,
      generated_at: "2026-07-29T12:00:00.000Z",
      expires_at: "2026-07-29T13:00:00.000Z",
      layers: {
        l1: {
          status: "active",
          encryption: "AES-256-GCM",
          key_custody: "self",
          integrity: "merkle-signed",
          identity_type: "ed25519",
          state_portable: true,
        },
        l2: {
          status: "active",
          isolation_type: "append-only audit",
          attestation_available: true,
        },
        l3: {
          status: "active",
          proof_system: "commitments",
          selective_disclosure: true,
        },
        l4: {
          status: "active",
          reputation_mode: "local",
          attestation_format: "ed25519",
          reputation_portable: true,
        },
      },
      capabilities: {
        handshake: true,
        shr_exchange: true,
        reputation_verify: true,
        encrypted_channel: true,
      },
      degradations: [],
    },
    signed_by: "test-public-key",
    signature_scheme: "ed25519-v1",
    signature: "test-signature",
  };
}

function testFederationPosture(): FederationPostureSummary {
  return {
    version: NODE_TRUST_BOUNDARY_VERSION,
    local_nodes: 0,
    operator_cloud_nodes: 0,
    sovereign_tee_nodes: 0,
    unknown_nodes: 0,
    provider_in_trust_boundary: false,
    tee_attested: false,
    disclosure: null,
    guardian_break_glass: { active: false },
  };
}

async function armedWallPosture(now: number): Promise<CastleWallPosture> {
  const storage = new MemoryStorage();
  const log = new AuditLog(storage, generateRandomKey());
  await log.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: CLAIM_SUBJECT,
    result: "success",
    details: {
      agent_id: CLAIM_TOKEN,
      cw_source: "castle_wall_audit_consumer",
    },
    timestamp: new Date(now - 2 * 60 * 1000).toISOString(),
  });
  return await buildCastleWallPosture({
    protectionClaimSubject: CLAIM_SUBJECT,
    auditLog: log,
    originMachine: FORTRESS,
    platform: "linux",
    now,
  });
}

async function armedSovereigntyPayload(now: number): Promise<SovereigntyRoutePayload> {
  const wall = await armedWallPosture(now);
  return buildSovereigntyRoutePayload({
    shr: testShr(),
    wall,
    federationPosture: testFederationPosture(),
    configLoaded: true,
  });
}

function liftSealHarness(): SealHarness {
  const src = getClientScript();
  const maxLine = src.match(/const SEAL_FRESHNESS_MAX_MS = [^;]+;/)?.[0];
  if (!maxLine) throw new Error("SEAL_FRESHNESS_MAX_MS not found");
  const pieces = [
    'const state = { tier1: { lockdown: { state: "idle" } }, posture: { data: null } };',
    maxLine,
    "let sealFreshnessTimer = null;",
    "let __rerenderCount = 0;",
    "function makeEl() { const classes = new Set(); return { textContent: '', hidden: false, attrs: {}, classList: { add: function () { for (let i = 0; i < arguments.length; i++) classes.add(arguments[i]); }, remove: function () { for (let i = 0; i < arguments.length; i++) classes.delete(arguments[i]); }, has: function (name) { return classes.has(name); } }, setAttribute: function (k, v) { this.attrs[k] = String(v); } }; }",
    "const elements = { 'posture-seal': makeEl(), 'posture-seal-word': makeEl(), 'posture-seal-freshness': makeEl(), 'posture-seal-pop': makeEl() };",
    "const document = { getElementById: function (id) { return elements[id] || null; } };",
    functionSource(src, "shortTime"),
    functionSource(src, "durationLabelFromMs"),
    functionSource(src, "liveEnforcementSnapshot"),
    functionSource(src, "sealFreshnessWindowMs"),
    functionSource(src, "sealEvidenceWhat"),
    functionSource(src, "deriveSealFreshness"),
    functionSource(src, "clearSealFreshnessTimer"),
    functionSource(src, "scheduleSealFreshnessRefresh"),
    functionSource(src, "deriveSeal"),
    functionSource(src, "renderPostureSeal"),
    "function rerender() { __rerenderCount += 1; renderPostureSeal(); }",
    "return { state, deriveSeal, renderPostureSeal, elements, rerenderCount: function () { return __rerenderCount; } };",
  ];
  return new Function(pieces.join("\n"))() as SealHarness;
}

function armedPayload(
  lastEvidenceAt: string | null,
  freshnessWindowMs?: unknown,
): unknown {
  const live: Record<string, unknown> = {
    castle_wall_arm_state: "armed",
    evidence_basis: "fresh_enforcement_evidence",
    last_enforcement_evidence_at: lastEvidenceAt,
    freshness_window_ms: arguments.length >= 2 ? freshnessWindowMs : 600_000,
  };
  return {
    live_enforcement: live,
  };
}

describe("v1.1 dashboard seal freshness", () => {
  const now = Date.parse("2026-07-29T12:00:00.000Z");

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("absent enforcement timestamp with armed payload does not render Protected", () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const harness = liftSealHarness();
    harness.state.posture.data = armedPayload(null);

    const seal = harness.deriveSeal();

    expect(seal.word).toBe("Attention");
    expect(seal.tone).toBe("attention");
    expect(seal.freshness.state).toBe("absent");
    expect(seal.freshness.current).toBe(false);
    expect(seal.freshness.inline).toBe("no evidence");
  });

  it("unparseable enforcement timestamp with armed payload does not render Protected", () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const harness = liftSealHarness();
    harness.state.posture.data = armedPayload("not-a-date");

    const seal = harness.deriveSeal();

    expect(seal.word).toBe("Attention");
    expect(seal.tone).toBe("attention");
    expect(seal.freshness.state).toBe("unparseable");
    expect(seal.freshness.current).toBe(false);
    expect(seal.freshness.inline).toBe("invalid evidence time");
  });

  it("stale enforcement timestamp with armed payload does not render Protected", () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const harness = liftSealHarness();
    harness.state.posture.data = armedPayload(
      new Date(now - 11 * 60 * 1000).toISOString(),
    );

    const seal = harness.deriveSeal();

    expect(seal.word).toBe("Attention");
    expect(seal.tone).toBe("attention");
    expect(seal.freshness.state).toBe("stale");
    expect(seal.freshness.current).toBe(false);
    expect(seal.freshness.inline).toBe("last evidenced 11m ago");
  });

  it("fresh enforcement timestamp with armed payload renders Protected with visible age", () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const harness = liftSealHarness();
    harness.state.posture.data = armedPayload(
      new Date(now - 2 * 60 * 1000).toISOString(),
    );

    const seal = harness.deriveSeal();

    expect(seal.word).toBe("Protected");
    expect(seal.tone).toBe("protected");
    expect(seal.freshness.state).toBe("fresh");
    expect(seal.freshness.current).toBe(true);
    expect(seal.freshness.inline).toBe("last evidenced 2m ago");
    expect(seal.title).toBe("Protected. Last evidenced 2m ago.");
  });

  it("the real /api/sovereignty payload builder emits the posture freshness window", async () => {
    const wall = await armedWallPosture(now);
    const payload = buildSovereigntyRoutePayload({
      shr: testShr(),
      wall,
      federationPosture: testFederationPosture(),
      configLoaded: true,
    });

    expect(payload.live_enforcement.castle_wall_arm_state).toBe("armed");
    expect(payload.live_enforcement.freshness_window_ms).toBe(
      wall.freshness_window_ms,
    );
    expect(payload.live_enforcement.freshness_window_ms).toBe(
      DEFAULT_ENFORCEMENT_FRESHNESS_MS,
    );
    expect(Number.isFinite(payload.live_enforcement.freshness_window_ms)).toBe(true);
    expect(payload.live_enforcement.freshness_window_ms).toBeGreaterThan(0);
  });

  it("a real /api/sovereignty payload drives the client seal to Protected while current", async () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const harness = liftSealHarness();
    harness.state.posture.data = await armedSovereigntyPayload(now);

    const seal = harness.deriveSeal();

    expect(seal.word).toBe("Protected");
    expect(seal.tone).toBe("protected");
    expect(seal.freshness.state).toBe("fresh");
    expect(seal.freshness.current).toBe(true);
    expect(seal.freshness.windowKnown).toBe(true);
    expect(seal.freshness.windowLabel).toBe("10m");
    expect(seal.freshness.inline).toBe("last evidenced 2m ago");
  });

  it("rerenders the seal stale after the freshness window elapses without a new event", () => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    const harness = liftSealHarness();
    harness.state.posture.data = armedPayload(new Date(now).toISOString(), 60_000);

    harness.renderPostureSeal();

    expect(harness.elements["posture-seal"].classList.has("tone-protected")).toBe(true);
    expect(harness.elements["posture-seal-word"].textContent).toBe("Protected");
    expect(harness.elements["posture-seal-freshness"].classList.has("fresh")).toBe(true);

    vi.advanceTimersByTime(61_001);

    expect(harness.rerenderCount()).toBe(1);
    expect(harness.elements["posture-seal"].classList.has("tone-protected")).toBe(false);
    expect(harness.elements["posture-seal"].classList.has("tone-attention")).toBe(true);
    expect(harness.elements["posture-seal-word"].textContent).toBe("Attention");
    expect(harness.elements["posture-seal-freshness"].classList.has("not-fresh")).toBe(true);
  });

  it("malformed or absent freshness windows render unknown instead of current", () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const cases: unknown[] = [undefined, "not-a-number", "NaN", 0, -1];
    const harness = liftSealHarness();

    for (const freshnessWindowMs of cases) {
      harness.state.posture.data = armedPayload(
        new Date(now - 1_000).toISOString(),
        freshnessWindowMs,
      );

      const seal = harness.deriveSeal();

      expect(seal.word).toBe("Attention");
      expect(seal.tone).toBe("attention");
      expect(seal.freshness.state).toBe("unknown");
      expect(seal.freshness.current).toBe(false);
      expect(seal.freshness.inline).toBe("freshness window unknown");
      expect(seal.freshness.windowLabel).toBe("unknown");
      expect(seal.freshness.windowKnown).toBe(false);
    }
  });

  it("renders a dedicated freshness slot and popover evidence detail", () => {
    const html = renderDashboardV11Html({ embedClient: false });
    const client = getClientScript();

    expect(html).toContain('id="posture-seal-freshness"');
    expect(html).toContain("loading evidence");
    expect(client).toContain("What was evidenced");
    expect(client).toContain("Evidence time");
    expect(client).toContain(
      "Protected means Castle Wall enforcement was observed within the freshness window",
    );
  });
});
