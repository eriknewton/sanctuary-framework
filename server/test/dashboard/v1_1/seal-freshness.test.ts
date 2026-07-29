/**
 * Sanctuary v1.1 Dashboard - top-bar seal freshness tests.
 *
 * The seal must never render a confident Protected claim from an absent,
 * unparseable, or stale enforcement timestamp. Fresh evidence must carry its
 * own visible age.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getClientScript,
  renderDashboardV11Html,
} from "../../../src/dashboard/v1_1/index.js";

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
      what: string;
    };
    title: string;
  };
}

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

function liftSealHarness(): SealHarness {
  const src = getClientScript();
  const maxLine = src.match(/const SEAL_FRESHNESS_MAX_MS = [^;]+;/)?.[0];
  if (!maxLine) throw new Error("SEAL_FRESHNESS_MAX_MS not found");
  const pieces = [
    'const state = { tier1: { lockdown: { state: "idle" } }, posture: { data: null } };',
    maxLine,
    functionSource(src, "shortTime"),
    functionSource(src, "durationLabelFromMs"),
    functionSource(src, "liveEnforcementSnapshot"),
    functionSource(src, "sealFreshnessWindowMs"),
    functionSource(src, "sealEvidenceWhat"),
    functionSource(src, "deriveSealFreshness"),
    functionSource(src, "deriveSeal"),
    "return { state, deriveSeal };",
  ];
  return new Function(pieces.join("\n"))() as SealHarness;
}

function armedPayload(lastEvidenceAt: string | null): unknown {
  return {
    live_enforcement: {
      castle_wall_arm_state: "armed",
      evidence_basis: "fresh_enforcement_evidence",
      last_enforcement_evidence_at: lastEvidenceAt,
      freshness_window_ms: 600_000,
    },
  };
}

describe("v1.1 dashboard seal freshness", () => {
  const now = Date.parse("2026-07-29T12:00:00.000Z");

  afterEach(() => {
    vi.restoreAllMocks();
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
