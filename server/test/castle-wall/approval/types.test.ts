/**
 * Castle Wall approval-flow type tests.
 *
 * Exercises the strict-mode confidence helper and the default coalescing
 * config to ensure the wire shape downstream PRs build against is stable.
 */

import { describe, it, expect } from "vitest";
import {
  CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP,
  CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS,
} from "../../../src/castle-wall/constants.js";
import {
  LOW_CONFIDENCE_LABELS,
  defaultPromptCoalescingConfig,
  shouldRequireStrictConfirmation,
  type ApprovalConfidence,
} from "../../../src/castle-wall/approval/types.js";

describe("castle-wall/approval/types : confidence labels", () => {
  it("includes every low-confidence label", () => {
    expect(LOW_CONFIDENCE_LABELS).toContain("low_opaque");
    expect(LOW_CONFIDENCE_LABELS).toContain("low_raw_ip");
    expect(LOW_CONFIDENCE_LABELS).toContain("low_doh_dot");
  });

  it("excludes the high-confidence label", () => {
    expect(LOW_CONFIDENCE_LABELS).not.toContain("high");
  });

  it("strict-mode helper triggers on every low-confidence label when enabled", () => {
    for (const label of LOW_CONFIDENCE_LABELS) {
      expect(shouldRequireStrictConfirmation(label, true)).toBe(true);
    }
  });

  it("strict-mode helper never triggers when strict mode is disabled", () => {
    const labels: ApprovalConfidence[] = ["high", "low_opaque", "low_raw_ip", "low_doh_dot"];
    for (const label of labels) {
      expect(shouldRequireStrictConfirmation(label, false)).toBe(false);
    }
  });

  it("strict-mode helper does not trigger on high-confidence label even when enabled", () => {
    expect(shouldRequireStrictConfirmation("high", true)).toBe(false);
  });
});

describe("castle-wall/approval/types : default coalescing config", () => {
  it("matches scope-lock defaults: 5 prompts per 30 seconds per agent", () => {
    const cfg = defaultPromptCoalescingConfig();
    expect(cfg.default_cap_per_agent.count).toBe(CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP);
    expect(cfg.default_cap_per_agent.window_seconds).toBe(
      CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS
    );
    expect(cfg.default_cap_per_agent.count).toBe(5);
    expect(cfg.default_cap_per_agent.window_seconds).toBe(30);
  });

  it("starts with no per-template overrides", () => {
    const cfg = defaultPromptCoalescingConfig();
    expect(cfg.per_template_overrides).toEqual({});
  });

  it("returns a fresh object each call so tests do not share mutable state", () => {
    const a = defaultPromptCoalescingConfig();
    const b = defaultPromptCoalescingConfig();
    a.per_template_overrides["claude-code"] = { count: 10, window_seconds: 60 };
    expect(b.per_template_overrides).toEqual({});
  });
});
