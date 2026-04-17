/**
 * L2 Governor Tools tests
 *
 * Covers: governor_status calculation, high-rate tool warnings, hard_stopped state,
 * governor_reset confirmation gate, pre/post state capture.
 * Not covered: performance, integration with real CallGovernor.
 */

import { describe, it, expect, vi } from "vitest";
import { createGovernorTools } from "../../src/l2-operational/governor-tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";

function makeGovernor(overrides: Partial<ReturnType<typeof defaultStatus>> = {}) {
  const status = { ...defaultStatus(), ...overrides };
  return {
    getStatus: vi.fn(() => ({ ...status })),
    reset: vi.fn(() => {
      status.volume_current = 0;
      status.lifetime_current = 0;
      status.duplicate_cache_size = 0;
      status.hard_stopped = false;
      status.rate_by_tool = {};
    }),
  };
}

function defaultStatus() {
  return {
    volume_current: 50,
    volume_limit: 200,
    lifetime_current: 100,
    lifetime_limit: 1000,
    duplicate_cache_size: 5,
    hard_stopped: false,
    rate_by_tool: {} as Record<string, number>,
    window_start: new Date().toISOString(),
    window_seconds: 60,
  };
}

function setup(overrides?: Partial<ReturnType<typeof defaultStatus>>) {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const governor = makeGovernor(overrides);
  const { tools } = createGovernorTools(governor as any, auditLog);
  const findTool = (name: string) => tools.find(t => t.name === name)!;
  return { governor, auditLog, findTool };
}

describe("Governor Tools", () => {
  describe("governor_status", () => {
    it("returns usage percentages", async () => {
      const { findTool } = setup();
      const result = await findTool("governor_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.summary.volume_usage).toContain("25%");
    });

    it("warns when volume > 80%", async () => {
      const { findTool } = setup({ volume_current: 180, volume_limit: 200 });
      const result = await findTool("governor_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.warnings.some((w: string) => w.includes("Volume usage"))).toBe(true);
    });

    it("includes hard stop warning", async () => {
      const { findTool } = setup({ hard_stopped: true });
      const result = await findTool("governor_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.warnings.some((w: string) => w.includes("HARD STOP"))).toBe(true);
    });

    it("flags high-rate tools", async () => {
      const { findTool } = setup({ rate_by_tool: { "state_read": 15, "state_write": 3 } });
      const result = await findTool("governor_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.warnings.some((w: string) => w.includes("state_read"))).toBe(true);
    });
  });

  describe("governor_reset", () => {
    it("rejects without confirmation", async () => {
      const { findTool, governor } = setup();
      const result = await findTool("governor_reset").handler({ confirm: false });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe("confirmation_required");
      expect(governor.reset).not.toHaveBeenCalled();
    });

    it("resets with confirmation", async () => {
      const { findTool, governor } = setup();
      const result = await findTool("governor_reset").handler({ confirm: true });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.reset).toBe(true);
      expect(governor.reset).toHaveBeenCalledOnce();
      expect(parsed.current_state.volume_current).toBe(0);
    });

    it("notes hard stop was cleared", async () => {
      const { findTool } = setup({ hard_stopped: true });
      const result = await findTool("governor_reset").handler({ confirm: true });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.message).toContain("Hard stop has been cleared");
    });
  });
});
