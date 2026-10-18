import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  BARRIER_RELEASE_BOUND_MS,
  DRAIN_TAIL_MS,
  EXIT_MARGIN_MS,
  RELAY_CHILD_SIGTERM_GRACE_MS,
  STOP_LATENCY_BUDGET_MS,
} from "../../src/hermes-memory-bridge/process-shell.js";

const PROCESS_SHELL = fileURLToPath(new URL("../../src/hermes-memory-bridge/process-shell.ts", import.meta.url));

describe("Hermes process shell stop budget wiring", () => {
  it("uses subtracting deadlines for every exit-path bounded wait", () => {
    const source = readFileSync(PROCESS_SHELL, "utf8");
    const exitStart = source.indexOf("private async exitWhenDrained");
    const mainStart = source.indexOf("export async function hermesBridgeMain");
    const exitAndWriterPath = source.slice(
      source.indexOf("async endAndFlush"),
      mainStart,
    );
    const exitPath = source.slice(exitStart, mainStart);

    expect(exitPath).toContain("drainTailDeadline");
    expect(exitPath).toContain("exitDeadline");
    expect(exitPath.match(/performance\.now\(\)/gu) ?? []).toHaveLength(1);
    expect(exitPath).toContain("withDeadline(this.barrier?.release() ?? Promise.resolve(), exitDeadline)");
    expect(exitAndWriterPath).toContain("withDeadline");
    expect(exitAndWriterPath).not.toContain("withTimeout");
    expect(exitAndWriterPath).not.toMatch(/endAndFlush\([^)]*BOUND|endAndFlush\([^)]*MS/u);
  });

  it("keeps the summed stop budget under the relay grace", () => {
    expect(STOP_LATENCY_BUDGET_MS).toBe(DRAIN_TAIL_MS + BARRIER_RELEASE_BOUND_MS + EXIT_MARGIN_MS);
    expect(STOP_LATENCY_BUDGET_MS).toBeLessThanOrEqual(RELAY_CHILD_SIGTERM_GRACE_MS);
    expect(DRAIN_TAIL_MS + EXIT_MARGIN_MS).toBeLessThan(RELAY_CHILD_SIGTERM_GRACE_MS);
  });
});
