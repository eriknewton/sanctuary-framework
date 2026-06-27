import { describe, expect, it } from "vitest";
import {
  listTierBAdapters,
  supervisorHarnessForTierBAdapter,
  TIER_B_ADAPTER_SUPERVISOR_HARNESSES,
  TIER_B_ADAPTER_WRAP_PLATFORMS,
  wrapPlatformForTierBAdapter,
} from "../../src/agent-contract/adapters/index.js";
import { LOCAL_HARNESS_KINDS } from "../../src/contracts/v1.1/local-agent-records.js";
import {
  parseRequest,
  SUPERVISOR_KNOWN_HARNESSES,
} from "../../src/supervisor/protocol.js";
import { harnessKindForPlatform, parseWrapArgs } from "../../src/wrap/cli.js";
import type { AgentPlatform } from "../../src/wrap/config-reader.js";

function sorted(values: Iterable<string>): string[] {
  return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function registeredTierBAdapterIds(): string[] {
  return listTierBAdapters().map((r) => r.id);
}

function selectedPlatforms(
  opts: ReturnType<typeof parseWrapArgs>,
): AgentPlatform[] {
  const selected: AgentPlatform[] = [];
  if (opts.openclaw) selected.push("openclaw");
  if (opts.hermes) selected.push("hermes");
  if (opts.claudeCode) selected.push("claude-code");
  if (opts.cursor) selected.push("cursor");
  if (opts.cline) selected.push("cline");
  if (opts.mastra) selected.push("mastra");
  return selected;
}

describe("harness registry parity", () => {
  it("derives the supervisor harness set from LocalHarnessKind", () => {
    expect(sorted(SUPERVISOR_KNOWN_HARNESSES)).toEqual(
      sorted(LOCAL_HARNESS_KINDS),
    );
  });

  it("maps every registered Tier B adapter to a supervisor-accepted harness", () => {
    const ids = sorted(registeredTierBAdapterIds());
    expect(ids).toEqual(sorted(Object.keys(TIER_B_ADAPTER_SUPERVISOR_HARNESSES)));

    for (const id of ids) {
      const harness = supervisorHarnessForTierBAdapter(id);
      expect(harness).toBeDefined();
      expect(SUPERVISOR_KNOWN_HARNESSES.has(harness!)).toBe(true);
      const parsed = parseRequest({
        kind: "protect",
        agent_id: `agent-${id}`,
        harness,
        config_path: `/tmp/${id}.json`,
        transient_key_b64: "AAAA",
      });
      expect(parsed?.kind).toBe("protect");
      if (parsed?.kind === "protect") {
        expect(parsed.harness).toBe(harness);
      }
    }
  });

  it("maps every registered Tier B adapter to a wrap platform with the same harness", () => {
    const ids = sorted(registeredTierBAdapterIds());
    expect(ids).toEqual(sorted(Object.keys(TIER_B_ADAPTER_WRAP_PLATFORMS)));

    for (const id of ids) {
      const platform = wrapPlatformForTierBAdapter(id);
      expect(platform).toBeDefined();
      expect(harnessKindForPlatform(platform!)).toBe(
        supervisorHarnessForTierBAdapter(id),
      );
      const parsed = parseWrapArgs([`--${platform}`]);
      expect(selectedPlatforms(parsed)).toEqual([platform]);
    }
  });
});
