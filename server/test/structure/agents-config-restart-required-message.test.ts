/**
 * Operator guidance after a policy configuration change states the truth
 * about when the change takes effect, consistent with the policy layer's
 * load-once-and-freeze design (AGENTS.md MUST-NEVER #7). This structure
 * test pins the current wording and the absence of the retired phrasing
 * so a future edit cannot silently reintroduce it.
 *
 * Private register: ic-sweep-policy-config-live-reload-honest.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

// The false claim, in every phrasing it appeared in across the swept
// surfaces. None of these substrings may appear anywhere in the files this
// test covers — a partial match ("next request" without "gate") still
// carries the same false promise.
const RETIRED_PHRASES = [
  "next gate request",
  "no restart required for running servers",
  "without a server restart on the next request",
  "so policy edits take effect on the next request",
  "reflected on the next approval",
  "without restarting the server",
] as const;

const CLI_PATH = "server/src/cli/agents/cli.ts";
const AGGREGATOR_CHANNEL_PATH =
  "server/src/principal-policy/channels/aggregator-backed-channel.ts";
const INDEX_PATH = "server/src/index.ts";

describe("IC-26: agents config restart-required message is honest", () => {
  it("prints the restart-required message, not the next-request claim, at the CLI call site", () => {
    const source = read(CLI_PATH);
    expect(source).toContain(
      "Persisted. Takes effect after this tenant's Sanctuary server process is stopped and started again",
    );
    expect(source).toContain("a running server keeps the policy it booted with");
  });

  it("carries the MUST-NEVER #7 invariant comment at the CLI message site", () => {
    const source = read(CLI_PATH);
    const anchor = "Persisted. Takes effect after this tenant";
    const index = source.indexOf(anchor);
    expect(index).toBeGreaterThanOrEqual(0);
    const window = source.slice(Math.max(0, index - 700), index);
    expect(window).toContain("MUST-NEVER #7");
    expect(window).toContain("IC-26");
  });

  it("states the restart requirement in the config verb's doc-comment header", () => {
    const source = read(CLI_PATH);
    expect(source).toContain(
      "Takes effect only after the tenant's Sanctuary server",
    );
    expect(source).toContain("MUST-NEVER");
  });

  it("never repeats the retired next-request/no-restart phrasing anywhere in the swept surfaces", () => {
    const surfaces: Array<[string, string]> = [
      [CLI_PATH, read(CLI_PATH)],
      [AGGREGATOR_CHANNEL_PATH, read(AGGREGATOR_CHANNEL_PATH)],
      [INDEX_PATH, read(INDEX_PATH)],
    ];
    for (const [path, source] of surfaces) {
      for (const phrase of RETIRED_PHRASES) {
        expect(
          source.includes(phrase),
          `${path} still contains the retired phrase: "${phrase}"`,
        ).toBe(false);
      }
    }
  });

  it("aggregator-backed-channel.ts documents the freeze instead of a hot-reload promise", () => {
    const source = read(AGGREGATOR_CHANNEL_PATH);
    expect(source).toContain("MUST-NEVER #7");
    expect(source.match(/MUST-NEVER #7/g)?.length ?? 0).toBeGreaterThanOrEqual(3);
  });

  it("index.ts's wire-up comment documents the freeze instead of a hot-reload promise", () => {
    const source = read(INDEX_PATH);
    const anchor = "wrap the approval channel with the";
    const index = source.indexOf(anchor);
    expect(index).toBeGreaterThanOrEqual(0);
    const window = source.slice(index, index + 900);
    expect(window).toContain("MUST-NEVER #7");
    expect(window).toContain("restarted");
  });
});
