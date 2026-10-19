import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CHILD_READY_TIMEOUT_MS,
  RELAY_CHILD_EXIT_BOUND_MS,
  RELAY_CHILD_SIGTERM_GRACE_MS,
} from "../../src/hermes-memory-bridge/process-shell.js";
import { PROBE_REPLY_BOUND_MS } from "../../src/hermes-memory-bridge/constants.js";

const root = new URL("../../../", import.meta.url);
const swiftPath = "hermes-memory-relay/Sources/HermesMemoryRelayCore/Core.swift";

describe("relay runtime shared contracts", () => {
  it("relayStartupBudgetPinsNameRealSwiftDeclarations", async () => {
    const swift = await readFile(new URL(swiftPath, root), "utf8");
    const node = await readFile(new URL("server/src/hermes-memory-bridge/process-shell.ts", root), "utf8");
    const pairs = [
      ["childReadyTimeoutMilliseconds", CHILD_READY_TIMEOUT_MS],
      ["childSigtermGraceMilliseconds", RELAY_CHILD_SIGTERM_GRACE_MS],
      ["probeReplyBoundMilliseconds", PROBE_REPLY_BOUND_MS],
    ] as const;
    for (const [name, expected] of pairs) {
      const match = swift.match(new RegExp(`static let ${name} = ([0-9_]+)`));
      expect(match, name).not.toBeNull();
      expect(Number(match![1]!.replaceAll("_", "")), name).toBe(expected);
    }
    for (const name of ["childReadyTimeoutMilliseconds", "childSigtermGraceMilliseconds", "relayChildExitBoundMilliseconds"]) {
      expect(node).toContain(`Must match \`${name}\` in ${swiftPath}.`);
    }
    expect(swift).toContain("Must match CHILD_READY_TIMEOUT_MS in server/src/hermes-memory-bridge/process-shell.ts.");
    expect(swift).toContain("Must match RELAY_CHILD_SIGTERM_GRACE_MS in server/src/hermes-memory-bridge/process-shell.ts.");
    expect(swift).toContain("relayChildExitBoundMilliseconds = probeReplyBoundMilliseconds + childSigtermGraceMilliseconds");
    expect(RELAY_CHILD_EXIT_BOUND_MS).toBe(PROBE_REPLY_BOUND_MS + RELAY_CHILD_SIGTERM_GRACE_MS);
  });

  it("relayFixtureMatchesCanonicalSwiftBytes", async () => {
    const canonical = await readFile(new URL("hermes-memory-relay/Tests/HermesMemoryRelayCoreTests/Fixtures/relay-frames.json", root));
    const node = await readFile(fileURLToPath(new URL("./fixtures/relay-frames.json", import.meta.url)));
    expect(node.equals(canonical)).toBe(true);
  });
});
