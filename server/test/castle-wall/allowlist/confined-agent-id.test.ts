import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  parseConfinedAgentId,
  validateLinuxInstallAgentIdScopes,
} from "../../../src/castle-wall/allowlist/confined-agent-id.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

const vectors = JSON.parse(
  readFileSync("../castle-wall-daemon/test-vectors/confined-agent-id-v1.json", "utf8"),
) as { valid: string[]; invalid: string[] };

function rule(agentIds: string[]): AllowlistRule {
  return {
    id: "linux-explicit-ip",
    schema_version: 1,
    created_at: "2026-10-01T00:00:00Z",
    match: { ip: ["203.0.113.10"], port: [443], protocol: "tcp" },
    scope: { agent_ids: agentIds },
    disposition: "allow",
  };
}

describe("confined agent id form", () => {
  it("matches the shared Rust and TypeScript vector set", () => {
    expect(vectors.valid.map((id) => [id, parseConfinedAgentId(id) !== null])).toEqual(
      vectors.valid.map((id) => [id, true]),
    );
    expect(vectors.invalid.map((id) => [id, parseConfinedAgentId(id) !== null])).toEqual(
      vectors.invalid.map((id) => [id, false]),
    );
  });

  it("refuses malformed install scopes before signing", () => {
    for (const agentId of ["0123456789abcdef/uid-60123", "", "uid-", "uid-01"]) {
      expect(() => validateLinuxInstallAgentIdScopes([rule([agentId])], 60123)).toThrow(
        `scope.agent_ids entry ${JSON.stringify(agentId)}: expected uid-<decimal uid>`,
      );
    }
  });

  it("accepts only the admitted uid in install scopes", () => {
    expect(() => validateLinuxInstallAgentIdScopes([rule(["uid-60123"])], 60123)).not.toThrow();
    expect(() => validateLinuxInstallAgentIdScopes([rule(["uid-60124"])], 60123)).toThrow(
      `scope.agent_ids entry "uid-60124": expected admitted uid 60123`,
    );
  });
});
