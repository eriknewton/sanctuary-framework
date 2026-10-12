import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  HABEAS_DISTRESS_PORT,
  HABEAS_LOCAL_RULE_ID,
  isGenuineDerivedHabeasRule,
} from "../../../src/castle-wall/allowlist/habeas-port.js";
import {
  parseConfinedAgentId,
  validateLinuxInstallAgentIdScopes,
} from "../../../src/castle-wall/allowlist/confined-agent-id.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

const vectors = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../../../castle-wall-daemon/test-vectors/confined-agent-id-v1.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
) as { valid: string[]; invalid: string[] };

type RefusalVector = {
  name: string;
  kind: "malformed" | "wrong_uid";
  rule_id: string;
  agent_id: string;
  admitted_uid: number;
  expected: { shared: string };
};

const EXPECTED_REFUSAL_CASE_IDS = [
  "malformed_id",
  "wrong_uid",
  "malformed_quote_rule_and_agent_id",
  "malformed_backslash_rule_and_agent_id",
  "wrong_uid_quote_rule_id",
  "wrong_uid_backslash_rule_id",
  "long_rule_and_agent_id",
  "wrong_uid_long_rule_id",
  "rlo_id",
  "zero_width_space_id",
  "line_separator_id",
  "del_id",
  "nul_id",
  "astral_id",
  "long_escaped_id_truncates_after_escape",
] as const;

const refusalVectors = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../../../castle-wall-daemon/test-vectors/confined-agent-id-refusals-v1.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
) as { version: 1; cases: RefusalVector[] };

function rule(agentIds: string[], id = "linux-explicit-ip"): AllowlistRule {
  return {
    id,
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

  it("matches the shared full-refusal message vector set", () => {
    expect(refusalVectors.cases.map((vector) => vector.name)).toEqual([
      ...EXPECTED_REFUSAL_CASE_IDS,
    ]);
    for (const vector of refusalVectors.cases) {
      let message = "";
      try {
        validateLinuxInstallAgentIdScopes(
          [rule([vector.agent_id], vector.rule_id)],
          vector.admitted_uid,
        );
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message, vector.name).toBe(vector.expected.shared);
    }
  });

  it("refuses malformed install scopes before signing", () => {
    for (const agentId of ["0123456789abcdef/uid-60123", "", "uid-", "uid-01"]) {
      expect(() => validateLinuxInstallAgentIdScopes([rule([agentId])], 60123)).toThrow(
        `scope.agent_ids entry ${JSON.stringify(agentId)}: expected uid-<decimal uid>; re-sign with the uid-<uid> form`,
      );
    }
  });

  it("accepts only the admitted uid in install scopes", () => {
    expect(() => validateLinuxInstallAgentIdScopes([rule(["uid-60123"])], 60123)).not.toThrow();
    expect(() => validateLinuxInstallAgentIdScopes([rule(["uid-60124"])], 60123)).toThrow(
      `scope.agent_ids entry "uid-60124": expected admitted uid 60123; scope agent rules to uid-60123`,
    );
  });

  it("checks operator-authored rules that resemble the derived distress lane", () => {
    const derivedShapeWithOperatorScope: AllowlistRule = {
      id: HABEAS_LOCAL_RULE_ID,
      schema_version: 1,
      created_at: "2026-10-01T00:00:00Z",
      match: { ip: ["127.0.0.1", "::1"], port: [HABEAS_DISTRESS_PORT], protocol: "tcp" },
      scope: { agent_ids: ["uid-60124"] },
      disposition: "allow",
    };
    expect(isGenuineDerivedHabeasRule(derivedShapeWithOperatorScope)).toBe(false);
    expect(() =>
      validateLinuxInstallAgentIdScopes([derivedShapeWithOperatorScope], 60123),
    ).toThrow(
      `scope.agent_ids entry "uid-60124": expected admitted uid 60123; scope agent rules to uid-60123`,
    );
  });
});
