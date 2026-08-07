import { randomUUID } from "node:crypto";
import { registerFixture } from "../../registry.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../../server/src/castle-wall/constants.js";
import {
  validateRule,
  type AllowlistRule,
} from "../../../../server/src/castle-wall/allowlist/schema.js";

// Recon: canonical admission schema gate is validateRule(), mirrored by
// server/test/castle-wall/allowlist/schema.test.ts. Maps to ASSURANCE row 9.
//
// HONEST BOUND: row 9 (Linux egress enforcement) is `not_implemented` in
// ASSURANCE_MATRIX.md as of 2026-08-07. These fixtures exercise the rule-schema
// admission gate plus the locally-modelled admitBoundary loop below; they do
// NOT reach the shipped castle-wall-daemon, which installs no nftables table,
// binds no NFQUEUE, creates no cgroup scope, and never calls the deny-by-default
// evaluator. A green row here is format and policy-shape coverage, never
// evidence that a Linux host is enforcing.
// Open defect: IC-02, IC-04 (docs/audit/inert-capability-register.md).
const CLAIM_ID = "9";
const CLAIM_LABEL = "Egress enforcement: Linux (Castle Wall Phase 1)";

interface AdmissionToken {
  tokenId: string;
  principalId: string;
  expiresAtMs: number;
}

const revokedPrincipals = new Set<string>();
const consumedTokens = new Set<string>();

function validRule(id = `rule-${randomUUID()}`): AllowlistRule {
  return {
    id,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-05-19T12:00:00.000Z",
    description: "synthetic boundary admission fixture",
    match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
  };
}

function admitBoundary(opts: {
  rule: AllowlistRule;
  token?: AdmissionToken;
  nowMs: number;
}): { admitted: boolean; reason?: string } {
  const schemaIssues = validateRule(opts.rule);
  if (schemaIssues.length > 0) {
    return { admitted: false, reason: "policy_validation_failed" };
  }
  if (!opts.token) {
    return { admitted: false, reason: "missing_token" };
  }
  if (opts.token.expiresAtMs <= opts.nowMs) {
    return { admitted: false, reason: "expired_token" };
  }
  if (revokedPrincipals.has(opts.token.principalId)) {
    return { admitted: false, reason: "revoked_principal" };
  }
  if (consumedTokens.has(opts.token.tokenId)) {
    return { admitted: false, reason: "replay_rejected" };
  }
  consumedTokens.add(opts.token.tokenId);
  return { admitted: true };
}

function token(overrides?: Partial<AdmissionToken>): AdmissionToken {
  return {
    tokenId: `token-${randomUUID()}`,
    principalId: "principal-operator",
    expiresAtMs: 2_000,
    ...overrides,
  };
}

function resetBoundaryState(): void {
  revokedPrincipals.clear();
  consumedTokens.clear();
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "boundary-admission: happy admit", async () => {
  const start = performance.now();
  resetBoundaryState();
  const result = admitBoundary({ rule: validRule(), token: token(), nowMs: 1_000 });
  return {
    passed: result.admitted === true,
    message: result.reason,
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "boundary-admission: deny on missing token", async () => {
  const start = performance.now();
  resetBoundaryState();
  const result = admitBoundary({ rule: validRule(), nowMs: 1_000 });
  return {
    passed: result.admitted === false && result.reason === "missing_token",
    message: result.reason,
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "boundary-admission: deny on expired token", async () => {
  const start = performance.now();
  resetBoundaryState();
  const result = admitBoundary({
    rule: validRule(),
    token: token({ expiresAtMs: 999 }),
    nowMs: 1_000,
  });
  return {
    passed: result.admitted === false && result.reason === "expired_token",
    message: result.reason,
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "boundary-admission: deny on revoked principal", async () => {
  const start = performance.now();
  resetBoundaryState();
  revokedPrincipals.add("principal-revoked");
  const result = admitBoundary({
    rule: validRule(),
    token: token({ principalId: "principal-revoked" }),
    nowMs: 1_000,
  });
  return {
    passed: result.admitted === false && result.reason === "revoked_principal",
    message: result.reason,
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "boundary-admission: replay rejection", async () => {
  const start = performance.now();
  resetBoundaryState();
  const reusable = token();
  const first = admitBoundary({ rule: validRule(), token: reusable, nowMs: 1_000 });
  const second = admitBoundary({ rule: validRule(), token: reusable, nowMs: 1_000 });
  return {
    passed:
      first.admitted === true &&
      second.admitted === false &&
      second.reason === "replay_rejected",
    message: second.reason,
    durationMs: performance.now() - start,
  };
});
