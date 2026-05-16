import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");

function source(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("critical audit follow-up classification", () => {
  it("keeps migrated critical call sites on appendCritical", () => {
    const expectations: Array<[string, RegExp]> = [
      ["src/principal-policy/gate.ts", /appendCritical\(\{[\s\S]*operation: `gate_injection_block/],
      ["src/principal-policy/gate.ts", /appendCritical\(\{[\s\S]*operation: `gate_allow_proxy/],
      ["src/principal-policy/gate.ts", /appendCritical\(\{[\s\S]*operation: `gate_allow:/],
      ["src/principal-policy/gate.ts", /appendCritical\(\{[\s\S]*operation: `gate_unclassified/],
      ["src/principal-policy/gate.ts", /appendCritical\(\{[\s\S]*operation: `gate_deny/],
      ["src/principal-policy/approval-aggregator.ts", /appendCritical\(\{[\s\S]*operation: APPROVAL_AGGREGATOR_AUDIT_OPS\.AGGREGATED/],
      ["src/principal-policy/approval-aggregator.ts", /appendCritical\(\{[\s\S]*operation: APPROVAL_AGGREGATOR_AUDIT_OPS\.RESOLVED/],
      ["src/principal-policy/dashboard.ts", /appendCritical\(\{[\s\S]*operation: "sovereignty_profile_update_dashboard"/],
      ["src/principal-policy/dashboard.ts", /appendCritical\(\{[\s\S]*operation: "proxy_servers_update_dashboard"/],
      ["src/sovereignty-profile-tools.ts", /appendCritical\(\{[\s\S]*operation: "sovereignty_profile_update"/],
      ["src/principal-policy/unified-inbox-producers.ts", /appendCritical\(\{[\s\S]*operation: PSI2_AUDIT_OPS\.CASTLE_WALL_BLOCKED_EGRESS/],
      ["src/proxy/proxy-router.ts", /appendCritical\(\{[\s\S]*operation: `proxy_injection_blocked/],
      ["src/proxy/proxy-router.ts", /appendCritical\(\{[\s\S]*operation: `proxy_governor_blocked/],
      ["src/proxy/proxy-router.ts", /appendCritical\(\{[\s\S]*operation: `proxy_privacy_denied/],
      ["src/proxy/proxy-router.ts", /appendCritical\(\{[\s\S]*operation: `proxy_call:/],
      ["src/bridge/tools.ts", /appendCritical\(\{[\s\S]*operation: "bridge_commit"/],
      ["src/bridge/tools.ts", /appendCritical\(\{[\s\S]*operation: "bridge_attest"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "reputation_record"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "reputation_export"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "reputation_import"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "bootstrap_create_escrow"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "bootstrap_provide_guarantee"/],
      ["src/l4-reputation/tools.ts", /appendCritical\(\{[\s\S]*operation: "reputation_publish"/],
      ["src/l3-disclosure/tools.ts", /appendCritical\(\{[\s\S]*operation: "proof_commitment"/],
      ["src/l3-disclosure/tools.ts", /appendCritical\(\{[\s\S]*operation: "disclosure_set_policy"/],
      ["src/l3-disclosure/tools.ts", /appendCritical\(\{[\s\S]*operation: "zk_commit"/],
      ["src/l3-disclosure/broker/broker.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.BACKEND_UNLOCKED/],
      ["src/l3-disclosure/broker/broker.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.SECRET_ADDED/],
      ["src/l3-disclosure/broker/broker.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.SECRET_ROTATED/],
      ["src/l3-disclosure/broker/broker.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.SECRET_DELETED/],
      ["src/l3-disclosure/broker/token-issuer.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.TOKEN_DENIED/],
      ["src/l3-disclosure/broker/token-issuer.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.TOKEN_ISSUED/],
      ["src/l3-disclosure/broker/token-issuer.ts", /appendCritical\(\{[\s\S]*operation: BROKER_OPS\.SECRET_READ/],
    ];

    for (const [path, pattern] of expectations) {
      expect(source(path), `${path} should route critical audit through appendCritical`).toMatch(pattern);
    }
  });

  it("leaves classified best-effort observations on append", () => {
    const expectations: Array<[string, RegExp]> = [
      ["src/principal-policy/gate.ts", /\.append\("l2", `injection_detected/],
      ["src/proxy/proxy-router.ts", /\.append\("l2", `proxy_injection_escalated/],
      ["src/proxy/proxy-router.ts", /\.append\("l2", `proxy_governor_cached/],
      ["src/bridge/tools.ts", /auditLog\.append\("l3", "bridge_verify"/],
      ["src/l4-reputation/tools.ts", /auditLog\.append\("l4", "reputation_query"/],
      ["src/l4-reputation/tools.ts", /auditLog\.append\("l4", "reputation_query_weighted"/],
      ["src/l3-disclosure/tools.ts", /auditLog\.append\("l3", "proof_reveal"/],
      ["src/l3-disclosure/tools.ts", /auditLog\.append\("l3", "disclosure_evaluate"/],
      ["src/principal-policy/tools.ts", /auditLog\.append\("l2", "principal_policy_view"/],
      ["src/principal-policy/tools.ts", /auditLog\.append\("l2", "principal_baseline_view"/],
      ["src/sovereignty-profile-tools.ts", /auditLog\.append\("l2", "sovereignty_profile_get"/],
      ["src/sovereignty-profile-tools.ts", /auditLog\.append\("l2", "sovereignty_profile_generate_prompt"/],
      ["src/principal-policy/unified-inbox-producers.ts", /auditLog\.append\("l2", PSI2_AUDIT_OPS\.QUERY_ANONYMITY_DAILY_AGGREGATED/],
    ];

    for (const [path, pattern] of expectations) {
      expect(source(path), `${path} should keep best-effort audit on append`).toMatch(pattern);
    }
  });
});
