/**
 * Hostile-fixture suite for governance.yaml parse + recursively-closed schema
 * (design §3.1, §3.2a; RFC §4.1a, §8). Every rejection asserts the NAMED reason.
 */

import { describe, it, expect } from "vitest";

import { parseGovernance, governanceHash, SubstrateError } from "../../src/substrate/index.js";

function expectReject(text: string, reason: string, hostSelectors: string[] = []) {
  try {
    parseGovernance(text, hostSelectors);
    throw new Error("expected rejection but none thrown");
  } catch (e) {
    expect(e, `expected SubstrateError for reason ${reason}, got ${String(e)}`).toBeInstanceOf(SubstrateError);
    expect((e as SubstrateError).reason).toBe(reason);
  }
}

const VALID = `
plugin_id: ai.example.blocklist
version: 1.0.0
channel: stable
entry: bin/blocklist
hooks:
  - hook_class: egress_decision
    fields:
      - egress.host
      - egress.port
    fail_mode: deny
endpoints: []
signal_keys:
  - blocked_count
`;

describe("parseGovernance — happy path", () => {
  it("parses a valid egress blocklist manifest", () => {
    const g = parseGovernance(VALID);
    expect(g.plugin_id).toBe("ai.example.blocklist");
    expect(g.hooks[0]!.hook_class).toBe("egress_decision");
    expect(g.hooks[0]!.fail_mode).toBe("deny");
    expect(g.signal_keys).toEqual(["blocked_count"]);
  });

  it("governanceHash is deterministic and stable across logically-identical parses", () => {
    const g1 = parseGovernance(VALID);
    const reordered = `
version: 1.0.0
plugin_id: ai.example.blocklist
channel: stable
entry: bin/blocklist
signal_keys:
  - blocked_count
endpoints: []
hooks:
  - hook_class: egress_decision
    fail_mode: deny
    fields:
      - egress.host
      - egress.port
`;
    const g2 = parseGovernance(reordered);
    expect(governanceHash(g1)).toBe(governanceHash(g2));
  });
});

describe("parseGovernance — closed schema (unknown keys reject)", () => {
  it("rejects an unknown top-level key", () => {
    expectReject(VALID + "\nrogue: value\n", "unknown_top_level_key");
  });

  it("rejects an unknown NESTED key inside a hook (recursive closure)", () => {
    const text = `
plugin_id: ai.example.blocklist
version: 1.0.0
channel: stable
entry: bin/blocklist
hooks:
  - hook_class: egress_decision
    fields:
      - egress.host
    fail_mode: deny
    sneaky_nested: true
`;
    expectReject(text, "unknown_nested_key");
  });

  it("rejects an unknown nested key inside an endpoint", () => {
    const text = `
plugin_id: ai.example.det
version: 1.0.0
channel: stable
entry: bin/det
hooks:
  - hook_class: egress_decision
    fields:
      - egress.host
    fail_mode: deny
endpoints:
  - host: api.vendor.com
    port: 443
    data_class: low
    extra_key: leak
`;
    expectReject(text, "unknown_nested_key");
  });
});

describe("parseGovernance — security rules", () => {
  it("rejects a field not in the host closed allowlist (Never-tier/unknown)", () => {
    const text = `
plugin_id: ai.example.det
version: 1.0.0
channel: stable
entry: bin/det
hooks:
  - hook_class: egress_decision
    fields:
      - master_key
    fail_mode: deny
`;
    expectReject(text, "unknown_nested_key");
  });

  it("rejects a fail-open fail-mode on an enforcement hook", () => {
    const text = `
plugin_id: ai.example.det
version: 1.0.0
channel: stable
entry: bin/det
hooks:
  - hook_class: egress_decision
    fields:
      - egress.host
    fail_mode: no_objection
`;
    expectReject(text, "fail_open_enforcement_fail_mode");
  });

  it("rejects an endpoint missing its data_class", () => {
    const text = `
plugin_id: ai.example.det
version: 1.0.0
channel: stable
entry: bin/det
hooks:
  - hook_class: egress_decision
    fields:
      - egress.host
    fail_mode: deny
endpoints:
  - host: api.vendor.com
    port: 443
`;
    expectReject(text, "undeclared_data_class_endpoint");
  });

  it("rejects an arguments_fields request whose selector is not host-allowlisted", () => {
    const text = `
plugin_id: ai.example.policy
version: 1.0.0
channel: stable
entry: bin/policy
hooks:
  - hook_class: policy_decision
    fields:
      - tool_name
      - arguments_fields
    fail_mode: escalate
    argument_selectors:
      - /secret/path
`;
    expectReject(text, "undeclared_field_selector", ["/url"]);
  });

  it("accepts a host-allowlisted argument selector", () => {
    const text = `
plugin_id: ai.example.policy
version: 1.0.0
channel: stable
entry: bin/policy
hooks:
  - hook_class: policy_decision
    fields:
      - tool_name
      - arguments_fields
    fail_mode: escalate
    argument_selectors:
      - /url
`;
    const g = parseGovernance(text, ["/url", "/headers/host"]);
    expect(g.hooks[0]!.argument_selectors).toEqual(["/url"]);
  });

  it("rejects an invalid plugin id", () => {
    const text = VALID.replace("ai.example.blocklist", "Not_A_DNS_Id");
    expectReject(text, "invalid_plugin_id");
  });

  it("rejects an over-size manifest", () => {
    const huge = VALID + "\n# pad" + "x".repeat(300 * 1024);
    expectReject(huge, "manifest_too_large");
  });

  it("rejects a __proto__ top-level key smuggling required fields (codex HIGH regression)", () => {
    // The exact exploit codex proved: a governance file whose only top-level key is
    // __proto__ containing plugin_id/version/etc. must NOT be accepted via prototype.
    const exploit = `__proto__:
  plugin_id: ai.example.proto
  version: 1.0.0
  channel: stable
  entry: bin/x
  hooks:
    - hook_class: egress_decision
      fields:
        - egress.host
      fail_mode: deny
`;
    expectReject(exploit, "yaml_non_string_key");
  });

  it("rejects an entry path with a backslash/traversal (self-contained path validation)", () => {
    const text = VALID.replace("entry: bin/blocklist", "entry: ..\\\\escape");
    expectReject(text, "bundle_path_traversal");
  });
});
