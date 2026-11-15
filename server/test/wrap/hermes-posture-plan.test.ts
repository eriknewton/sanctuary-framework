import { describe, expect, it } from "vitest";
import { planHermesMemoryPosture, planHermesMemoryRevert } from "../../src/wrap/hermes-yaml.js";
import { HERMES_POSTURE_SETTINGS } from "../../src/wrap/hermes-posture.js";
const plan = (text: string | null) => planHermesMemoryPosture(text, HERMES_POSTURE_SETTINGS);
const fresh = "memory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\nplugins:\n  enabled: [sanctuary]\n";
export const refusedShapes = [
  ["duplicate top-level keys", "model: one\nmodel: two\n"],
  ["memory flow mapping", "memory: {provider: old}\n"],
  ["memory scalar", "memory: yes\n"],
  ["plugins flow mapping", "plugins: {enabled: []}\n"],
  ["plugins scalar", "plugins: yes\n"],
  ["nested managed value", "memory:\n  provider:\n    nested: value\n"],
  ["literal managed value", "memory:\n  provider: |\n    text\n"],
  ["folded managed value", "memory:\n  provider: >\n    text\n"],
  ["managed anchor", "memory:\n  provider: &name old\n"],
  ["managed alias", "memory:\n  provider: *name\n"],
  ["managed tag", "memory:\n  provider: !!str old\n"],
  ["enabled scalar", "plugins:\n  enabled: sanctuary\n"],
  ["enabled mapping", "plugins:\n  enabled:\n    sanctuary: true\n"],
  ["enabled nested sequence", "plugins:\n  enabled:\n    - [other]\n"],
  ["enabled multiline flow", "plugins:\n  enabled: [other,\n    sanctuary]\n"],
  ["enabled anchor", "plugins:\n  enabled: &items [other]\n"],
  ["disabled sanctuary", "plugins:\n  disabled: [sanctuary]\n"],
  ["hard stop", "tool_loop_guardrails:\n  hard_stop_enabled: true\n"],
  ["memory indentless sequence", "memory:\n- provider\n"],
  ["plugins indentless sequence", "plugins:\n- enabled\n"],
  ["scalar followed by indentless item", "model: one\n- two\n"],
  ["document is a sequence", "- one\nmemory:\n  provider: old\n"],
  ["document starts with a bare item", "-\nmemory:\n  provider: old\n"],
  ["guardrails indentless sequence", "tool_loop_guardrails:\n- hard_stop_enabled\n"],
  ["anchor followed by indentless item", "toolsets: &a\n- web\n"],
  ["empty MCP flow followed by item", "mcp_servers: {}\n- weather\n"],
  ["line separator hides a key", "toolsets:\n- web\u2028memory:\n  provider: old\n"],
  ["no-break space after a dash", "toolsets:\n-\u00a0web: x\n"],
] as const;

describe("Hermes memory YAML planner", () => {
  it.each([
    ["config absent", null, fresh],
    ["blocks absent", "# keep\nmodel: fixture\n", "# keep\nmodel: fixture\n" + fresh],
    ["empty blocks", "memory: {} # memory\nplugins: {} # plugins\n", "memory:  # memory\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\nplugins:  # plugins\n  enabled: [sanctuary]\n"],
    ["values replaced", "memory:\n    provider: old # owner\n    memory_enabled: true\n    user_profile_enabled: true\n    memory_char_limit: 3000\n# tail\nplugins:\n  enabled: [other_plugin] # keep\n", "memory:\n    provider: sanctuary_memory # owner\n    memory_enabled: false\n    user_profile_enabled: false\n    memory_char_limit: 3000\n# tail\nplugins:\n  enabled: [other_plugin, sanctuary] # keep\n"],
    ["block sequence", "plugins:\n  enabled:\n    - other_plugin\n# end\n", "plugins:\n  enabled:\n    - other_plugin\n    - sanctuary\n# end\nmemory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\n"],
    ["indentless block sequence", "plugins:\n  enabled:\n  - other_plugin\n", "plugins:\n  enabled:\n  - other_plugin\n  - sanctuary\nmemory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\n"],
    ["empty flow list", "plugins:\n  enabled: []\n", "plugins:\n  enabled: [sanctuary]\nmemory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\n"],
    ["empty MCP block", "mcp_servers:\n  sanctuary:\n    command: old\n", "mcp_servers: {}\n" + fresh],
    ["MCP header comment", "mcp_servers: # preserved\n  sanctuary:\n    command: old\n", "mcp_servers: {} # preserved\n" + fresh],
    ["other MCP kept", "mcp_servers:\n  sanctuary:\n    command: old\n  weather:\n    command: weather\n", "mcp_servers:\n  weather:\n    command: weather\n" + fresh],
    ["already installed", fresh, fresh],
    // PyYAML's default dump, which Hermes writes: top-level lists are not indented.
    ["indentless top-level lists kept", "fallback_providers:\n- provider: one\n  model: m1\n- provider: two\ntoolsets:\n- web\n-\ncommand_allowlist:\n- execute_code # keep\n# between\n- script execution\nmemory:\n  provider: old\n", "fallback_providers:\n- provider: one\n  model: m1\n- provider: two\ntoolsets:\n- web\n-\ncommand_allowlist:\n- execute_code # keep\n# between\n- script execution\nmemory:\n  provider: sanctuary_memory\n  memory_enabled: false\n  user_profile_enabled: false\nplugins:\n  enabled: [sanctuary]\n"],
  ])("%s", (_name, input, expected) => {
    const result = plan(input);
    expect(result.content).toBe(expected);
    expect(plan(result.content).content).toBe(expected);
  });
  it.each(refusedShapes)("refuses %s", (_name, input) => {
    expect(() => plan(input)).toThrow();
  });
  it("indentless lists never become top-level keys and removal restores them byte for byte", () => {
    const original = "toolsets:\n- web\n- terminal\nmemory:\n  provider: old\nmcp_servers:\n  sanctuary:\n    command: old\ncommand_allowlist:\n- execute_code\n";
    const result = plan(original);
    expect(result.before.top).toEqual(["toolsets", "memory", "mcp_servers", "command_allowlist"]);
    expect(planHermesMemoryRevert(result.content, original, result.content).content)
      .toBe("toolsets:\n- web\n- terminal\nmemory:\n  provider: old\nmcp_servers: {}\ncommand_allowlist:\n- execute_code\n");
  });
  it("records removed MCP bytes including their terminating newline", () => {
    expect(plan("mcp_servers:\n  sanctuary:\n    command: old\n").removedMcp)
      .toBe("  sanctuary:\n    command: old\n");
  });
  it("changed removal keeps unrelated bytes and does not add the MCP entry", () => {
    const original = "memory:\n  provider: prior # keep\nplugins:\n  enabled: [other]\nmcp_servers:\n  sanctuary:\n    command: old\n";
    const installed = plan(original).content;
    expect(planHermesMemoryRevert(installed + "new_key: value\n", original, installed).content).toBe(
      "memory:\n  provider: prior # keep\nplugins:\n  enabled: [other]\nmcp_servers: {}\nnew_key: value\n");
  });
  it("changed comments keep their bytes while matching managed values revert", () => {
    const original = "memory:\n  provider: old # original\n  memory_enabled: true # original\n";
    const installed = plan(original).content;
    const live = installed.replace("sanctuary_memory # original", '\"sanctuary_memory\" # edited').replace("false # original", "false # edited");
    expect(planHermesMemoryRevert(live, original, installed).content).toBe(
      "memory:\n  provider: old # edited\n  memory_enabled: true # edited\n");
  });
  it("removal restores a prior flow list after equivalent block formatting", () => {
    const original = "plugins:\n  enabled: [other]\n";
    const installed = plan(original).content;
    const live = installed.replace("  enabled: [other, sanctuary]", "  enabled: # edited\n    - other\n    - sanctuary");
    expect(planHermesMemoryRevert(live, original, installed).content).toBe(
      "plugins:\n  enabled: [other] # edited\n");
  });
  it("changed managed value remains the operator's value", () => {
    expect(planHermesMemoryRevert(fresh.replace("provider: sanctuary_memory", "provider: chosen"), null, fresh).content)
      .toBe("memory:\n  provider: chosen\n");
  });
});
