/**
 * Shared predicate for rule files that an agent-classified flow could match.
 *
 * The no-egress arm guard and the dashboard stop path must agree by
 * construction. Invalid or unreadable files evaluate false because the
 * enforcing daemon would reject that ruleset rather than grant egress.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { AllowlistRule } from "./schema.js";
import { validateRule } from "./schema.js";
import { HABEAS_RULE_ID_PREFIX } from "./habeas-port.js";

export function isAgentMatchableAllowRule(rule: AllowlistRule): boolean {
  if (validateRule(rule).length > 0) return false;
  if (rule.disposition !== "allow") return false;
  return !rule.id.startsWith(HABEAS_RULE_ID_PREFIX);
}

export async function isAgentMatchableAllowRuleFile(
  filePath: string,
): Promise<boolean> {
  try {
    const parsed = JSON.parse(await readFile(filePath, "utf8")) as AllowlistRule;
    return isAgentMatchableAllowRule(parsed);
  } catch {
    return false;
  }
}

export async function listAgentMatchableAllowRuleFiles(
  rulesDir: string,
  filenames: readonly string[],
): Promise<string[]> {
  const selected: string[] = [];
  for (const filename of filenames) {
    if (!filename.endsWith(".json")) continue;
    if (await isAgentMatchableAllowRuleFile(join(rulesDir, filename))) {
      selected.push(filename);
    }
  }
  return selected.sort();
}
