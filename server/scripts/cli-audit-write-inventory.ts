/**
 * CLI audit-write completeness inventory.
 *
 * Walks every CLI surface under server/src/cli/ (and the top-level cli.ts
 * for surfaces routed there: exit, honeypot, wrap, compliance,
 * template) and classifies each subcommand as:
 *
 *   - mutator:   changes fortress state (identity, policy, subscriptions,
 *                tasks, secrets, audit chain, keys, files, config).
 *   - read-only: pure read, no persistent state change.
 *   - pure-ui:   --help, --version, usage text.
 *
 * For each mutator, the script checks whether the handler (or any function
 * it delegates to in the same file) calls into an audit-emitting code path.
 *
 * Output: JSON array to stdout. Also writes structured output to
 * server/scripts/cli-audit-write-inventory.output.json and a markdown
 * summary to server/scripts/cli-audit-write-inventory.summary.md.
 *
 * ZZZZZ batch 5a prep. Fixes ship in batch 5b.
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

// ---- Types ----------------------------------------------------------------

interface InventoryEntry {
  subcommand: string;
  file_path: string;
  line_number: number;
  classification: "mutator" | "read-only" | "pure-ui";
  audits_currently: boolean | null;
  notes: string;
}

// ---- File discovery -------------------------------------------------------

const SERVER_SRC = resolve(import.meta.dirname ?? ".", "..", "src");
const CLI_DIR = join(SERVER_SRC, "cli");
const PROJECT_ROOT = resolve(SERVER_SRC, "..");

function collectTsFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectTsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      results.push(full);
    }
  }
  return results;
}

// ---- Audit-emit detection -------------------------------------------------

function fileHasAuditEmit(content: string): boolean {
  const hasAuditLogImport = /import.*AuditLog/.test(content);
  const hasAppendOrFlush = /\.append\(|\.flush\(/.test(content);
  if (hasAuditLogImport && hasAppendOrFlush) return true;
  if (/DID_WEB_AUDIT_OPS/.test(content) && hasAppendOrFlush) return true;
  return false;
}

function handlerDelegatesToBroker(content: string): boolean {
  return /broker\.\w+Secret\b/.test(content) || /broker\.grant\b/.test(content) ||
    /broker\.revoke\b/.test(content) || /broker\.queryAudit\b/.test(content);
}

// ---- Classification table -------------------------------------------------
// Explicit classification for every known CLI subcommand. This is more
// reliable than heuristic verb matching.

interface CommandSpec {
  classification: "mutator" | "read-only" | "pure-ui";
  /** If mutator, does this handler currently emit audit entries? */
  auditOverride?: boolean;
  notes?: string;
}

/**
 * Canonical classification of every CLI subcommand. Key is the full
 * subcommand string (e.g. "task create"). Classification is based on
 * manual code review of each handler.
 */
const COMMAND_TABLE: Record<string, CommandSpec> = {
  // ---- task (dashboard-delegated; audits server-side) ----
  "task create":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },
  "task list":    { classification: "read-only" },
  "task show":    { classification: "read-only" },
  "task update":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated PATCH (audits server-side)" },
  "task assign":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },
  "task cancel":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },

  // ---- secrets (broker-delegated; broker audits internally) ----
  "secrets add":    { classification: "mutator", auditOverride: true, notes: "broker-delegated (broker audits internally)" },
  "secrets list":   { classification: "read-only" },
  "secrets rotate": { classification: "mutator", auditOverride: true, notes: "broker-delegated (broker audits internally)" },
  "secrets delete": { classification: "mutator", auditOverride: true, notes: "broker-delegated (broker audits internally)" },
  "secrets grant":  { classification: "mutator", auditOverride: true, notes: "broker-delegated (broker audits internally)" },
  "secrets revoke": { classification: "mutator", auditOverride: true, notes: "broker-delegated (broker audits internally)" },
  "secrets audit":  { classification: "read-only" },

  // ---- sentinel ----
  "sentinel list":           { classification: "read-only" },
  "sentinel list-subscribed": { classification: "read-only" },
  "sentinel subscribe":      { classification: "mutator", auditOverride: true, notes: "AuditLog.append in subscribe handler (ZZZZZ batch 5b)" },
  "sentinel unsubscribe":    { classification: "mutator", auditOverride: true, notes: "AuditLog.append in unsubscribe handler (ZZZZZ batch 5b)" },
  "sentinel findings":       { classification: "read-only" },

  // ---- anomaly ----
  "anomaly detectors":       { classification: "read-only" },
  "anomaly list-subscribed": { classification: "read-only" },
  "anomaly subscribe":       { classification: "mutator", auditOverride: true, notes: "AuditLog.append in subscribe handler (ZZZZZ batch 5b)" },
  "anomaly unsubscribe":     { classification: "mutator", auditOverride: true, notes: "AuditLog.append in unsubscribe handler (ZZZZZ batch 5b)" },
  "anomaly findings":        { classification: "read-only" },
  "anomaly classifier-state": { classification: "read-only" },

  // ---- erc8004 ----
  "erc8004 register":        { classification: "mutator", auditOverride: true, notes: "AuditLog.append via handleErc8004Request (PR 3)" },
  "erc8004 status":          { classification: "read-only" },

  // ---- did-web ----
  "did-web issue":           { classification: "mutator", auditOverride: true, notes: "AuditLog.append in issue handler (ZZZZZ batch 5b)" },
  "did-web show":            { classification: "read-only" },
  "did-web rotate-key":      { classification: "mutator", auditOverride: true, notes: "AuditLog.append + flush in rotate-key handler" },
  "did-web key-history":     { classification: "read-only" },
  "did-web register-hosted": { classification: "mutator", auditOverride: true, notes: "AuditLog.append + flush in register-hosted handler" },

  // ---- auto-trigger rules (nested subcommands) ----
  "auto-trigger rules list":          { classification: "read-only" },
  "auto-trigger rules show":          { classification: "read-only" },
  "auto-trigger rules promote":       { classification: "mutator", auditOverride: true, notes: "AuditLog.append with before/after rung (ZZZZZ batch 5b)" },
  "auto-trigger rules demote":        { classification: "mutator", auditOverride: true, notes: "AuditLog.append with before/after rung (ZZZZZ batch 5b)" },
  "auto-trigger rules set-threshold": { classification: "mutator", auditOverride: true, notes: "AuditLog.append with before/after threshold values (ZZZZZ batch 5b)" },

  // ---- auto-trigger recommendations (nested) ----
  "auto-trigger recommendations list":   { classification: "read-only" },
  "auto-trigger recommendations show":   { classification: "read-only" },
  "auto-trigger recommendations accept": { classification: "mutator", auditOverride: true, notes: "AuditLog.append with recommendation detail (ZZZZZ batch 5b)" },
  "auto-trigger recommendations reject": { classification: "mutator", auditOverride: true, notes: "AuditLog.append with suppression detail (ZZZZZ batch 5b)" },

  // ---- auto-trigger cancel ----
  "auto-trigger cancel": { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },

  // ---- identity ----
  "identity show": { classification: "read-only" },

  // ---- file-grant (Governed File-Grant v1, 2026-07-07) ----
  "file-grant mint":   { classification: "mutator", auditOverride: true, notes: "AuditLog.appendCritical in mintFileGrant (success and rolled-back-failure paths); reconciles expired grants on this touch" },
  // R3-2: `list` was misclassified as read-only. `cmdList` calls
  // `reconcileFileGrantTree` before listing -- a safe-direction MUTATOR side
  // effect (scrubs expired tree entries, flips expired status, emits
  // `file_grant_revoke`/`expired_ttl_scrub` audits) -- so it is not purely a
  // read. It also still emits its own `file_grant_list` access audit.
  "file-grant list":   { classification: "mutator", auditOverride: true, notes: "safe-direction mutator: calls reconcileFileGrantTree before listing (scrubs expired tree entries, flips expired status, emits file_grant_revoke/expired_ttl_scrub audits); also emits its own file_grant_list access audit (Tier-3 auto-allow + audit, recordFileGrantListAudit)" },
  "file-grant revoke": { classification: "mutator", auditOverride: true, notes: "AuditLog.appendCritical in revokeFileGrant (success, not-found, and scrub-failure paths); reconciles expired grants on this touch" },

  // ---- intelligence ----
  "intelligence diagnose": { classification: "read-only" },

  // ---- inbox (dashboard-delegated; audits server-side) ----
  "inbox list":    { classification: "read-only" },
  "inbox show":    { classification: "read-only" },
  "inbox archive": { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },
  "inbox dismiss": { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },
  "inbox snooze":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },
  "inbox retention show": { classification: "read-only" },
  "inbox retention set":  { classification: "mutator", auditOverride: true, notes: "dashboard-delegated PATCH (audits server-side)" },
  "inbox approvals list":    { classification: "read-only" },
  "inbox approvals approve": { classification: "mutator", auditOverride: true, notes: "dashboard-delegated POST (audits server-side)" },

  // ---- policy ----
  "policy compile":              { classification: "read-only", notes: "stateless preview, no fortress state change" },
  "policy drafts list":          { classification: "read-only" },
  "policy drafts show":          { classification: "read-only" },
  "policy drafts check-conflicts": { classification: "read-only", notes: "queries server for conflicts, no state change" },
  "policy drafts activate":      { classification: "mutator", auditOverride: true, notes: "AuditLog.append before HTTP POST + failure audit (ZZZZZ batch 5b)" },

  // ---- concierge ----
  "concierge ask":    { classification: "read-only" },
  "concierge status": { classification: "read-only" },

  // ---- agents ----
  "agents list":   { classification: "read-only" },
  "agents show":   { classification: "read-only" },
  "agents status": { classification: "read-only" },
  "agents config": { classification: "mutator", auditOverride: true, notes: "AuditLog.append with before/after approval_redirect (ZZZZZ batch 5b)" },

  // ---- audit-chain (the export and verify surfaces) ----
  "audit-chain export": { classification: "read-only", notes: "exports chain data, no state change" },
  "audit-chain verify": { classification: "read-only", notes: "standalone verifier, no state change" },

  // ---- reset-passphrase ----
  "reset-passphrase nuke": { classification: "mutator", auditOverride: false, notes: "destroys fortress (audit log destroyed too)" },

  // ---- exit ----
  "exit export":        { classification: "mutator", auditOverride: true, notes: "AuditLog.append in exit export handler" },
  "exit verify":        { classification: "read-only" },
  "exit import":        { classification: "mutator", auditOverride: true, notes: "AuditLog.append in exit import handler" },
  "exit manifest-shape": { classification: "read-only" },

  // ---- honeypot ----
  "honeypot compile":          { classification: "read-only" },
  "honeypot deploy":           { classification: "mutator", auditOverride: true, notes: "AuditLog.append in honeypot deploy" },
  "honeypot list":             { classification: "read-only" },
  "honeypot tool-traps":       { classification: "read-only" },
  "honeypot credential-traps": { classification: "read-only" },
  "honeypot undeploy":         { classification: "mutator", auditOverride: true, notes: "AuditLog.append in honeypot undeploy" },
  "honeypot findings":         { classification: "read-only" },

  // ---- template ----
  "template list": { classification: "read-only" },
  "template init": { classification: "mutator", auditOverride: true, notes: "AuditLog.append with template + agent detail (ZZZZZ batch 5b)" },
};

// ---- Subcommand extraction ------------------------------------------------

interface SubcommandInfo {
  subcommand: string;
  file_path: string;
  line_number: number;
}

function deriveParentCommand(filePath: string): string | null {
  const base = filePath.replace(/\.ts$/, "");
  if (base.endsWith("cli/task")) return "task";
  if (base.endsWith("cli/secrets")) return "secrets";
  if (base.endsWith("cli/sentinel")) return "sentinel";
  if (base.endsWith("cli/anomaly")) return "anomaly";
  if (base.endsWith("cli/erc8004")) return "erc8004";
  if (base.endsWith("cli/did-web")) return "did-web";
  if (base.endsWith("cli/auto-trigger")) return "auto-trigger";
  if (base.endsWith("cli/identity")) return "identity";
  if (base.endsWith("cli/file-grant")) return "file-grant";
  if (base.endsWith("cli/intelligence")) return "intelligence";
  if (base.endsWith("cli/inbox")) return "inbox";
  if (base.endsWith("cli/policy")) return "policy";
  if (base.endsWith("cli/concierge")) return "concierge";
  if (base.endsWith("cli/agents/cli")) return "agents";
  if (base.endsWith("cli/reset-passphrase")) return "reset-passphrase";
  if (base.endsWith("cli/audit-chain-export")) return "audit-chain";
  if (base.endsWith("cli/audit-chain-verify")) return "audit-chain";
  if (base.endsWith("exit/cli")) return "exit";
  if (base.endsWith("honeypot/cli")) return "honeypot";
  if (base.endsWith("templates/cli")) return "template";
  // Skip wrap/cli, compliance cli - they parse flags in case statements
  return null;
}

/**
 * Verbs that appear inside nested switch blocks (e.g. inside cmdRules or
 * cmdRecommendations in auto-trigger.ts). These are NOT top-level subcommands;
 * they are handled by the nestedToAdd list below. Skip them during extraction
 * to avoid creating duplicate "auto-trigger list" entries that shadow the
 * real "auto-trigger rules list" entries.
 */
const NESTED_LEAF_VERBS: Record<string, Set<string>> = {
  "auto-trigger": new Set([
    "list", "show", "accept", "reject", "promote", "demote", "set-threshold",
  ]),
  "inbox": new Set(["list", "approve", "show", "set"]),
  "policy": new Set(["list", "show", "check-conflicts", "activate"]),
};

function extractSubcommands(filePath: string, content: string, parentCommand: string): SubcommandInfo[] {
  const results: SubcommandInfo[] = [];
  const lines = content.split("\n");
  const relPath = relative(PROJECT_ROOT, filePath);
  const nestedSkip = NESTED_LEAF_VERBS[parentCommand];

  // Pattern 1: switch/case blocks - only in the MAIN dispatcher switch
  const caseRegex = /^\s*case\s+["']([^"']+)["']\s*:/;
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i]!.match(caseRegex);
    if (!match) continue;
    const verb = match[1]!;
    if (verb.startsWith("-")) continue;
    if (["keychain", "fallback-file", "not-initialized"].includes(verb)) continue;
    if (["openclaw", "hermes", "claude-code", "cursor", "cline", "generic"].includes(verb) &&
        parentCommand === "wrap") continue;
    // R3-2: this scanner is a line-scanner, not a parser -- it matches every
    // `case "..."` in the file, not only the ones in the top-level dispatcher
    // switch. `cli/file-grant.ts`'s `enforcementLine()` helper has its own
    // nested `switch (enforcement)` with these three case labels; they are
    // NOT CLI subcommands, so skip them for this parent command specifically
    // (narrow, file-grant-scoped -- does not touch extraction for any other
    // CLI surface).
    if (["met", "unmet", "unverified"].includes(verb) && parentCommand === "file-grant") continue;
    // Skip nested leaf verbs - they'll be added via nestedToAdd
    if (nestedSkip?.has(verb)) continue;

    results.push({ subcommand: verb, file_path: relPath, line_number: i + 1 });
  }

  // Pattern 2: if (command === "verb") blocks
  const ifRegex = /^\s*if\s*\((?:command|sub|subcommand|verb)\s*===\s*["']([^"']+)["']\)/;
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i]!.match(ifRegex);
    if (!match) continue;
    const verb = match[1]!;
    if (verb.startsWith("-")) continue;
    if (nestedSkip?.has(verb)) continue;
    if (results.some((r) => r.subcommand === verb)) continue;
    results.push({ subcommand: verb, file_path: relPath, line_number: i + 1 });
  }

  return results;
}

// ---- Build inventory using the command table ------------------------------

function buildInventory(): InventoryEntry[] {
  const entries: InventoryEntry[] = [];

  // Collect files
  const cliFiles = collectTsFiles(CLI_DIR);
  const otherCliFiles = [
    join(SERVER_SRC, "exit", "cli.ts"),
    join(SERVER_SRC, "honeypot", "cli.ts"),
    join(SERVER_SRC, "templates", "cli.ts"),
  ].filter((f) => { try { statSync(f); return true; } catch { return false; } });
  const allFiles = [...cliFiles, ...otherCliFiles];
  const seen = new Set<string>();

  for (const filePath of allFiles) {
    const base = filePath.replace(/\.ts$/, "");
    // Skip helpers
    if (base.endsWith("/discovery") || base.endsWith("/health") || base.endsWith("/runtime")) continue;
    if (base.endsWith("/index")) continue;

    const parentCommand = deriveParentCommand(filePath);
    if (!parentCommand) continue;

    const content = readFileSync(filePath, "utf-8");
    const subcommands = extractSubcommands(filePath, content, parentCommand);

    for (const sub of subcommands) {
      // Build the lookup key for the command table
      let lookupKey = `${parentCommand} ${sub.subcommand}`;

      // For nested subcommands, try nested key first
      const spec = COMMAND_TABLE[lookupKey];
      if (!spec) {
        // Try without the verb if it's a parent dispatcher
        // (e.g. "auto-trigger rules" dispatches to "auto-trigger rules list", etc.)
        // Skip parent dispatchers that aren't themselves commands
        if (["rules", "recommendations", "drafts", "approvals", "retention"].includes(sub.subcommand)) {
          continue; // These are routers, not leaf commands
        }
        // Unknown subcommand - classify conservatively
        const key = `sanctuary ${lookupKey}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push({
          subcommand: key,
          file_path: sub.file_path,
          line_number: sub.line_number,
          classification: "read-only",
          audits_currently: null,
          notes: "not in classification table; assumed read-only (review needed)",
        });
        continue;
      }

      const key = `sanctuary ${lookupKey}`;
      if (seen.has(key)) continue;
      seen.add(key);

      let audits_currently: boolean | null;
      let notes: string;

      if (spec.classification === "pure-ui") {
        audits_currently = null;
        notes = spec.notes ?? "pure-UI; audit not required";
      } else if (spec.classification === "read-only") {
        audits_currently = null;
        notes = spec.notes ?? "read-only; audit not required";
      } else {
        audits_currently = spec.auditOverride ?? false;
        notes = spec.notes ?? (audits_currently
          ? "audit entry confirmed"
          : `no audit-emitting code path in handler for ${lookupKey}`);
      }

      entries.push({
        subcommand: key,
        file_path: sub.file_path,
        line_number: sub.line_number,
        classification: spec.classification,
        audits_currently,
        notes,
      });
    }
  }

  // Add nested subcommands from auto-trigger that are in the table but
  // registered via nested switch blocks. Walk them from the source.
  const nestedToAdd = [
    "auto-trigger rules list", "auto-trigger rules show",
    "auto-trigger rules promote", "auto-trigger rules demote",
    "auto-trigger rules set-threshold",
    "auto-trigger recommendations list", "auto-trigger recommendations show",
    "auto-trigger recommendations accept", "auto-trigger recommendations reject",
    "inbox retention show", "inbox retention set",
    "inbox approvals list", "inbox approvals approve",
    "policy drafts list", "policy drafts show",
    "policy drafts check-conflicts", "policy drafts activate",
  ];

  // Find source files for nested commands
  const autoTriggerFile = allFiles.find((f) => f.endsWith("auto-trigger.ts"));
  const inboxFile = allFiles.find((f) => f.endsWith("inbox.ts"));
  const policyFile = allFiles.find((f) => f.endsWith("policy.ts"));

  for (const fullCmd of nestedToAdd) {
    const key = `sanctuary ${fullCmd}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const spec = COMMAND_TABLE[fullCmd];
    if (!spec) continue;

    const verb = fullCmd.split(" ").pop()!;
    let srcFile: string | undefined;
    let relPath = "";
    if (fullCmd.startsWith("auto-trigger")) { srcFile = autoTriggerFile; }
    else if (fullCmd.startsWith("inbox")) { srcFile = inboxFile; }
    else if (fullCmd.startsWith("policy")) { srcFile = policyFile; }

    let lineNum = 0;
    if (srcFile) {
      const content = readFileSync(srcFile, "utf-8");
      relPath = relative(PROJECT_ROOT, srcFile);
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]!.includes(`"${verb}"`) || lines[i]!.includes(`'${verb}'`)) {
          // Find the case or if matching this verb
          if (/case\s+["']/.test(lines[i]!) || /===\s*["']/.test(lines[i]!)) {
            lineNum = i + 1;
            break;
          }
        }
      }
    }

    let audits_currently: boolean | null;
    let notes: string;
    if (spec.classification === "read-only") {
      audits_currently = null;
      notes = spec.notes ?? "read-only; audit not required";
    } else {
      audits_currently = spec.auditOverride ?? false;
      notes = spec.notes ?? (audits_currently
        ? "audit entry confirmed"
        : `no audit-emitting code path in handler for ${fullCmd}`);
    }

    entries.push({
      subcommand: key,
      file_path: relPath,
      line_number: lineNum,
      classification: spec.classification,
      audits_currently,
      notes,
    });
  }

  entries.sort((a, b) => a.subcommand.localeCompare(b.subcommand));
  return entries;
}

// ---- Summary generation ---------------------------------------------------

function generateSummary(entries: InventoryEntry[]): string {
  const total = entries.length;
  const mutators = entries.filter((e) => e.classification === "mutator");
  const readOnly = entries.filter((e) => e.classification === "read-only");
  const pureUi = entries.filter((e) => e.classification === "pure-ui");
  const mutatorNoAudit = mutators.filter((e) => e.audits_currently === false);
  const uncertain = entries.filter(
    (e) => e.notes.includes("review needed"),
  );

  const lines: string[] = [
    "# CLI Audit-Write Completeness Inventory",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Summary",
    "",
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Total CLI subcommands inventoried | ${total} |`,
    `| Mutators | ${mutators.length} |`,
    `| Read-only | ${readOnly.length} |`,
    `| Pure-UI | ${pureUi.length} |`,
    `| **Mutators that do NOT audit (Batch 5b targets)** | **${mutatorNoAudit.length}** |`,
    `| Uncertain (operator review needed) | ${uncertain.length} |`,
    "",
  ];

  if (mutatorNoAudit.length > 0) {
    lines.push("## Mutators Missing Audit (Batch 5b Targets)");
    lines.push("");
    for (const e of mutatorNoAudit) {
      lines.push(`- \`${e.subcommand}\` (${e.file_path}:${e.line_number})`);
      lines.push(`  ${e.notes}`);
    }
    lines.push("");
  }

  if (uncertain.length > 0) {
    lines.push("## Uncertain Classification (Operator Review Needed)");
    lines.push("");
    for (const e of uncertain) {
      lines.push(`- \`${e.subcommand}\` (${e.file_path}:${e.line_number})`);
      lines.push(`  ${e.notes}`);
    }
    lines.push("");
  }

  lines.push("## Full Inventory");
  lines.push("");
  lines.push("| Subcommand | Classification | Audits? | File | Line |");
  lines.push("|------------|---------------|---------|------|------|");
  for (const e of entries) {
    const auditsLabel =
      e.audits_currently === true ? "yes" :
      e.audits_currently === false ? "**NO**" :
      "n/a";
    lines.push(
      `| \`${e.subcommand}\` | ${e.classification} | ${auditsLabel} | ${e.file_path} | ${e.line_number} |`,
    );
  }
  lines.push("");

  return lines.join("\n");
}

// ---- Main -----------------------------------------------------------------

const entries = buildInventory();
const jsonOutput = JSON.stringify(entries, null, 2);

const outputPath = resolve(import.meta.dirname ?? ".", "cli-audit-write-inventory.output.json");
writeFileSync(outputPath, jsonOutput + "\n");

const summary = generateSummary(entries);
const summaryPath = resolve(import.meta.dirname ?? ".", "cli-audit-write-inventory.summary.md");
writeFileSync(summaryPath, summary);

process.stdout.write(jsonOutput + "\n");

const mutatorNoAudit = entries.filter(
  (e) => e.classification === "mutator" && e.audits_currently === false,
);
process.stderr.write(`\nInventory complete: ${entries.length} subcommands\n`);
process.stderr.write(`  Mutators: ${entries.filter((e) => e.classification === "mutator").length}\n`);
process.stderr.write(`  Read-only: ${entries.filter((e) => e.classification === "read-only").length}\n`);
process.stderr.write(`  Pure-UI: ${entries.filter((e) => e.classification === "pure-ui").length}\n`);
process.stderr.write(`  Mutators missing audit: ${mutatorNoAudit.length}\n`);
if (mutatorNoAudit.length > 0) {
  for (const e of mutatorNoAudit) {
    process.stderr.write(`    - ${e.subcommand}\n`);
  }
}
