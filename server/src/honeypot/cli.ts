/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1 Honeypot CLI.
 *
 * Five subcommands surface the same operations the management API
 * exposes, with operator-friendly output rendering:
 *
 *   sanctuary honeypot compile "<English>"     POST /api/honeypot/compile
 *   sanctuary honeypot deploy <trap_id>        POST /api/honeypot/deploy
 *   sanctuary honeypot list                    GET  /api/honeypot/traps
 *   sanctuary honeypot tool-traps list         list tool-call trap stats
 *   sanctuary honeypot credential-traps list   list credential trap stats
 *   sanctuary honeypot undeploy <trap_id>      DELETE /api/honeypot/traps/:id
 *   sanctuary honeypot findings [--since=...]  GET  /api/honeypot/findings
 *
 * The CLI is a pure function over caller-supplied deps: it takes a
 * TrapRegistry + compiler + finding-store reference and runs the
 * operation in-process. (Unlike `sanctuary exit`, which opens a
 * fortress storage context, honeypot operations are stateless
 * relative to storage; the registry holds the live state.)
 *
 * Tests inject the deps directly so the CLI is exercised without
 * standing up a full HTTP listener.
 */

import type { Writable } from "node:stream";
import { randomUUID } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SubstrateSelector } from "../intelligence/selector.js";

import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  type HoneypotDraft,
  type TrapSpec,
  type TrapTrigger,
} from "./types.js";

/**
 * Render the operator-friendly suffix that follows the `path_pattern`
 * on `sanctuary honeypot compile`'s non-JSON output. Branches on the
 * trigger's discriminator so the suffix carries the most-relevant
 * class-specific detail without leaking the union shape to the user.
 */
function formatTriggerSuffix(trigger: TrapTrigger): string {
  if (trigger.kind === "http_endpoint") {
    return ` (${trigger.method ?? "ANY"})`;
  }
  if (trigger.kind === "filesystem") {
    return ` (ops=${trigger.ops.join(",")})`;
  }
  if (trigger.kind === "credential") {
    return ` (${trigger.fake_credential_type}; paths=${trigger.emission_paths.join(",")})`;
  }
  return ` (${trigger.catalog_visibility})`;
}

function formatTriggerPrimary(trigger: TrapTrigger): string {
  if (trigger.kind === "tool_call") return trigger.fake_tool_name;
  if (trigger.kind === "credential") return trigger.fake_credential_name;
  return trigger.path_pattern;
}
import {
  compileHoneypot,
  hashOfEnglishDraft,
} from "./honeypot-compiler.js";
import { TrapRegistry } from "./trap-registry.js";
import { flagValue } from "../cli/argv.js";

export interface HoneypotCliDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  operatorId: string;
  fortressId: string;
  /** Optional selector for Path A LLM compile. Absent forces Path B. */
  selector?: SubstrateSelector;
  /** Spec lookup by id. Tests inject deterministic specs; production
   * uses an in-memory map keyed by `trap_id` from a prior `compile`
   * run. Pi-1 ships the spec via the deploy subcommand's stdin or a
   * caller-provided lookup; auto-persistence of compiled specs lands
   * in Pi-2 (fortress-config persistence). */
  resolveSpec?: (trapId: string) => TrapSpec | undefined;
  toolTrapStats?: () => Array<{
    trap_id: string;
    fake_tool_name: string;
    invocation_count: number;
    last_invocation_at: string | null;
    caller_diversity: number;
  }>;
  credentialTrapStats?: () => Array<{
    trap_id: string;
    fake_credential_name: string;
    read_count: number;
    use_attempt_count: number;
    last_access_at: string | null;
    caller_diversity: number;
  }>;
  now?: () => Date;
}

export interface HoneypotCliArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
}

function write(stream: Writable | undefined, text: string): void {
  if (stream) stream.write(text);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.some((a) => a === name || a.startsWith(`${name}=`));
}

/**
 * Execute one honeypot CLI command. Returns exit code (0 success, 1
 * operator-error, 2 usage-error).
 */
export async function runHoneypotCli(
  deps: HoneypotCliDeps,
  args: HoneypotCliArgs,
): Promise<number> {
  const { argv, out, err } = args;
  const command = argv[0];
  const now = deps.now ?? (() => new Date());
  const json = hasFlag(argv, "--json");

  if (!command || command === "--help" || command === "-h") {
    write(
      out,
      "Usage: sanctuary honeypot <compile|deploy|list|tool-traps|credential-traps|undeploy|findings>\n",
    );
    return command ? 0 : 2;
  }

  if (command === "compile") {
    const englishText = argv[1];
    if (!englishText || englishText.startsWith("--")) {
      write(err, 'Usage: sanctuary honeypot compile "<English description>"\n');
      return 2;
    }
    const draft: HoneypotDraft = {
      english_text: englishText,
      operator_id: deps.operatorId,
      observed_at: now().toISOString(),
    };
    await deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.DRAFTED, deps.operatorId, {
      fortress_id: deps.fortressId,
      english_hash: hashOfEnglishDraft(englishText),
    });
    const result = await compileHoneypot(draft, {
      ...(deps.selector !== undefined ? { selector: deps.selector } : {}),
      now,
    });
    await deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.COMPILED, deps.operatorId, {
      fortress_id: deps.fortressId,
      trap_id: result.spec.trap_id,
      source: result.source,
      warning_count: result.warnings.length,
    });
    if (json) {
      write(out, JSON.stringify(result, null, 2) + "\n");
    } else {
      write(out, `compiled: ${result.spec.trap_id}\n`);
      write(out, `source: ${result.source}\n`);
      write(out, `class: ${result.spec.trap_class}\n`);
      const label =
        result.spec.trigger.kind === "tool_call" ||
        result.spec.trigger.kind === "credential"
          ? "target"
          : "pattern";
      write(
        out,
        `${label}: ${formatTriggerPrimary(result.spec.trigger)}${formatTriggerSuffix(result.spec.trigger)}\n`,
      );
      write(out, `severity: ${result.spec.finding_severity}\n`);
      write(out, `explanation: ${result.spec.explanation_paragraph}\n`);
      for (const warning of result.warnings) {
        write(out, `warning: ${warning}\n`);
      }
    }
    return 0;
  }

  if (command === "deploy") {
    const trapId = argv[1];
    if (!trapId || trapId.startsWith("--")) {
      write(err, "Usage: sanctuary honeypot deploy <trap_id>\n");
      return 2;
    }
    if (!deps.resolveSpec) {
      write(
        err,
        "Error: deploy requires a spec-lookup function in this CLI context\n",
      );
      return 1;
    }
    const spec = deps.resolveSpec(trapId);
    if (!spec) {
      write(err, `Error: unknown trap_id ${trapId}\n`);
      return 1;
    }
    const wasNew = deps.registry.deploy(spec);
    await deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.DEPLOYED, deps.operatorId, {
      fortress_id: deps.fortressId,
      trap_id: spec.trap_id,
      trap_class: spec.trap_class,
      target: formatTriggerPrimary(spec.trigger),
      was_new: wasNew,
    });
    if (json) {
      write(out, JSON.stringify({ trap_id: spec.trap_id, was_new: wasNew }, null, 2) + "\n");
    } else {
      write(out, `deployed: ${spec.trap_id} (${wasNew ? "new" : "replaced"})\n`);
    }
    return 0;
  }

  if (command === "list") {
    const traps = deps.registry.list();
    if (json) {
      write(out, JSON.stringify({ traps }, null, 2) + "\n");
    } else if (traps.length === 0) {
      write(out, "no honeypot traps deployed\n");
    } else {
      for (const t of traps) {
        write(
          out,
          `${t.trap_id}  ${t.trap_class}  ${formatTriggerPrimary(t.trigger)}  severity=${t.finding_severity}\n`,
        );
      }
    }
    return 0;
  }

  if (command === "tool-traps") {
    const sub = argv[1];
    if (sub !== "list") {
      write(err, "Usage: sanctuary honeypot tool-traps list\n");
      return 2;
    }
    const traps = deps.toolTrapStats
      ? deps.toolTrapStats()
      : deps.registry
          .list()
          .filter((t) => t.trigger.kind === "tool_call")
          .map((t) => ({
            trap_id: t.trap_id,
            fake_tool_name:
              t.trigger.kind === "tool_call"
                ? t.trigger.fake_tool_name
                : "",
            invocation_count: 0,
            last_invocation_at: null,
            caller_diversity: 0,
          }));
    if (json) {
      write(out, JSON.stringify({ traps }, null, 2) + "\n");
    } else if (traps.length === 0) {
      write(out, "no tool-call honeypot traps deployed\n");
    } else {
      for (const t of traps) {
        write(
          out,
          `${t.trap_id}  ${t.fake_tool_name}  invocations=${t.invocation_count}  callers=${t.caller_diversity}  last=${t.last_invocation_at ?? "never"}\n`,
        );
      }
    }
    return 0;
  }

  if (command === "credential-traps") {
    const sub = argv[1];
    if (sub !== "list") {
      write(err, "Usage: sanctuary honeypot credential-traps list\n");
      return 2;
    }
    const traps = deps.credentialTrapStats
      ? deps.credentialTrapStats()
      : deps.registry
          .list()
          .filter((t) => t.trigger.kind === "credential")
          .map((t) => ({
            trap_id: t.trap_id,
            fake_credential_name:
              t.trigger.kind === "credential"
                ? t.trigger.fake_credential_name
                : "",
            read_count: 0,
            use_attempt_count: 0,
            last_access_at: null,
            caller_diversity: 0,
          }));
    if (json) {
      write(out, JSON.stringify({ traps }, null, 2) + "\n");
    } else if (traps.length === 0) {
      write(out, "no credential honeypot traps deployed\n");
    } else {
      for (const t of traps) {
        write(
          out,
          `${t.trap_id}  ${t.fake_credential_name}  reads=${t.read_count}  uses=${t.use_attempt_count}  callers=${t.caller_diversity}  last=${t.last_access_at ?? "never"}\n`,
        );
      }
    }
    return 0;
  }

  if (command === "undeploy") {
    const trapId = argv[1];
    if (!trapId || trapId.startsWith("--")) {
      write(err, "Usage: sanctuary honeypot undeploy <trap_id>\n");
      return 2;
    }
    const removed = deps.registry.undeploy(trapId);
    if (removed) {
      await deps.auditLog.append(
        "l2",
        HONEYPOT_AUDIT_OPS.UNDEPLOYED,
        deps.operatorId,
        { fortress_id: deps.fortressId, trap_id: trapId },
      );
    }
    if (json) {
      write(out, JSON.stringify({ trap_id: trapId, removed }, null, 2) + "\n");
    } else {
      write(out, removed ? `undeployed: ${trapId}\n` : `not found: ${trapId}\n`);
    }
    return removed ? 0 : 1;
  }

  if (command === "findings") {
    const since = flagValue(argv, "--since");
    const sinceIso = parseSinceFlag(since, now);
    const all = await deps.findingStore.listFindings({
      ...(sinceIso !== undefined ? { since: sinceIso } : {}),
      limit: 200,
    });
    const honeypotFindings = all.filter((f) =>
      f.sentinel_id.startsWith(HONEYPOT_SENTINEL_ID_PREFIX),
    );
    if (json) {
      write(out, JSON.stringify({ findings: honeypotFindings }, null, 2) + "\n");
    } else if (honeypotFindings.length === 0) {
      write(out, "no honeypot findings in the requested window\n");
    } else {
      for (const f of honeypotFindings) {
        write(
          out,
          `${f.observed_at}  ${f.severity.padEnd(5)}  ${f.sentinel_id}  ${f.summary}\n`,
        );
      }
    }
    return 0;
  }

  write(err, `Unknown subcommand: ${command}\n`);
  return 2;
}

function parseSinceFlag(
  raw: string | undefined,
  now: () => Date,
): string | undefined {
  if (raw === undefined) return undefined;
  // Accept ISO 8601 directly.
  if (/^\d{4}-/.test(raw)) return raw;
  // Accept relative durations like "24h", "7d", "1h".
  const match = raw.match(/^(\d+)([hd])$/);
  if (!match) return undefined;
  const n = Number.parseInt(match[1]!, 10);
  const unit = match[2]!;
  const ms = unit === "h" ? n * 60 * 60 * 1000 : n * 24 * 60 * 60 * 1000;
  return new Date(now().getTime() - ms).toISOString();
}

// Re-export deterministic id factory so tests can stub.
export function defaultTrapId(): string {
  return randomUUID();
}
