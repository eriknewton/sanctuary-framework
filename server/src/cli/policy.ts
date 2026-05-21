/**
 * Sanctuary WP-V1.3-6 Xi-1 `sanctuary policy` CLI subcommand.
 *
 * Operator-facing surface for the English-Authored Policy Compiler.
 * v1.3.0 (BBBBB): compile path now loads the intelligence substrate
 * selector from the operator's fortress when SANCTUARY_PASSPHRASE
 * is set and intelligence is configured. Falls back to deterministic-
 * only when the fortress or substrate is not available.
 *
 * Subcommands:
 *   compile "<English text>"          Returns CompiledPolicy JSON
 *                                     (deterministic-only; --json by default).
 *   drafts list                       Print persisted drafts from a
 *                                     known fortress path (in-memory
 *                                     store: this CLI compiles + prints;
 *                                     persistent drafts live in the
 *                                     server's running store).
 *   drafts show <draft_id>            Look up a draft by id (best-effort
 *                                     against the local cache; absence
 *                                     does NOT mean the server has no
 *                                     record).
 *   drafts check-conflicts <draft_id> Query a running fortress for policy
 *                                     conflicts before activation.
 *   drafts activate <draft_id>        Activate through a running fortress;
 *                                     auto-checks conflicts first.
 *
 * The CLI is intentionally lean. Xi-1's persistence is in the
 * running server's in-memory store; CLI compile is a stateless
 * helper that lets the operator preview the compiler's output
 * without spinning up the server. CLI drafts list / show are
 * placeholders for Xi-2 when the activation lifecycle persists
 * drafts under encrypted fortress state and the CLI can read them.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { AuditLog } from "../l2-operational/audit-log.js";
import { MemoryStorage } from "../storage/memory.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { generateRandomKey } from "../core/random.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { bytesToString, stringToBytes } from "../core/encoding.js";
import {
  EnglishPolicyCompiler,
  type CompiledPolicy,
} from "../policy-engine/english-policy-compiler.js";
import type { PolicyConflict } from "../policy-engine/conflict-detector.js";
import { SubstrateSelector } from "../intelligence/selector.js";
import { resolveStoragePath } from "../paths.js";

export interface PolicyArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
}

export async function runPolicyCommand(args: PolicyArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
  }

  try {
    switch (sub) {
      case "compile":
        return await cmdCompile(rest, { out, err });
      case "drafts":
        return await cmdDrafts(rest, { out, err });
      default:
        err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary policy: ${msg}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary policy <command> [args]

  compile "<English text>"        Compile an operator policy statement
                                  to a structured rule + explanation.
                                  Uses LLM-assist when SANCTUARY_PASSPHRASE
                                  is set and intelligence is configured;
                                  otherwise falls back to deterministic.
  drafts list                     Placeholder for Xi-2 persistence.
  drafts show <draft_id>          Placeholder for Xi-2 persistence.
  drafts check-conflicts <draft_id> [--api-base <url>]
                                  Query /api/policy for conflicts.
  drafts activate <draft_id> [--acknowledge-conflicts]
                  [--force-conflict <conflict_id>] [--api-base <url>]
                                  Activate through /api/policy.

Set SANCTUARY_POLICY_API_BASE or pass --api-base for drafts commands
that talk to a running fortress.

`);
}

/**
 * v1.3.0 (BBBBB): attempt to load the intelligence substrate selector from
 * the operator's fortress. Returns null when the fortress is not accessible,
 * passphrase is unavailable, or intelligence is not configured.
 */
async function tryLoadSubstrateSelector(): Promise<{
  selector: SubstrateSelector;
  auditLog: AuditLog;
  fortressId: string;
} | null> {
  try {
    const storagePath = resolveStoragePath();
    const intelligenceDir = resolve(storagePath, "state", "_intelligence");
    if (!existsSync(intelligenceDir)) return null;

    const passphrase = process.env["SANCTUARY_PASSPHRASE"];
    if (!passphrase) {
      // Don't attempt keychain resolution in a compile-preview command;
      // require the env var for non-interactive substrate access.
      return null;
    }

    const storage = new FilesystemStorage(`${storagePath}/state`);
    let existingParams: KeyDerivationParams | undefined;
    try {
      const raw = await storage.read("_meta", "key-params");
      if (raw) existingParams = JSON.parse(bytesToString(raw));
    } catch { /* first run */ }

    const { key: masterKey, params } = await deriveMasterKey(passphrase, existingParams);
    if (!existingParams) {
      await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
    }

    const fortressId = `fortress:${storagePath}`;
    const auditLog = new AuditLog(storage, masterKey);
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: fortressId,
    });
    await selector.load();
    return { selector, auditLog, fortressId };
  } catch {
    return null;
  }
}

async function cmdCompile(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
): Promise<number> {
  const englishText = argv[0];
  if (!englishText) {
    ctx.err.write('compile requires the English text as a single argument:\n');
    ctx.err.write('  sanctuary policy compile "always require approval for state_export"\n');
    return 2;
  }

  // v1.3.0 (BBBBB): try to load the intelligence substrate so LLM-assist
  // is available when the fortress is configured. Falls back to
  // deterministic-only when not available.
  const fortress = await tryLoadSubstrateSelector();

  const storage = fortress ? undefined : new MemoryStorage();
  const masterKey = fortress ? undefined : generateRandomKey();
  const auditLog = fortress?.auditLog ?? new AuditLog(storage!, masterKey!);
  const fortressId = fortress?.fortressId ?? "cli-local";

  const compiler = new EnglishPolicyCompiler({
    auditLog,
    fortressId,
    selector: fortress?.selector ?? null,
  });
  const compiled = await compiler.compile({
    english_text: englishText,
    observed_at: new Date().toISOString(),
    operator_id: "cli-operator",
  });

  // v1.3.0 (BBBBB): surface a clearer message when LLM-assist is unavailable.
  if (
    !fortress?.selector &&
    compiled.compile_warnings?.some((w: string) => w.includes("LLM-assist disabled"))
  ) {
    ctx.err.write(
      "LLM-assist requires intelligence substrate. " +
        "Set SANCTUARY_PASSPHRASE and ensure intelligence is configured:\n" +
        "  sanctuary intelligence configure --substrate local\n",
    );
  }

  ctx.out.write(formatCompiledHumanReadable(compiled) + "\n");
  return 0;
}

async function cmdDrafts(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
): Promise<number> {
  const [sub, ...rest] = argv;
  if (sub === "list" || sub === undefined) {
    ctx.out.write(
      "(no local drafts persisted in CLI mode; drafts live in the running server's in-memory store)\n",
    );
    ctx.out.write(
      'Use "sanctuary policy compile \\"<text>\\"" to preview a compile result locally,\n',
    );
    ctx.out.write(
      'or POST to /api/policy/compile on the running fortress for the full surface.\n',
    );
    return 0;
  }
  if (sub === "show") {
    const draftId = rest[0];
    if (!draftId) {
      ctx.err.write("drafts show requires a draft_id\n");
      return 2;
    }
    ctx.out.write(
      `(CLI does not yet persist drafts; show ${draftId} via GET /api/policy/drafts/${draftId} on the running fortress)\n`,
    );
    return 0;
  }
  if (sub === "check-conflicts") {
    return await cmdDraftsCheckConflicts(rest, ctx);
  }
  if (sub === "activate") {
    return await cmdDraftsActivate(rest, ctx);
  }
  ctx.err.write(`Unknown drafts subcommand: ${sub}\n`);
  return 2;
}

async function cmdDraftsCheckConflicts(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
): Promise<number> {
  const parsed = parseDraftCommandArgs(argv);
  if (!parsed.draftId) {
    ctx.err.write("drafts check-conflicts requires a draft_id\n");
    return 2;
  }
  const base = resolveApiBase(parsed, ctx.err);
  if (!base) return 2;
  const conflicts = await fetchConflicts(base, parsed.draftId);
  ctx.out.write(formatConflicts(conflicts) + "\n");
  return 0;
}

async function cmdDraftsActivate(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
): Promise<number> {
  const parsed = parseDraftCommandArgs(argv);
  if (!parsed.draftId) {
    ctx.err.write("drafts activate requires a draft_id\n");
    return 2;
  }
  const base = resolveApiBase(parsed, ctx.err);
  if (!base) return 2;

  const conflicts = await fetchConflicts(base, parsed.draftId);
  const hasHigh = conflicts.some((c) => c.severity === "high");
  if (conflicts.length > 0 && !parsed.acknowledgeConflicts) {
    ctx.err.write(formatConflicts(conflicts) + "\n");
    ctx.err.write("activation refused: pass --acknowledge-conflicts to activate with conflicts\n");
    return 1;
  }
  if (hasHigh) {
    const forced = new Set(parsed.forceConflictIds);
    const missing = conflicts.filter(
      (c) => c.severity === "high" && !forced.has(c.conflict_id),
    );
    if (missing.length > 0) {
      ctx.err.write(formatConflicts(conflicts) + "\n");
      ctx.err.write("activation refused: high-severity conflicts require --force-conflict <conflict_id>\n");
      return 1;
    }
  }

  const res = await fetch(
    `${base}/api/policy/drafts/${encodeURIComponent(parsed.draftId)}/activate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        conflicts_acknowledged: parsed.acknowledgeConflicts
          ? conflicts
          : undefined,
        force_conflict_ids: parsed.forceConflictIds,
      }),
    },
  );
  const body = await res.json() as {
    ok: boolean;
    error?: string;
    detail?: string;
    data?: { record?: { status?: string } };
  };
  if (!res.ok || !body.ok) {
    ctx.err.write(`activation failed: ${body.error ?? res.statusText}\n`);
    if (body.detail) ctx.err.write(`${body.detail}\n`);
    return 1;
  }
  ctx.out.write(`activated: ${body.data?.record?.status ?? "activated"}\n`);
  return 0;
}

interface ParsedDraftCommandArgs {
  draftId: string | null;
  apiBase?: string;
  acknowledgeConflicts: boolean;
  forceConflictIds: string[];
}

function parseDraftCommandArgs(argv: string[]): ParsedDraftCommandArgs {
  let draftId: string | null = null;
  let apiBase: string | undefined;
  let acknowledgeConflicts = false;
  const forceConflictIds: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--api-base") {
      apiBase = argv[++i];
      continue;
    }
    if (arg === "--acknowledge-conflicts") {
      acknowledgeConflicts = true;
      continue;
    }
    if (arg === "--force-conflict") {
      const id = argv[++i];
      if (id) forceConflictIds.push(id);
      continue;
    }
    if (draftId === null) draftId = arg;
  }
  return { draftId, apiBase, acknowledgeConflicts, forceConflictIds };
}

function resolveApiBase(
  parsed: ParsedDraftCommandArgs,
  err: NodeJS.WritableStream,
): string | null {
  const raw = parsed.apiBase ?? process.env["SANCTUARY_POLICY_API_BASE"];
  if (!raw) {
    err.write("drafts command requires --api-base or SANCTUARY_POLICY_API_BASE\n");
    return null;
  }
  return raw.replace(/\/+$/, "");
}

async function fetchConflicts(
  base: string,
  draftId: string,
): Promise<PolicyConflict[]> {
  const res = await fetch(
    `${base}/api/policy/drafts/${encodeURIComponent(draftId)}/check-conflicts`,
    { method: "POST" },
  );
  const body = await res.json() as {
    ok: boolean;
    error?: string;
    detail?: string;
    data?: { conflicts?: PolicyConflict[] };
  };
  if (!res.ok || !body.ok) {
    throw new Error(body.detail ?? body.error ?? `HTTP ${res.status}`);
  }
  return body.data?.conflicts ?? [];
}

function formatConflicts(conflicts: PolicyConflict[]): string {
  if (conflicts.length === 0) return "conflicts: none";
  const lines = [`conflicts: ${conflicts.length}`];
  for (const c of conflicts) {
    lines.push(
      `- ${c.conflict_id} [${c.severity}/${c.conflict_type}] ${c.affected_capability}: ${c.explanation}`,
    );
  }
  return lines.join("\n");
}

export function formatCompiledHumanReadable(c: CompiledPolicy): string {
  const lines: string[] = [];
  lines.push(`draft_id: ${c.draft_id}`);
  lines.push(`compile_confidence: ${c.compile_confidence}`);
  lines.push(`substrate_used: ${c.substrate_used}`);
  lines.push(`compiled_at: ${c.compiled_at}`);
  lines.push(``);
  lines.push(`english_text:`);
  lines.push(`  ${c.english_text}`);
  lines.push(``);
  lines.push(`compiled_rule:`);
  lines.push(`  kind: ${c.compiled_rule.kind}`);
  if (c.compiled_rule.operation !== undefined) {
    lines.push(`  operation: ${c.compiled_rule.operation}`);
  }
  if (c.compiled_rule.tier2_update !== undefined) {
    lines.push(`  tier2_update.field: ${c.compiled_rule.tier2_update.field}`);
    lines.push(`  tier2_update.value: ${String(c.compiled_rule.tier2_update.value)}`);
  }
  lines.push(``);
  lines.push(`explanation:`);
  lines.push(`  ${c.explanation_paragraph}`);
  if (c.compile_warnings.length > 0) {
    lines.push(``);
    lines.push(`warnings:`);
    for (const w of c.compile_warnings) lines.push(`  - ${w}`);
  }
  return lines.join("\n");
}
