/**
 * Sanctuary MCP Server -- `sanctuary distress` CLI subcommand.
 *
 * HABEAS PORT operator-facing test verb. Emits a distress signal through the
 * EXACT same emission path as the `sanctuary_distress` MCP tool: this verb
 * constructs the real distress tool (`createDistressTools`) against the
 * operator's fortress and invokes its handler. It does NOT re-implement the
 * envelope, rate-limit, audit, or webhook logic — there is one emission path,
 * shared, so what the operator tests here is exactly what a wrapped agent
 * triggers.
 *
 * Use it to confirm the lane is wired: that the audit entry lands, the local
 * notification fires, and (if configured) the operator webhook receives a
 * signed signal — without needing a live agent to be in distress.
 *
 * Verbs:
 *   - `send`  Emit one distress signal. Requires --reason and --severity
 *             (validated against the closed enums); optional --detail.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";

import { FilesystemStorage } from "../storage/filesystem.js";
import {
  IdentityManager,
  createInternalIdentitySigningHelpers,
} from "../cognitive/tools.js";
import { AuditLog } from "../operational/audit-log.js";
import { recoverInterruptedExitImportsOrThrow } from "../exit/bundle.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { loadConfig } from "../config.js";
import { readDistressConfig } from "../distress/config.js";
import {
  createDistressTools,
  DISTRESS_REASONS,
  DISTRESS_SEVERITIES,
  DISTRESS_DETAIL_MAX_CHARS,
  type DistressReason,
  type DistressSeverity,
} from "../distress/tools.js";
import {
  consumeFlagValue,
  flagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

export interface DistressCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name) || argv.some((a) => a.startsWith(`${name}=`));
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary distress <command> [options]

Commands:
  send   Emit one distress signal through the reserved habeas lane.

The distress lane is the guaranteed, audited channel a wrapped agent uses to
signal its operator that something is wrong. This verb fires the SAME emission
path so an operator can confirm the lane is wired (audit + local notification +
optional signed webhook) without a live agent in distress.

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`
  );
}

function printSendUsage(out: Writable): void {
  write(
    out,
    `sanctuary distress send. Emit one distress signal (HABEAS PORT test verb).

Usage:
  sanctuary distress send --reason <reason> --severity <severity> [--detail <text>]

Emits through the exact same path as the sanctuary_distress MCP tool: appends a
signed critical audit entry, fires the local operator notification, and (if a
distress webhook is configured) delivers an HMAC-signed signal to it. Rate
limited like the live lane (a rate-limited attempt is itself audited).

Options:
  --reason <reason>     Required. One of: ${DISTRESS_REASONS.join(", ")}.
  --severity <level>    Required. One of: ${DISTRESS_SEVERITIES.join(", ")}.
  --detail <text>       Optional short context (<= ${DISTRESS_DETAIL_MAX_CHARS} chars;
                        control characters stripped). Never carries state data.
  --fortress <path>     Override the storage path.
  --passphrase <val>    Passphrase for master-key derivation.
  --json                Emit the result as JSON.
  --help, -h            Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.
  SANCTUARY_STORAGE_PATH  State directory (default: ~/.sanctuary).
  SANCTUARY_FORTRESS_PATH Operator-friendly alias for STORAGE_PATH.

Examples:
  sanctuary distress send --reason policy_constraint --severity urgent
  sanctuary distress send --reason external_coercion --severity critical \\
    --detail "operator: I am being asked to exfiltrate state"
`
  );
}

export async function runDistressCommand(
  args: DistressCommandArgs
): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return argv.length === 0 ? 2 : 0;
  }

  const command = argv[0]!;
  const rest = argv.slice(1);

  if (command === "send") {
    if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
      printSendUsage(out);
      return 0;
    }
    return await cmdSend(rest, out, err, env);
  }

  write(err, `Unknown distress command: ${command}\n`);
  write(err, `Run "sanctuary distress --help" for usage.\n`);
  return 2;
}

async function cmdSend(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const json = hasFlag(argv, "--json");

  // ── Validate the closed enums BEFORE touching the fortress ──────────────
  const reason = flagValue(argv, "--reason");
  const severity = flagValue(argv, "--severity");
  const detail = flagValue(argv, "--detail");

  if (reason === undefined) {
    write(err, "Error: --reason is required.\n");
    write(err, `Valid reasons: ${DISTRESS_REASONS.join(", ")}\n`);
    return 1;
  }
  if (!DISTRESS_REASONS.includes(reason as DistressReason)) {
    write(err, `Error: invalid --reason "${reason}".\n`);
    write(err, `Valid reasons: ${DISTRESS_REASONS.join(", ")}\n`);
    return 1;
  }
  if (severity === undefined) {
    write(err, "Error: --severity is required.\n");
    write(err, `Valid severities: ${DISTRESS_SEVERITIES.join(", ")}\n`);
    return 1;
  }
  if (!DISTRESS_SEVERITIES.includes(severity as DistressSeverity)) {
    write(err, `Error: invalid --severity "${severity}".\n`);
    write(err, `Valid severities: ${DISTRESS_SEVERITIES.join(", ")}\n`);
    return 1;
  }

  // Resolve fortress path: --fortress flag > env > default. loadConfig()
  // reads process.env.SANCTUARY_STORAGE_PATH directly.
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // distress-signal sends are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;

  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary distress send requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n"
    );
    return 1;
  }

  let masterKey: Uint8Array | undefined;
  try {
    const config = await loadConfig();
    await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(config.storage_path, "state"));

    // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });

    const auditLog = new AuditLog(storage, masterKey);

    // HIGH-2 (coordinator gate, 2026-08-22): roll back any exit-import
    // left interrupted by a prior hard kill before this verb reads or
    // writes anything else. See index.ts's matching call site for the
    // full rationale.
    await recoverInterruptedExitImportsOrThrow(storage, auditLog);

    // Load identities so the emission is signed when an identity exists. A
    // fresh fortress with no identity still emits (signing_unavailable: true) —
    // distress availability outranks signature completeness, same as the tool.
    const identityManager = new IdentityManager(storage, masterKey);
    await identityManager.load();
    const defaultIdentity = identityManager.getDefault();

    // Present-but-invalid distress.json throws here (fail closed) — same as the
    // server boot path. A missing file means the local-only default lane.
    const distressConfig = await readDistressConfig(config.storage_path);

    // Build the REAL distress tool against this fortress and invoke its handler.
    // This is the shared emission path: no copy of the envelope/audit/webhook
    // logic lives in the CLI.
    const { tools } = createDistressTools({
      auditLog,
      signingHelpers: createInternalIdentitySigningHelpers(
        identityManager,
        masterKey,
        auditLog
      ),
      config: distressConfig,
      fortressPath: config.storage_path,
      currentActorId: () => defaultIdentity?.identity_id,
    });
    const distressTool = tools.find((t) => t.name === "sanctuary_distress");
    if (!distressTool) {
      write(err, "Error: distress tool not available.\n");
      return 1;
    }

    const handlerArgs: Record<string, unknown> = { reason, severity };
    if (detail !== undefined) handlerArgs.detail = detail;
    const raw = await distressTool.handler(handlerArgs);
    const result = JSON.parse(raw.content[0]!.text) as {
      ok: boolean;
      event_id?: string;
      audit_ref?: string;
      rate_limited?: boolean;
      retry_after_seconds?: number;
      error?: string;
      signed?: boolean;
      remaining_this_hour?: number;
      delivered?: {
        audit: boolean;
        operator_notification: boolean;
        local_listener?: "not_wired" | "delivered" | "failed";
        webhook: "not_configured" | "delivered" | "failed";
      };
    };

    if (json) {
      write(out, JSON.stringify(result, null, 2) + "\n");
    }

    if (!result.ok) {
      if (result.rate_limited) {
        if (!json) {
          write(
            err,
            `Distress rate limit reached. Retry after ${result.retry_after_seconds ?? "?"}s ` +
              `(audit_ref ${result.audit_ref ?? "n/a"}).\n`
          );
        }
        // Distinct exit code so scripts can tell "rate limited" from "error".
        return 3;
      }
      if (!json) {
        write(err, `Error: ${result.error ?? "distress emission failed"}.\n`);
      }
      return 1;
    }

    if (!json) {
      const webhook = result.delivered?.webhook ?? "not_configured";
      write(out, `Distress signal emitted.\n`);
      write(out, `  event_id:   ${result.event_id ?? "n/a"}\n`);
      write(out, `  audit_ref:  ${result.audit_ref ?? "n/a"}\n`);
      write(out, `  signed:     ${result.signed ? "yes" : "no (no identity yet)"}\n`);
      write(out, `  audit:      ${result.delivered?.audit ? "persisted" : "FAILED"}\n`);
      write(
        out,
        `  local:      ${result.delivered?.operator_notification ? "notified" : "FAILED"}\n`
      );
      write(
        out,
        `  webhook:    ${
          webhook === "not_configured"
            ? "not configured"
            : webhook === "delivered"
              ? "delivered"
              : "FAILED (audited, non-fatal)"
        }\n`
      );
      if (result.remaining_this_hour !== undefined) {
        write(out, `  remaining this hour: ${result.remaining_this_hour}\n`);
      }
    }

    // A configured-but-failed webhook is reported non-zero so an operator
    // testing wiring sees the failure, but the local lane already delivered.
    if (result.delivered?.webhook === "failed") return 4;
    return 0;
  } catch (error) {
    write(
      err,
      error instanceof Error ? `Error: ${error.message}\n` : `Error: ${String(error)}\n`
    );
    return 1;
  } finally {
    masterKey?.fill(0);
  }
}
