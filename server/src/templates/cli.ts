/**
 * Sanctuary Template Library — CLI subcommands.
 *
 * `sanctuary template list` — enumerate available templates.
 * `sanctuary template init <name> --agent-id <id>` — load a template.
 *
 * Orphan-rejection policy (v1.0, Option A): `template init` requires an
 * already-wrapped harness. The default `isAgentWrapped` check resolves
 * `agent_id` against the tenant discovery layer (`findTenant`); a tenant
 * that is present and initialized counts as wrapped. Callers may override
 * via `TemplateCommandArgs.isAgentWrapped` for tests.
 */

import { listTemplates, getTemplate, TEMPLATE_NAMES, isTemplateName } from "./registry.js";
import { buildCompiledPolicyFromTemplate } from "./init.js";
import { encodePolicyBlob } from "../policy-engine/canonical-policy.js";
import { findTenant } from "../cli/agents/discovery.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { loadConfig } from "../config.js";
import { getOrCreatePassphrase } from "../cocoon/passphrase.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";

export interface TemplateCommandArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  /**
   * Override the orphan-check. Returns true when a cocoon is bound to the
   * given agent_id. Default: resolves against tenant discovery.
   */
  isAgentWrapped?: (agentId: string) => Promise<boolean>;
}

export async function runTemplateCommand(args: TemplateCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printTemplateHelp(out);
    return 0;
  }

  switch (sub) {
    case "list":
      return cmdList(out, err);
    case "init":
      return cmdInit(rest, out, err, args.isAgentWrapped ?? defaultIsAgentWrapped);
    default:
      err.write(`Unknown template subcommand: ${sub}\n`);
      printTemplateHelp(err);
      return 1;
  }
}

/**
 * Default orphan-check. An agent counts as wrapped when tenant discovery
 * finds a tenant with that name and the tenant is initialized (state dir
 * or cocoon-profile.json present).
 */
async function defaultIsAgentWrapped(agentId: string): Promise<boolean> {
  const tenant = await findTenant(agentId);
  if (!tenant) return false;
  return tenant.initialized || tenant.has_cocoon_profile;
}

// ═══════════════════════════════════════════════════════════════════════
// list
// ═══════════════════════════════════════════════════════════════════════

function cmdList(
  out: NodeJS.WritableStream,
  _err: NodeJS.WritableStream
): number {
  const templates = listTemplates();
  out.write("\nSanctuary Template Library\n");
  out.write("=".repeat(60) + "\n\n");
  out.write(
    padRight("NAME", 24) +
    padRight("CHANNEL", 26) +
    padRight("TIER", 6) +
    "DESCRIPTION\n"
  );
  out.write("-".repeat(100) + "\n");
  for (const entry of templates) {
    const m = entry.metadata;
    out.write(
      padRight(m.name, 24) +
      padRight(m.channel, 26) +
      padRight(m.tier, 6) +
      m.description + "\n"
    );
  }
  out.write("\n");
  out.write(`Use "sanctuary template init <name> --agent-id <id>" to load a template.\n\n`);
  return 0;
}

function padRight(str: string, len: number): string {
  return str.length >= len ? str + " " : str + " ".repeat(len - str.length);
}

// ═══════════════════════════════════════════════════════════════════════
// init
// ═══════════════════════════════════════════════════════════════════════

async function cmdInit(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  isAgentWrapped: (agentId: string) => Promise<boolean>
): Promise<number> {
  let templateName: string | undefined;
  let agentId: string | undefined;
  let fortressId = "fortress-default";
  let counterparty = "*";

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--agent-id" && argv[i + 1]) {
      agentId = argv[++i];
    } else if (argv[i] === "--fortress-id" && argv[i + 1]) {
      fortressId = argv[++i]!;
    } else if (argv[i] === "--counterparty" && argv[i + 1]) {
      counterparty = argv[++i]!;
    } else if (argv[i] === "--help" || argv[i] === "-h") {
      printInitHelp(out);
      return 0;
    } else if (!argv[i]!.startsWith("--")) {
      templateName = argv[i];
    }
  }

  if (!templateName) {
    err.write("Error: template name is required.\n");
    err.write(`Available templates: ${TEMPLATE_NAMES.join(", ")}\n`);
    return 1;
  }

  if (!isTemplateName(templateName)) {
    err.write(`Error: unknown template "${templateName}".\n`);
    err.write(`Available templates: ${TEMPLATE_NAMES.join(", ")}\n`);
    return 1;
  }

  if (!agentId) {
    err.write("Error: --agent-id is required.\n");
    return 1;
  }

  // Orphan-reject: a channel-shape template binds to an already-wrapped
  // harness. If no cocoon exists for this agent_id, fail loudly and point
  // the operator at `sanctuary wrap`. Sanctuary ships channel-shape
  // governance templates, not named-agent runtimes; authoring a policy
  // for nothing is the drift surface we closed in v1.0.0-rc.2.
  const wrapped = await isAgentWrapped(agentId);
  if (!wrapped) {
    err.write(
      `Error: no wrapped harness found for agent-id "${agentId}".\n` +
      `\n` +
      `A channel-shape template binds to an already-wrapped harness.\n` +
      `Wrap the harness first, then re-run template init:\n` +
      `\n` +
      `  sanctuary wrap --claude-code   # or --openclaw, --hermes, --cursor, --cline\n` +
      `  sanctuary template init ${templateName} --agent-id ${agentId}\n`
    );
    return 1;
  }

  const bundle = getTemplate(templateName);
  if (!bundle) {
    err.write(`Error: template "${templateName}" not found.\n`);
    return 1;
  }

  // Build the compiled policy (deterministic; no signing keys needed for preview)
  const compiled = buildCompiledPolicyFromTemplate(bundle, {
    agent_id: agentId,
    fortress_id: fortressId,
    counterparty,
    policy_version: 1,
  });

  // Encode the policy blob for display
  const blob = encodePolicyBlob(compiled);

  // Best-effort audit write
  try {
    const config = await loadConfig();
    const storagePath = config.storage_path;
    const storage = new FilesystemStorage(`${storagePath}/state`);
    let passphrase = process.env["SANCTUARY_PASSPHRASE"];
    if (!passphrase) {
      const resolved = await getOrCreatePassphrase();
      passphrase = resolved.value;
    }
    let existingParams: KeyDerivationParams | undefined;
    try {
      const raw = await storage.read("_meta", "key-params");
      if (raw) existingParams = JSON.parse(bytesToString(raw));
    } catch { /* no key-params yet */ }
    const { key: masterKey, params } = await deriveMasterKey(passphrase, existingParams);
    if (!existingParams) {
      await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
    }
    const fortressId = fortressIdFromStoragePath(storagePath);
    const auditLog = new AuditLog(storage, masterKey);
    auditLog.append("l2", "template.init", `fortress:${fortressId}`, {
      template_name: templateName,
      agent_id: agentId,
      fortress_id: fortressId,
      channel: bundle.metadata.channel,
      tier: bundle.metadata.tier,
    });
  } catch { /* audit best-effort; do not block template init output */ }

  out.write("\nTemplate initialized successfully.\n");
  out.write("=".repeat(60) + "\n\n");
  out.write(`Template:       ${bundle.metadata.name}\n`);
  out.write(`Channel:        ${bundle.metadata.channel}\n`);
  out.write(`Tier:           ${bundle.metadata.tier}\n`);
  out.write(`Agent ID:       ${compiled.agent_id}\n`);
  out.write(`Fortress ID:    ${compiled.fortress_id}\n`);
  out.write(`Policy Version: ${compiled.policy_version}\n`);
  out.write(`Schema Version: ${compiled.schema_version}\n`);
  out.write("\n");

  // Slot access summary
  out.write("Slot access:\n");
  for (const slot of ["memory", "credentials", "plans", "outputs"] as const) {
    const rule = compiled.slots[slot];
    if (rule.mode === "deny") {
      out.write(`  ${slot}: deny (hermetic)\n`);
    } else {
      const grants = rule.grants.map(
        (g) => `${g.action} by ${g.counterparty}`
      );
      out.write(`  ${slot}: ${grants.join(", ")}\n`);
    }
  }

  // Capabilities
  if (compiled.capabilities.concordia_commitment_classes.length > 0) {
    out.write(
      `\nCommitment classes: ${compiled.capabilities.concordia_commitment_classes.join(", ")}\n`
    );
  }

  // WP-MVP-6 surfaces
  if (compiled.egress) {
    out.write(`\nEgress allowlist (${compiled.egress.allowlist.length} entries):\n`);
    for (const rule of compiled.egress.allowlist) {
      const methods = rule.methods.length > 0 ? rule.methods.join(",") : "*";
      out.write(`  ${rule.destination} [${methods}]\n`);
    }
  } else {
    out.write("\nEgress: hermetic (no outbound access)\n");
  }

  if (compiled.budgets) {
    out.write("\nBudgets:\n");
    if (compiled.budgets.daily) {
      out.write(
        `  Daily: ${compiled.budgets.daily.amount} ${compiled.budgets.daily.unit}\n`
      );
    }
    if (compiled.budgets.monthly) {
      out.write(
        `  Monthly: ${compiled.budgets.monthly.amount} ${compiled.budgets.monthly.unit}\n`
      );
    }
  }

  if (compiled.retention) {
    out.write("\nRetention windows:\n");
    for (const [slot, win] of Object.entries(compiled.retention.windows)) {
      if (win) {
        const days = Math.round(win.max_age_seconds / 86400);
        out.write(`  ${slot}: ${days} days${win.archive ? " (archive)" : ""}\n`);
      }
    }
  }

  out.write(`\nPolicy blob (base64url, ${blob.length} chars):\n`);
  out.write(`  ${blob.slice(0, 80)}...\n\n`);
  out.write(
    "To sign and emit this policy as a policy_update event, use the\n" +
    "policy engine's packPolicyUpdate with your node signing key.\n\n"
  );

  return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Help
// ═══════════════════════════════════════════════════════════════════════

function printTemplateHelp(out: NodeJS.WritableStream): void {
  out.write(`
sanctuary template — Manage Sanctuary policy templates.

Usage:
  sanctuary template list                    List available templates
  sanctuary template init <name> [options]   Load a template

Options:
  --help, -h    Show this help

Use "sanctuary template init --help" for init-specific options.
`);
}

function printInitHelp(out: NodeJS.WritableStream): void {
  out.write(`
sanctuary template init — Load a template into a fortress.

Usage:
  sanctuary template init <name> --agent-id <id> [options]

Arguments:
  <name>              Template name (see "sanctuary template list")

Options:
  --agent-id <id>     Agent ID to bind the policy to (required)
  --fortress-id <id>  Fortress ID (default: "fortress-default")
  --counterparty <id> Counterparty for channel grants (default: "*")
  --help, -h          Show this help

Available templates: ${TEMPLATE_NAMES.join(", ")}
`);
}
