/**
 * Sanctuary MCP Server — `sanctuary agents` CLI subcommand
 *
 * Multi-tenant inventory + configuration verbs:
 *
 *   - `list`    human table / JSON listing of every tenant Sanctuary sees.
 *   - `show <tenant>` details for one tenant (paths, keychain service name,
 *               passphrase status, runtime state, last activity, approval
 *               redirect state).
 *   - `status`  one-line-per-tenant summary (running / stopped + counts).
 *   - `config <tenant> --approval-redirect=<bool>` (v1.3 Upsilon-2)
 *               Writes principal-policy.yaml on disk for the tenant.
 *               Takes effect on the tenant's next gate request (no
 *               restart required for running servers because the policy
 *               supplier is consulted per request).
 *
 * Everything here is derivable from the filesystem + optional runtime.json
 * files. No tenant secrets or identity private keys are ever decrypted.
 *
 * `agent` (singular) is also accepted at the top-level dispatcher as an
 * alias — see server/src/cli.ts.
 */

import { readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";

import {
  discoverTenants,
  findTenant,
  type TenantDescriptor,
} from "./discovery.js";
import { probeTenantDashboard, type HealthProbeResult } from "./health.js";
import { parsePolicy } from "../../principal-policy/loader.js";
import { readLockdownStatus } from "../../lockdown/status.js";
import { AuditLog } from "../../l2-operational/audit-log.js";
import { FilesystemStorage } from "../../storage/filesystem.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../../core/encoding.js";
import { readStoredPassphrase } from "../../wrap/passphrase.js";
import { fortressIdFromStoragePath } from "../../dashboard/v1_1/wiring.js";

export interface AgentsCommandArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  /** Override process.env for tests. */
  env?: NodeJS.ProcessEnv;
  /** Override HOME directory for tests. */
  home?: string;
  /**
   * Override the storage root used for discovery. Primarily for tests —
   * production reads from `<home>/.sanctuary` by default.
   */
  root?: string;
  /** Swap the health probe for tests so they do not open real sockets. */
  probe?: (tenant: TenantDescriptor) => Promise<HealthProbeResult>;
}

interface ResolvedCtx {
  out: NodeJS.WritableStream;
  err: NodeJS.WritableStream;
  env: NodeJS.ProcessEnv;
  probe: (tenant: TenantDescriptor) => Promise<HealthProbeResult>;
  discoverOpts: { home?: string; env?: NodeJS.ProcessEnv; root?: string };
}

function resolveCtx(args: AgentsCommandArgs): ResolvedCtx {
  const env = args.env ?? process.env;
  const discoverOpts: { home?: string; env?: NodeJS.ProcessEnv; root?: string } = {
    env,
  };
  if (args.home !== undefined) discoverOpts.home = args.home;
  if (args.root !== undefined) discoverOpts.root = args.root;
  return {
    out: args.out ?? process.stdout,
    err: args.err ?? process.stderr,
    env,
    probe: args.probe ?? probeTenantDashboard,
    discoverOpts,
  };
}

export async function runAgentsCommand(
  args: AgentsCommandArgs
): Promise<number> {
  // Parse --fortress from argv and plumb into discoverOpts.root.
  const fortressIdx = args.argv.indexOf("--fortress");
  if (fortressIdx !== -1 && args.argv[fortressIdx + 1]) {
    args = { ...args, root: args.argv[fortressIdx + 1] };
    // Strip --fortress <path> from argv so subcommands don't see it.
    const filtered = [...args.argv];
    filtered.splice(fortressIdx, 2);
    args = { ...args, argv: filtered };
  }
  const ctx = resolveCtx(args);
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    printAgentsHelp(ctx.out);
    return 0;
  }

  try {
    switch (sub) {
      case "list":
        if (rest.includes("--help") || rest.includes("-h")) {
          printAgentsListHelp(ctx.out);
          return 0;
        }
        return await cmdList(rest, ctx);
      case "show":
        return await cmdShow(rest, ctx);
      case "status":
        return await cmdStatus(rest, ctx);
      case "config":
        return await cmdConfig(rest, ctx);
      default:
        ctx.err.write(`Unknown subcommand: ${sub}\n`);
        printAgentsHelp(ctx.err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    ctx.err.write(`sanctuary agents: ${msg}\n`);
    return 1;
  }
}

export function printAgentsListHelp(s: NodeJS.WritableStream = process.stdout): void {
  s.write(`sanctuary agents list. List every Sanctuary tenant visible on this host.

Usage:
  sanctuary agents list [--json] [--fortress <path>]
  sanctuary agent list [--json] [--fortress <path>]

Description:
  Discovers tenants by scanning the default Sanctuary root, configured extra
  paths, or a single fortress path when --fortress is supplied. Human output
  includes status, dashboard port, webhook port, passphrase source, and storage.

Options:
  --json              Output tenant rows as JSON.
  --fortress <path>   Scope discovery to a specific storage path.
  --help, -h          Show this help.

Examples:
  sanctuary agents list
  sanctuary agents list --fortress ~/.sanctuary-work --json
`);
}

export function printAgentsHelp(s: NodeJS.WritableStream = process.stdout): void {
  s.write(`Usage: sanctuary agents <command> [flags]
       sanctuary agent  <command> [flags]   (alias)

  list [--json]                 List every tenant visible on this host.
  show <tenant> [--json]        Show details for one tenant (includes
                                approval-redirect state).
  status [--json]               One-line-per-tenant running/stopped summary.
  config <tenant> [opts]        Write tenant principal-policy.yaml fields.
    --approval-redirect=<bool>    Toggle cross-harness inbox redirect.
    --approval-redirect-mode=<replace|notify>
                                  Pick replace (bypass underlying channel)
                                  or notify (race both paths). Default
                                  replace when toggled on.

Options:
  --fortress <path>             Scope discovery to a specific storage path
                                instead of scanning ~/.sanctuary.

Tenants are discovered by scanning ~/.sanctuary and any storage paths in
SANCTUARY_AGENTS_EXTRA_PATHS or ~/.sanctuary/agents-extra.json. Tenant
creation is done via \`sanctuary wrap\` with SANCTUARY_STORAGE_PATH set.
See docs/multi-tenancy.md for the full operating guide.
`);
}

function hasJsonFlag(argv: string[]): boolean {
  return argv.includes("--json");
}

function formatRelative(iso: string | null, now: Date = new Date()): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const diffMs = Math.max(0, now.getTime() - then);
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function passphraseLabel(tenant: TenantDescriptor): string {
  switch (tenant.passphrase_status) {
    case "keychain":
      return "keychain";
    case "fallback-file":
      return "fallback-file";
    case "not-initialized":
    default:
      return "not-init";
  }
}

function padRight(s: string, width: number): string {
  if (s.length >= width) return s;
  return s + " ".repeat(width - s.length);
}

// ── list ────────────────────────────────────────────────────────────

async function cmdList(argv: string[], ctx: ResolvedCtx): Promise<number> {
  const json = hasJsonFlag(argv);
  const tenants = await discoverTenants(ctx.discoverOpts);

  if (json) {
    const rows = await Promise.all(
      tenants.map(async (t) => {
        const [probe, lockdown_status] = await Promise.all([
          ctx.probe(t),
          readLockdownStatus(t.storage_path),
        ]);
        return {
          name: t.name,
          storage_path: t.storage_path,
          initialized: t.initialized,
          passphrase_status: t.passphrase_status,
          keychain_service: t.keychain_service,
          dashboard_port: t.runtime?.dashboard_port ?? null,
          webhook_callback_port: t.runtime?.webhook_callback_port ?? null,
          pid: t.runtime?.pid ?? null,
          running: probe.running,
          status: lockdown_status.active
            ? "LOCKED"
            : probe.running
              ? "running"
              : t.initialized
                ? "stopped"
                : "empty",
          lockdown_status,
          last_activity: t.last_activity,
        };
      })
    );
    ctx.out.write(JSON.stringify(rows, null, 2) + "\n");
    return 0;
  }

  if (tenants.length === 0) {
    ctx.out.write("(no Sanctuary tenants found — run `sanctuary wrap` to create one)\n");
    return 0;
  }

  const probes = await Promise.all(tenants.map((t) => ctx.probe(t)));
  const lockdownStatuses = await Promise.all(
    tenants.map((t) => readLockdownStatus(t.storage_path)),
  );
  const rows = tenants.map((t, i) => ({
    tenant: t,
    probe: probes[i]!,
    lockdown: lockdownStatuses[i]!,
  }));

  const nameW = Math.max(4, ...rows.map((r) => r.tenant.name.length));
  const pathW = Math.max(12, ...rows.map((r) => r.tenant.storage_path.length));
  const header =
    padRight("NAME", nameW) +
    "  " +
    padRight("STATUS", 8) +
    padRight("DASH", 6) +
    padRight("HOOK", 6) +
    padRight("PP", 15) +
    padRight("STORAGE", pathW);
  ctx.out.write(header + "\n");

  for (const { tenant, probe, lockdown } of rows) {
    const status = lockdown.active
      ? "LOCKED"
      : probe.running
        ? "running"
        : tenant.initialized
          ? "stopped"
          : "empty";
    const dashboard =
      tenant.runtime?.dashboard_port != null
        ? String(tenant.runtime.dashboard_port)
        : "-";
    const webhook =
      tenant.runtime?.webhook_callback_port != null
        ? String(tenant.runtime.webhook_callback_port)
        : "-";
    const pp = passphraseLabel(tenant);
    ctx.out.write(
      padRight(tenant.name, nameW) +
        "  " +
        padRight(status, 8) +
        padRight(dashboard, 6) +
        padRight(webhook, 6) +
        padRight(pp, 15) +
        padRight(tenant.storage_path, pathW) +
        "\n"
    );
  }

  return 0;
}

// ── show ────────────────────────────────────────────────────────────

async function cmdShow(argv: string[], ctx: ResolvedCtx): Promise<number> {
  const positional = argv.find((a) => !a.startsWith("--"));
  if (!positional) {
    ctx.err.write("Missing tenant. Usage: sanctuary agents show <tenant>\n");
    return 2;
  }
  const tenant = await findTenant(positional, ctx.discoverOpts);
  if (!tenant) {
    ctx.err.write(`sanctuary agents: unknown tenant "${positional}"\n`);
    return 1;
  }
  const probe = await ctx.probe(tenant);
  const approvalRedirect = await readApprovalRedirectState(tenant);
  const payload = {
    name: tenant.name,
    storage_path: tenant.storage_path,
    initialized: tenant.initialized,
    has_cocoon_profile: tenant.has_cocoon_profile,
    keychain_service: tenant.keychain_service,
    passphrase_status: tenant.passphrase_status,
    last_activity: tenant.last_activity,
    runtime: tenant.runtime,
    probe: {
      running: probe.running,
      status: probe.status,
      reason: probe.reason,
    },
    approval_redirect: approvalRedirect,
  };

  if (hasJsonFlag(argv)) {
    ctx.out.write(JSON.stringify(payload, null, 2) + "\n");
    return 0;
  }

  ctx.out.write(`tenant:            ${tenant.name}\n`);
  ctx.out.write(`storage_path:      ${tenant.storage_path}\n`);
  ctx.out.write(`initialized:       ${tenant.initialized ? "yes" : "no"}\n`);
  ctx.out.write(`cocoon-profile:    ${tenant.has_cocoon_profile ? "present" : "absent"}\n`);
  ctx.out.write(`keychain_service:  ${tenant.keychain_service}\n`);
  ctx.out.write(`passphrase:        ${passphraseLabel(tenant)}\n`);
  ctx.out.write(
    `last_activity:     ${tenant.last_activity ?? "never"}${tenant.last_activity ? ` (${formatRelative(tenant.last_activity)})` : ""}\n`
  );
  if (tenant.runtime) {
    ctx.out.write(`runtime:\n`);
    ctx.out.write(`  pid:             ${tenant.runtime.pid}\n`);
    ctx.out.write(`  started_at:      ${tenant.runtime.started_at}\n`);
    ctx.out.write(`  dashboard:       http://${tenant.runtime.dashboard_host}:${tenant.runtime.dashboard_port}\n`);
    if (tenant.runtime.webhook_callback_port != null) {
      const host = tenant.runtime.webhook_callback_host ?? "127.0.0.1";
      ctx.out.write(`  webhook_callback: http://${host}:${tenant.runtime.webhook_callback_port}\n`);
    }
    ctx.out.write(`  mode:            ${tenant.runtime.mode}\n`);
  } else {
    ctx.out.write(`runtime:           (no running process)\n`);
  }
  ctx.out.write(
    `probe:             ${probe.running ? "running" : "not-running"}${probe.reason ? ` (${probe.reason})` : ""}\n`
  );
  ctx.out.write(
    `approval_redirect: ${approvalRedirect.enabled ? `on (${approvalRedirect.mode})` : "off"}\n`,
  );
  return 0;
}

// ── config ──────────────────────────────────────────────────────────

interface ApprovalRedirectState {
  enabled: boolean;
  mode: "replace" | "notify";
}

/**
 * Read the tenant's persisted approval_redirect state. Falls back to the
 * defaults when the policy file is absent or lacks the field.
 *
 * Returns the safe default `{ enabled: false, mode: "replace" }` on any
 * read or parse error so a malformed policy never blocks `agents show`
 * from rendering. The on-disk validation happens at server boot through
 * the loader, which throws on malformed shape.
 */
async function readApprovalRedirectState(
  tenant: TenantDescriptor,
): Promise<ApprovalRedirectState> {
  const policyPath = join(tenant.storage_path, "principal-policy.yaml");
  try {
    const content = await readFile(policyPath, "utf-8");
    const parsed = parsePolicy(content);
    const cfg = parsed.approval_redirect;
    if (!cfg) return { enabled: false, mode: "replace" };
    return {
      enabled: !!cfg.enabled,
      mode: cfg.mode === "notify" ? "notify" : "replace",
    };
  } catch {
    return { enabled: false, mode: "replace" };
  }
}

function parseBoolFlag(raw: string | undefined): boolean | null {
  if (raw === undefined) return null;
  const v = raw.toLowerCase();
  if (v === "true" || v === "yes" || v === "on" || v === "1") return true;
  if (v === "false" || v === "no" || v === "off" || v === "0") return false;
  return null;
}

function findFlagValue(argv: string[], name: string): string | undefined {
  // Accept both `--flag=value` and `--flag value`.
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === name) {
      return argv[i + 1];
    }
    const eq = `${name}=`;
    if (a.startsWith(eq)) {
      return a.slice(eq.length);
    }
  }
  return undefined;
}

async function cmdConfig(argv: string[], ctx: ResolvedCtx): Promise<number> {
  const positional = argv.find((a) => !a.startsWith("--"));
  if (!positional) {
    ctx.err.write(
      "Missing tenant. Usage: sanctuary agents config <tenant> --approval-redirect=<bool>\n",
    );
    return 2;
  }
  const tenant = await findTenant(positional, ctx.discoverOpts);
  if (!tenant) {
    ctx.err.write(`sanctuary agents: unknown tenant "${positional}"\n`);
    return 1;
  }

  const redirectFlag = parseBoolFlag(
    findFlagValue(argv, "--approval-redirect"),
  );
  const modeFlag = findFlagValue(argv, "--approval-redirect-mode");

  if (redirectFlag === null && modeFlag === undefined) {
    ctx.err.write(
      "sanctuary agents config: nothing to do. Pass --approval-redirect=<bool> or --approval-redirect-mode=<replace|notify>.\n",
    );
    return 2;
  }

  if (modeFlag !== undefined && modeFlag !== "replace" && modeFlag !== "notify") {
    ctx.err.write(
      `sanctuary agents config: --approval-redirect-mode must be "replace" or "notify" (got "${modeFlag}")\n`,
    );
    return 2;
  }

  const current = await readApprovalRedirectState(tenant);
  const next: ApprovalRedirectState = {
    enabled: redirectFlag !== null ? redirectFlag : current.enabled,
    mode:
      modeFlag === "notify" || modeFlag === "replace"
        ? modeFlag
        : current.mode,
  };

  await writeApprovalRedirectToPolicyFile(tenant.storage_path, next);

  try {
    const fortressId = fortressIdFromStoragePath(tenant.storage_path);
    const storage = new FilesystemStorage(`${tenant.storage_path}/state`);
    let passphrase = ctx.env.SANCTUARY_PASSPHRASE;
    if (!passphrase) {
      const stored = await readStoredPassphrase({ storagePath: tenant.storage_path });
      if (stored) passphrase = stored.value;
    }
    if (passphrase) {
      let existingParams: KeyDerivationParams | undefined;
      try {
        const raw = await storage.read("_meta", "key-params");
        if (raw) existingParams = JSON.parse(bytesToString(raw));
      } catch { /* no key-params yet */ }
      const { key: masterKey, params } = await deriveMasterKey(passphrase, existingParams);
      if (!existingParams) {
        await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
      }
      const auditLog = new AuditLog(storage, masterKey);
      auditLog.append("l2", "agents.config", `fortress:${fortressId}`, {
        tenant: tenant.name,
        approval_redirect: next,
        previous: current,
      });
    }
  } catch { /* audit best-effort; do not block config write */ }

  if (hasJsonFlag(argv)) {
    ctx.out.write(
      JSON.stringify(
        {
          tenant: tenant.name,
          approval_redirect: next,
        },
        null,
        2,
      ) + "\n",
    );
  } else {
    ctx.out.write(
      `sanctuary agents config: tenant "${tenant.name}" approval_redirect=${next.enabled ? `on (${next.mode})` : "off"}\n`,
    );
    ctx.out.write(
      `  Takes effect on the next gate request for the running server.\n`,
    );
  }
  return 0;
}

/**
 * Write the `approval_redirect` block into the tenant's
 * principal-policy.yaml. Preserves any other fields and surrounding
 * comments via targeted line-range replacement; falls back to appending
 * a fresh block when the file lacks one. Idempotent.
 *
 * If the policy file does not exist (tenant not yet booted), creates it
 * from the loader-default shape and writes the new block. The next
 * `sanctuary` boot loads the file as written here.
 */
async function writeApprovalRedirectToPolicyFile(
  storagePath: string,
  state: ApprovalRedirectState,
): Promise<void> {
  const policyPath = join(storagePath, "principal-policy.yaml");
  let content: string;
  try {
    content = await readFile(policyPath, "utf-8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code !== "ENOENT") throw err;
    // Generate a minimal default shape so this command works on a tenant
    // that has been wrapped but not yet booted.
    content = await defaultPolicyTextForBootstrap();
  }

  const block = renderApprovalRedirectBlock(state);
  const updated = upsertApprovalRedirectBlock(content, block);

  await writeFile(policyPath, updated, "utf-8");
  await chmod(policyPath, 0o600);
}

function renderApprovalRedirectBlock(state: ApprovalRedirectState): string {
  return [
    "# Approval Redirect (v1.3 WP-V1.3-10 Upsilon-2)",
    "approval_redirect:",
    `  enabled: ${state.enabled ? "true" : "false"}`,
    `  mode: ${state.mode}`,
  ].join("\n");
}

/**
 * Replace any existing `approval_redirect:` block with `block`, or append
 * `block` to the end of the file. The simple matcher looks for a line
 * starting with `approval_redirect:` (no leading whitespace) and treats
 * subsequent indented lines plus the immediately preceding heading
 * comment as part of the block.
 */
function upsertApprovalRedirectBlock(content: string, block: string): string {
  const lines = content.split("\n");
  const startIdx = lines.findIndex((l) => l.startsWith("approval_redirect:"));
  if (startIdx === -1) {
    const trimmed = content.endsWith("\n") ? content : content + "\n";
    return trimmed + "\n" + block + "\n";
  }
  // Walk backward absorbing the preceding heading-comment line if any.
  let blockStart = startIdx;
  if (
    blockStart > 0 &&
    lines[blockStart - 1] !== undefined &&
    lines[blockStart - 1]!.startsWith("# Approval Redirect")
  ) {
    blockStart = blockStart - 1;
  }
  // Walk forward to find the end of the block (next non-indented non-empty
  // line, or EOF).
  let blockEnd = startIdx + 1;
  while (blockEnd < lines.length) {
    const l = lines[blockEnd]!;
    if (l === "") {
      blockEnd++;
      continue;
    }
    if (/^[A-Za-z0-9#]/.test(l)) {
      break;
    }
    blockEnd++;
  }
  const before = lines.slice(0, blockStart);
  const after = lines.slice(blockEnd);
  const replaced = [...before, ...block.split("\n"), ...after].join("\n");
  return replaced.endsWith("\n") ? replaced : replaced + "\n";
}

async function defaultPolicyTextForBootstrap(): Promise<string> {
  // Inline minimal stub matching the loader's required-keys contract.
  return [
    "version: 1",
    "tier1_always_approve:",
    "  - state_export",
    "  - state_import",
    "  - state_delete",
    "approval_channel:",
    "  type: stderr",
    "  timeout_seconds: 300",
    "",
  ].join("\n");
}

// ── status ──────────────────────────────────────────────────────────

async function cmdStatus(argv: string[], ctx: ResolvedCtx): Promise<number> {
  const tenants = await discoverTenants(ctx.discoverOpts);
  const probes = await Promise.all(tenants.map((t) => ctx.probe(t)));
  const rows = tenants.map((t, i) => ({ tenant: t, probe: probes[i]! }));

  if (hasJsonFlag(argv)) {
    ctx.out.write(
      JSON.stringify(
        rows.map(({ tenant, probe }) => ({
          name: tenant.name,
          running: probe.running,
          initialized: tenant.initialized,
          dashboard_port: tenant.runtime?.dashboard_port ?? null,
          last_activity: tenant.last_activity,
        })),
        null,
        2
      ) + "\n"
    );
    return 0;
  }

  if (rows.length === 0) {
    ctx.out.write("(no Sanctuary tenants found)\n");
    return 0;
  }

  const nameW = Math.max(4, ...rows.map((r) => r.tenant.name.length));
  for (const { tenant, probe } of rows) {
    const state = probe.running ? "running" : tenant.initialized ? "stopped" : "empty";
    const dash =
      tenant.runtime?.dashboard_port != null
        ? `:${tenant.runtime.dashboard_port}`
        : "";
    const last = tenant.last_activity
      ? ` · last ${formatRelative(tenant.last_activity)}`
      : "";
    ctx.out.write(
      `${padRight(tenant.name, nameW)}  ${padRight(state, 8)}${dash}${last}\n`
    );
  }
  return 0;
}
