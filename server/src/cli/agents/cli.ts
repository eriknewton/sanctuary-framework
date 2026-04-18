/**
 * Sanctuary MCP Server — `sanctuary agents` CLI subcommand
 *
 * Read-only inventory for multi-tenant hosts. Three verbs:
 *
 *   - `list`    human table / JSON listing of every tenant Sanctuary sees.
 *   - `show <tenant>` details for one tenant (paths, keychain service name,
 *               passphrase status, runtime state, last activity).
 *   - `status`  one-line-per-tenant summary (running / stopped + counts).
 *
 * Everything here is derivable from the filesystem + optional runtime.json
 * files. No tenant secrets or identity private keys are ever decrypted.
 */

import {
  discoverTenants,
  findTenant,
  type TenantDescriptor,
} from "./discovery.js";
import { probeTenantDashboard, type HealthProbeResult } from "./health.js";

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
  const ctx = resolveCtx(args);
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    printUsage(ctx.out);
    return 0;
  }

  try {
    switch (sub) {
      case "list":
        return await cmdList(rest, ctx);
      case "show":
        return await cmdShow(rest, ctx);
      case "status":
        return await cmdStatus(rest, ctx);
      default:
        ctx.err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(ctx.err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    ctx.err.write(`sanctuary agents: ${msg}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary agents <command> [flags]

  list [--json]                 List every tenant visible on this host.
  show <tenant> [--json]        Show details for one tenant.
  status [--json]               One-line-per-tenant running/stopped summary.

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
      tenants.map(async (t) => ({
        name: t.name,
        storage_path: t.storage_path,
        initialized: t.initialized,
        passphrase_status: t.passphrase_status,
        keychain_service: t.keychain_service,
        dashboard_port: t.runtime?.dashboard_port ?? null,
        webhook_callback_port: t.runtime?.webhook_callback_port ?? null,
        pid: t.runtime?.pid ?? null,
        running: (await ctx.probe(t)).running,
        last_activity: t.last_activity,
      }))
    );
    ctx.out.write(JSON.stringify(rows, null, 2) + "\n");
    return 0;
  }

  if (tenants.length === 0) {
    ctx.out.write("(no Sanctuary tenants found — run `sanctuary wrap` to create one)\n");
    return 0;
  }

  const probes = await Promise.all(tenants.map((t) => ctx.probe(t)));
  const rows = tenants.map((t, i) => ({
    tenant: t,
    probe: probes[i]!,
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

  for (const { tenant, probe } of rows) {
    const status = probe.running ? "running" : tenant.initialized ? "stopped" : "empty";
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
  return 0;
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
