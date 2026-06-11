/**
 * `sanctuary status` — unified daemon status (Federation PR-A1).
 *
 * The first locked Wave 1 MVP CLI verb to go API-backed: opens an RFC v7
 * challenge-response session against the local daemon and renders
 * GET /v1/status. Catalog contract (API Parity Catalog §4):
 *
 *   sanctuary status [--output json|yaml|table] [--verbose]
 *
 * Output schema: { ok, version, daemon, listener, federation, identity,
 * castle_wall }. Exit codes: 0 success; 1 user error / invalid args;
 * 2 daemon unavailable / system error; 3 auth failure (failed ceremony /
 * expired session); 4 not authorized / capability denied.
 */

import { Writable } from "node:stream";
import {
  dashboardRequest,
  DashboardRequestError,
  type DashboardRequestContext,
} from "./dashboard-request.js";
import { openV1Session } from "./v1-session.js";

export interface StatusCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  /** Dashboard base URL override (tests); env SANCTUARY_DASHBOARD_URL also works. */
  dashboardUrl?: string;
}

type OutputMode = "table" | "json" | "yaml";

const HELP = `sanctuary status. Unified daemon status over the /v1 API.

Usage: sanctuary status [--output json|yaml|table] [--verbose]

Options:
  --output <mode>   Output format: table (default), json, yaml
  --verbose         Reserved; accepted for forward compatibility
  --help, -h        Show this help

Opens a challenge-response session with the local Sanctuary daemon
(SANCTUARY_DASHBOARD_URL, default http://127.0.0.1:3502) and reports
daemon, listener, federation, identity, and Castle Wall state.

Exit codes:
  0  success
  1  invalid arguments
  2  daemon unavailable or system error
  3  auth failure (challenge-response ceremony denied / session expired)
  4  not authorized (capability denied)
`;

export async function runStatusCommand(args: StatusCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;

  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    out.write(HELP);
    return 0;
  }

  let output: OutputMode = "table";
  for (let i = 0; i < args.argv.length; i++) {
    const arg = args.argv[i]!;
    if (arg === "--output") {
      const value = args.argv[i + 1];
      if (value !== "json" && value !== "yaml" && value !== "table") {
        err.write(
          `sanctuary status: --output must be json, yaml, or table\nnext: run \`sanctuary status --help\`\n`,
        );
        return 1;
      }
      output = value;
      i++;
    } else if (arg.startsWith("--output=")) {
      const value = arg.slice("--output=".length);
      if (value !== "json" && value !== "yaml" && value !== "table") {
        err.write(
          `sanctuary status: --output must be json, yaml, or table\nnext: run \`sanctuary status --help\`\n`,
        );
        return 1;
      }
      output = value;
    } else if (arg === "--verbose") {
      // Reserved (catalog flag); full status is already the verbose view.
    } else {
      err.write(
        `sanctuary status: unknown option ${arg}\nnext: run \`sanctuary status --help\`\n`,
      );
      return 1;
    }
  }

  const ctx: DashboardRequestContext = {};
  if (args.dashboardUrl !== undefined) ctx.dashboardUrl = args.dashboardUrl;

  let status: Record<string, unknown>;
  try {
    const session = await openV1Session(ctx);
    status = (await dashboardRequest("/v1/status", undefined, {
      ...ctx,
      authToken: session.token,
    })) as Record<string, unknown>;
  } catch (cause) {
    return renderFailure(cause, err);
  }

  if (output === "json") {
    out.write(`${JSON.stringify(status, null, 2)}\n`);
  } else if (output === "yaml") {
    out.write(toYaml(status));
  } else {
    out.write(renderTable(status));
  }
  return 0;
}

function renderFailure(cause: unknown, err: Writable): number {
  if (cause instanceof DashboardRequestError) {
    if (cause.kind === "auth") {
      const code = cause.status === 403 ? 4 : 3;
      err.write(
        `sanctuary status: ${code === 4 ? "capability denied for this client" : "session ceremony denied"}\n` +
          `next: check SANCTUARY_DASHBOARD_AUTH_TOKEN, then re-run \`sanctuary status\`\n`,
      );
      return code;
    }
    if (cause.kind === "not-implemented") {
      err.write(
        `sanctuary status: this daemon does not serve /v1/status (upgrade or restart the dashboard)\n` +
          `next: restart the Sanctuary dashboard on a build that includes the /v1 API\n`,
      );
      return 2;
    }
    err.write(
      `sanctuary status: daemon unavailable\n` +
        `next: start the dashboard (\`sanctuary dashboard\`) or set SANCTUARY_DASHBOARD_URL\n` +
        `linux service: \`systemctl status sanctuary\`\n`,
    );
    return 2;
  }
  err.write(
    `sanctuary status: ${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  return 2;
}

function renderTable(status: Record<string, unknown>): string {
  const daemon = asRecord(status.daemon);
  const listener = asRecord(status.listener);
  const federation = asRecord(status.federation);
  const identity = asRecord(status.identity);
  const castleWall = asRecord(status.castle_wall);

  const lines = [
    `Sanctuary daemon status`,
    `  ok:           ${status.ok === true ? "yes" : "no"}`,
    `  version:      ${str(status.version)}`,
    `  daemon:       ${str(daemon?.mode)}${daemon?.pid !== undefined ? ` (pid ${str(daemon.pid)})` : ""}`,
    `  listener:     ${str(listener?.host)}:${str(listener?.port)} (${listener?.tls === true ? "https" : "http"})`,
    `  federation:   ${federation?.enabled === true ? "enabled" : "disabled"}`,
    `  identity:     ${identity ? `${str(identity.label)} (${str(identity.did)})` : "none"}`,
    `  castle wall:  ${str(castleWall?.status)}`,
  ];
  return `${lines.join("\n")}\n`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function str(value: unknown): string {
  if (value === undefined || value === null) return "unknown";
  return String(value);
}

/**
 * Minimal YAML rendering for plain JSON data (objects, arrays, scalars).
 * Sufficient for the /v1/status document; no dependency added.
 */
export function toYaml(value: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);
  if (value === null || value === undefined) return `${pad}null\n`;
  if (typeof value !== "object") return `${pad}${yamlScalar(value)}\n`;
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]\n`;
    return value
      .map((item) => {
        if (typeof item === "object" && item !== null) {
          return `${pad}-\n${toYaml(item, indent + 1)}`;
        }
        return `${pad}- ${yamlScalar(item)}\n`;
      })
      .join("");
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return `${pad}{}\n`;
  return entries
    .map(([key, item]) => {
      if (typeof item === "object" && item !== null) {
        const nested = toYaml(item, indent + 1);
        return `${pad}${key}:\n${nested}`;
      }
      return `${pad}${key}: ${yamlScalar(item)}\n`;
    })
    .join("");
}

function yamlScalar(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") {
    // Quote anything that could parse as a non-string or contains
    // structure characters.
    if (/^[A-Za-z0-9._/-]+$/.test(value) && !/^(true|false|null|~|[0-9.+-]+)$/i.test(value)) {
      return value;
    }
    return JSON.stringify(value);
  }
  return String(value);
}
