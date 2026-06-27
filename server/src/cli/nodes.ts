import type { Writable } from "node:stream";
import {
  dashboardRequest,
  DashboardRequestError,
  type DashboardRequestContext,
} from "./dashboard-request.js";

interface NodesFlags {
  dashboardUrl?: string;
  sessionToken?: string;
  output: "json" | "table";
}

function parseNodesFlags(argv: string[], env: NodeJS.ProcessEnv): NodesFlags | null {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const output = flag("--output") ?? "table";
  if (output !== "json" && output !== "table") return null;
  return {
    dashboardUrl: flag("--dashboard-url") ?? env.SANCTUARY_DASHBOARD_URL,
    sessionToken: flag("--session-token") ?? env.SANCTUARY_V1_SESSION_TOKEN,
    output,
  };
}

const HELP = `sanctuary nodes — federated node inventory

Usage:
  sanctuary nodes list [--dashboard-url <url>] [--session-token <token>] [--output json|table]

Environment:
  SANCTUARY_DASHBOARD_URL     Local daemon URL (default http://127.0.0.1:3502)
  SANCTUARY_V1_SESSION_TOKEN  Short-lived /v1 session token
`;

export async function runNodesCommand(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
}): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const sub = argv[0];
  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    out.write(HELP);
    return 0;
  }
  if (sub !== "list") {
    err.write(`sanctuary nodes: unknown subcommand "${sub}"\n\n${HELP}`);
    return 1;
  }

  const flags = parseNodesFlags(argv.slice(1), args.env ?? process.env);
  if (!flags) {
    err.write("sanctuary nodes list: --output must be json or table\n");
    return 1;
  }
  if (!flags.sessionToken) {
    err.write("sanctuary nodes list: --session-token or SANCTUARY_V1_SESSION_TOKEN is required\n");
    return 3;
  }

  const ctx: DashboardRequestContext = {
    dashboardUrl: flags.dashboardUrl,
    authToken: flags.sessionToken,
  };
  try {
    const body = (await (args.request ?? dashboardRequest)("/v1/nodes", {}, ctx)) as {
      nodes?: unknown;
      total?: unknown;
    };
    const nodes = Array.isArray(body.nodes) ? body.nodes : [];
    if (flags.output === "json") {
      out.write(`${JSON.stringify({ nodes, total: body.total ?? nodes.length }, null, 2)}\n`);
      return 0;
    }
    out.write(renderTable(nodes as Array<Record<string, unknown>>));
    return 0;
  } catch (cause) {
    if (cause instanceof DashboardRequestError) {
      err.write(`sanctuary nodes list: ${cause.message}\n`);
      return cause.kind === "auth" ? 3 : 2;
    }
    err.write(`sanctuary nodes list: unexpected error: ${String(cause)}\n`);
    return 1;
  }
}

function renderTable(nodes: Array<Record<string, unknown>>): string {
  if (nodes.length === 0) return "NODE ID  MODE     TRUST BOUNDARY  STATUS  LAST SYNC\n";
  const rows = nodes.map((node) => {
    const sync = node.last_sync as Record<string, unknown> | undefined;
    const boundary = node.trust_boundary as Record<string, unknown> | undefined;
    return [
      String(node.node_id ?? ""),
      String(node.node_mode ?? "unknown"),
      String(boundary?.label ?? "unknown"),
      String(node.attestation_status ?? "unknown"),
      String(sync?.received_at ?? sync?.sent_at ?? "never"),
    ];
  });
  return [
    "NODE ID  MODE     TRUST BOUNDARY  STATUS    LAST SYNC",
    ...rows.map(([id, mode, boundary, status, last]) =>
      `${id}  ${mode}  ${boundary}  ${status}  ${last}`
    ),
  ].join("\n") + "\n";
}
