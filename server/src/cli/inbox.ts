export interface InboxCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
}

const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

export async function runInboxCommand(args: InboxCliArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
  }

  try {
    switch (sub) {
      case "list":
        return await list(rest, out);
      case "show":
        return await show(rest, out, err);
      case "archive":
      case "dismiss":
        return await batch(sub, rest, out, err);
      case "snooze":
        return await snooze(rest, out, err);
      case "retention":
        return await retention(rest, out, err);
      default:
        err.write(`Unknown inbox subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (cause) {
    err.write(`sanctuary inbox: ${cause instanceof Error ? cause.message : String(cause)}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary inbox <command> [args]

  list [--source-class X] [--severity Y] [--agent Z] [--state active|archived|snoozed|dismissed]
  show <entry_id>
  archive <entry_id> [<entry_id>...]
  dismiss <entry_id> [<entry_id>...]
  snooze <entry_id> --until <ISO8601>
  retention show
  retention set --source-class blocked_egress --state archived --days 30

Env: SANCTUARY_DASHBOARD_URL, SANCTUARY_DASHBOARD_AUTH_TOKEN
`);
}

async function list(argv: string[], out: NodeJS.WritableStream): Promise<number> {
  const qs = new URLSearchParams();
  setFlag(qs, "source_class", argv, "--source-class");
  setFlag(qs, "severity", argv, "--severity");
  setFlag(qs, "agent_id", argv, "--agent");
  setFlag(qs, "state", argv, "--state");
  const body = await request(`/api/inbox/unified?${qs.toString()}`);
  const entries = body.data?.entries ?? [];
  for (const entry of entries) {
    out.write(`${entry.inbox_id} ${entry.state ?? "active"} ${entry.severity} ${entry.source_class} ${entry.agent_id ?? "-"} ${entry.summary}\n`);
  }
  return 0;
}

async function show(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
): Promise<number> {
  const id = argv[0];
  if (!id) {
    err.write("inbox show requires an entry_id\n");
    return 2;
  }
  const body = await request(`/api/inbox/unified/${encodeURIComponent(id)}`);
  out.write(JSON.stringify(body.data?.entry ?? body, null, 2) + "\n");
  return 0;
}

async function batch(
  action: "archive" | "dismiss",
  ids: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
): Promise<number> {
  if (ids.length === 0) {
    err.write(`inbox ${action} requires at least one entry_id\n`);
    return 2;
  }
  const body = await request("/api/inbox/unified/batch", {
    method: "POST",
    body: JSON.stringify({ action, entry_ids: ids }),
  });
  out.write(JSON.stringify(body.data?.result ?? body, null, 2) + "\n");
  return 0;
}

async function snooze(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
): Promise<number> {
  const id = argv[0];
  const until = flagValue(argv, "--until");
  if (!id || !until) {
    err.write("inbox snooze requires <entry_id> --until <ISO8601>\n");
    return 2;
  }
  const body = await request("/api/inbox/unified/batch", {
    method: "POST",
    body: JSON.stringify({ action: "snooze", entry_ids: [id], until }),
  });
  out.write(JSON.stringify(body.data?.result ?? body, null, 2) + "\n");
  return 0;
}

async function retention(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
): Promise<number> {
  const sub = argv[0];
  if (sub === "show") {
    const body = await request("/api/inbox/retention");
    out.write(JSON.stringify(body.data ?? body, null, 2) + "\n");
    return 0;
  }
  if (sub === "set") {
    const sourceClass = flagValue(argv, "--source-class");
    const state = flagValue(argv, "--state");
    const days = flagValue(argv, "--days");
    if (!sourceClass || !state || !days) {
      err.write("retention set requires --source-class, --state, and --days\n");
      return 2;
    }
    const body = await request(
      `/api/inbox/retention/${encodeURIComponent(sourceClass)}/${encodeURIComponent(state)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ retain_for_days: Number(days) }),
      },
    );
    out.write(JSON.stringify(body.data?.policy ?? body, null, 2) + "\n");
    return 0;
  }
  err.write("Unknown retention subcommand\n");
  return 2;
}

async function request(path: string, init?: RequestInit): Promise<any> {
  const base = (process.env.SANCTUARY_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL).replace(/\/$/, "");
  const token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${base}${path}`, { ...init, headers });
  const body = (await res.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: unknown;
  };
  if (!res.ok || body.ok === false) {
    throw new Error(body.error ? String(body.error) : `HTTP ${res.status}`);
  }
  return body;
}

function setFlag(
  qs: URLSearchParams,
  key: string,
  argv: string[],
  flag: string,
): void {
  const value = flagValue(argv, flag);
  if (value) qs.set(key, value);
}

function flagValue(argv: string[], flag: string): string | null {
  const idx = argv.indexOf(flag);
  if (idx < 0 || idx + 1 >= argv.length) return null;
  return argv[idx + 1] ?? null;
}
