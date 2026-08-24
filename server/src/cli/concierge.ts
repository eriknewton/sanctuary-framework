import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { readTenantRuntime } from "./agents/runtime.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { loadConfig } from "../config.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { IdentityManager } from "../cognitive/tools.js";
import { StateStore } from "../cognitive/state-store.js";
import { AuditLog } from "../operational/audit-log.js";
import { TaskService } from "../operational/task-coordination/index.js";
import {
  ConciergeReadError,
  ConciergeService,
  ConciergeUnavailableError,
  SanctuaryContextReader,
  type ConciergeAskResponse,
  type ConciergeStatus,
} from "../concierge/index.js";
import { SubstrateSelector } from "../intelligence/index.js";
import { consumeFlagValue, unknownFlagWithPrefix } from "./argv.js";

export interface ConciergeCliArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Test seam; production always constructs the fortress selector below. */
  localServiceFactory?: (env: NodeJS.ProcessEnv) => Promise<ConciergeService>;
}

interface ConciergeCliContext {
  argv: string[];
  dashboardUrl?: string;
}

const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

export async function runConciergeCommand(args: ConciergeCliArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  try {
    const ctx = await resolveContext(args.argv, err);
    if (!ctx) return 2;
    const [sub, ...rest] = ctx.argv;
    if (!sub || sub === "--help" || sub === "-h") {
      printUsage(out);
      return 0;
    }
    if (sub === "ask") return ask(rest, out, err, env, ctx, args.localServiceFactory);
    if (sub === "status") return status(rest, out, err, env, ctx, args.localServiceFactory);
    err.write(`Unknown concierge subcommand: ${sub}\n`);
    printUsage(err);
    return 2;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    err.write(`sanctuary concierge: ${message}\n`);
    return cause instanceof ConciergeReadError || cause instanceof ConciergeUnavailableError
      ? 1
      : 1;
  }
}

function printUsage(s: Writable): void {
  s.write(`Usage: sanctuary concierge <command> [args]

  ask "<question>" [--fortress <path>] [--json] [--no-stream] [--include-payloads]
  status [--fortress <path>] [--json]

Options:
  --fortress <path>      Use the dashboard runtime recorded for this fortress, or read that fortress directly when passphrase material is present.
  --json                 Output machine-readable JSON.
  --no-stream            Return the full answer at the end.
  --include-payloads     Include state-store payloads in local read context.

Env: SANCTUARY_DASHBOARD_URL, SANCTUARY_DASHBOARD_AUTH_TOKEN, SANCTUARY_PASSPHRASE, SANCTUARY_RECOVERY_KEY
`);
}

async function ask(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
  ctx: ConciergeCliContext,
  localServiceFactory?: (env: NodeJS.ProcessEnv) => Promise<ConciergeService>,
): Promise<number> {
  const question = firstPositional(argv);
  if (!question) {
    err.write("concierge ask requires a question\n");
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const stream = !hasFlag(argv, "--no-stream") && !json;
  const payload = {
    question,
    stream,
    includePayloads: hasFlag(argv, "--include-payloads"),
  };
  const response = ctx.dashboardUrl || env.SANCTUARY_DASHBOARD_URL
    ? await askViaHub(payload, ctx)
    : await askLocal(payload, out, env, localServiceFactory);

  if (json) {
    out.write(JSON.stringify(response, null, 2) + "\n");
  } else if (!stream) {
    out.write(response.answer.trimEnd() + "\n");
  } else {
    out.write("\n");
  }
  return 0;
}

async function status(
  _argv: string[],
  out: Writable,
  _err: Writable,
  env: NodeJS.ProcessEnv,
  ctx: ConciergeCliContext,
  localServiceFactory?: (env: NodeJS.ProcessEnv) => Promise<ConciergeService>,
): Promise<number> {
  const json = hasFlag(ctx.argv, "--json");
  const result = ctx.dashboardUrl || env.SANCTUARY_DASHBOARD_URL
    ? await statusViaHub(ctx)
    : await (await (localServiceFactory ?? createLocalService)(env)).status();
  if (json) {
    out.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    out.write(`provider: ${result.provider}\n`);
    out.write(`configured: ${result.configured ? "yes" : "no"}\n`);
    out.write(`reachable: ${result.reachable ? "yes" : "no"}\n`);
    out.write(`model: ${result.model}\n`);
    out.write(`read_surfaces: ${result.read_surfaces.join(", ")}\n`);
    out.write(`fallback: ${result.fallback}\n`);
    out.write(`message: ${result.message}\n`);
  }
  return 0;
}

async function askViaHub(
  payload: { question: string; stream: boolean; includePayloads: boolean },
  ctx: ConciergeCliContext,
): Promise<ConciergeAskResponse> {
  const body = await request("/api/hub/concierge/ask", {
    method: "POST",
    body: JSON.stringify(payload),
  }, ctx);
  return (body.data?.response ?? body.data ?? body) as ConciergeAskResponse;
}

async function statusViaHub(ctx: ConciergeCliContext): Promise<ConciergeStatus> {
  const body = await request("/api/hub/concierge/status", undefined, ctx);
  return (body.data?.status ?? body.data ?? body) as ConciergeStatus;
}

async function askLocal(
  payload: { question: string; stream: boolean; includePayloads: boolean },
  out: Writable,
  env: NodeJS.ProcessEnv,
  localServiceFactory?: (env: NodeJS.ProcessEnv) => Promise<ConciergeService>,
): Promise<ConciergeAskResponse> {
  const service = await (localServiceFactory ?? createLocalService)(env);
  return service.ask(payload, payload.stream ? (token) => out.write(token) : undefined);
}

async function createLocalService(env: NodeJS.ProcessEnv): Promise<ConciergeService> {
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(config.storage_path, "state"));
  const masterKey = await resolveMasterKey(storage, env);
  const identityManager = new IdentityManager(storage, masterKey);
  const loaded = await identityManager.load();
  if (loaded.loaded === 0) {
    throw new ConciergeReadError("no readable identities found for this fortress");
  }
  const identity = identityManager.getDefault();
  if (!identity) throw new ConciergeReadError("no primary identity found");
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey, { integrityMode: "strict" });
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: identity.identity_id,
  });
  await selector.load();
  const taskService = new TaskService({
    stateStore,
    auditLog,
    fortressId: config.storage_path,
    identityId: identity.identity_id,
    signingIdentity: identity,
    identityEncryptionKey: derivePurposeKey(masterKey, "identity-encryption"),
  });
  const reader = new SanctuaryContextReader({
    auditLog,
    identityManager,
    stateStore,
    taskService,
    config,
    storagePath: config.storage_path,
    fortressId: config.storage_path,
    identityId: identity.identity_id,
    inboxSources: emptyInboxSources(),
    policyBudgetSources: emptyPolicyBudgetSources(),
  });
  return new ConciergeService({
    reader,
    selector,
  });
}

async function resolveMasterKey(
  storage: FilesystemStorage,
  env: NodeJS.ProcessEnv,
): Promise<Uint8Array> {
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  if (env.SANCTUARY_PASSPHRASE) {
    return resolveCliMasterKey(storage, { passphrase: env.SANCTUARY_PASSPHRASE });
  }
  if (env.SANCTUARY_RECOVERY_KEY) {
    return resolveCliMasterKey(storage, { recoveryKey: env.SANCTUARY_RECOVERY_KEY });
  }
  throw new ConciergeReadError(
    "local concierge reads require SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY",
  );
}

interface ConciergeHubBody {
  ok?: boolean;
  error?: unknown;
  detail?: unknown;
  data?: { response?: unknown; status?: unknown };
}

async function request(
  path: string,
  init?: RequestInit,
  ctx?: ConciergeCliContext,
): Promise<ConciergeHubBody> {
  const base = (ctx?.dashboardUrl ?? process.env.SANCTUARY_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL).replace(/\/$/, "");
  const token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${base}${path}`, { ...init, headers });
  const body = (await res.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: unknown;
    detail?: unknown;
  };
  if (!res.ok || body.ok === false) {
    throw new Error(
      body.detail ? String(body.detail) : body.error ? String(body.error) : `HTTP ${res.status}`,
    );
  }
  return body;
}

async function resolveContext(
  argv: string[],
  err: Writable,
): Promise<ConciergeCliContext | null> {
  const unknownFortressFlag = unknownFlagWithPrefix(argv, "--fortress");
  if (unknownFortressFlag) {
    err.write(`concierge unknown fortress flag ${unknownFortressFlag}\n`);
    return null;
  }
  const parsed = consumeFlagValue(argv, "--fortress");
  if (parsed.error) {
    err.write(`concierge ${parsed.error}\n`);
    return null;
  }
  if (parsed.value === undefined) return { argv: parsed.argv };
  const fortress = parsed.value;
  process.env.SANCTUARY_STORAGE_PATH = fortress;
  const runtime = await readTenantRuntime(fortress);
  return {
    argv: parsed.argv,
    ...(runtime
      ? { dashboardUrl: `http://${runtime.dashboard_host}:${runtime.dashboard_port}` }
      : {}),
  };
}

function firstPositional(argv: string[]): string | null {
  for (let i = 0; i < argv.length; i++) {
    const current = argv[i]!;
    if (current.startsWith("--")) {
      if (current !== "--json" && current !== "--no-stream" && current !== "--include-payloads") i++;
      continue;
    }
    return current;
  }
  return null;
}

function hasFlag(argv: string[], flag: string): boolean {
  return argv.includes(flag);
}

function emptyInboxSources() {
  return {
    listPendingApprovals: () => [],
    listRecentBlockedEgress: () => [],
    listRecentPrivacyEvents: () => [],
    listActiveBudgetWarnings: () => [],
    listActiveRecoveryPrompts: () => [],
    listRecentAgentErrors: () => [],
  };
}

function emptyPolicyBudgetSources() {
  return {
    listPolicySummaries: () => [],
    listBudgetSummaries: () => [],
  };
}
