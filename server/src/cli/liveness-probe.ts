/**
 * `sanctuary liveness-probe`
 *
 * Runs the confined as-uid reachability differential and prints the outcome.
 */

import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";

import { resolveStoragePath } from "../paths.js";
import { readFileCustody } from "../storage/custody-fs.js";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import {
  HERMES_ENDPOINT_SET,
  readEgressRulesFromDisk,
  type EndpointStaticCheck,
  verifyProvisionedEgressStatically,
} from "../castle-wall/provision/index.js";
import {
  cosLivenessFromReachabilityReport,
  isVerifiedCosLivenessReachabilityEvidence,
  type CosLivenessOutcome,
} from "../castle-wall/provision/orchestrate.js";
import { collectSystemResolvers } from "../castle-wall/runtime/system-resolvers.js";
import { runAgentEgressProbesAsUid } from "../wrap/auto-provision.js";

const execFileAsync = promisify(execFile);

type ProbeExecFile = (
  file: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string }>;

export interface LivenessProbeCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Test seam. Production uses the existing sudo/curl as-uid prober. */
  execFileFn?: ProbeExecFile;
  /** Test seam. Production reads the host's current resolver set. */
  collectSystemResolvers?: () => Promise<readonly unknown[]>;
  now?: () => Date;
}

interface LivenessProbeOptions {
  fortress?: string;
  json: boolean;
  help: boolean;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runLivenessProbeCommand(args: LivenessProbeCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  let parsed: LivenessProbeOptions;
  try {
    parsed = parseLivenessProbeArgs(args.argv);
  } catch (parseErr) {
    write(err, `${(parseErr as Error).message}\n`);
    printUsage(err);
    return 2;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const fortressPath = parsed.fortress ?? resolveStoragePath(env);
  try {
    await assertFortressBaseReadable(fortressPath);
    const uid = await readCommittedAgentUid(fortressPath);
    const committedEndpoints = await verifyCommittedAllowlist({
      fortressPath,
      collectResolvers: args.collectSystemResolvers ?? collectSystemResolvers,
      now: parsedNow(args),
    });
    const report = await runAgentEgressProbesAsUid(
      uid,
      args.execFileFn ?? (execFileAsync as ProbeExecFile),
    );
    const result = cosLivenessFromReachabilityReport(report, { committedEndpoints });
    printResult(out, result, parsed.json);
    return result.kind === "cos_liveness_verified" ? 0 : 1;
  } catch (configErr) {
    write(err, `liveness-probe config error: ${(configErr as Error).message}\n`);
    return 2;
  }
}

function parsedNow(args: LivenessProbeCommandArgs): Date {
  return (args.now ?? (() => new Date()))();
}

function parseLivenessProbeArgs(argv: string[]): LivenessProbeOptions {
  const opts: LivenessProbeOptions = { json: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "--fortress") {
      opts.fortress = requireValue(argv, ++i, "--fortress");
    } else {
      throw new Error(`Unknown liveness-probe option: ${arg}`);
    }
  }
  return opts;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

async function assertFortressBaseReadable(fortressPath: string): Promise<void> {
  try {
    const stats = await lstat(fortressPath);
    if (!stats.isDirectory()) {
      throw new Error("config_unreadable");
    }
  } catch {
    throw new Error("config_unreadable");
  }
}

async function readCommittedAgentUid(fortressPath: string): Promise<number> {
  const originPath = join(fortressPath, "policy", "egress", "agent-origin.json");
  let raw: string;
  try {
    raw = await readFileCustody(originPath, { encoding: "utf8", verifyPathIdentity: true });
  } catch (originErr) {
    const code =
      originErr instanceof Error && "code" in originErr
        ? (originErr as NodeJS.ErrnoException).code
        : undefined;
    // SECURITY: no `cause` by design. The caught error is a CustodyFsError
    // carrying the absolute origin path, and `util.inspect(err)` prints
    // `[cause]` even when the top-level message is sanitized — that exact leak
    // was a merged finding on the Telegram prober (#1062). The CODE is the
    // diagnostic; the path stays out of operator output.
    // eslint-disable-next-line preserve-caught-error -- intentional: see SECURITY note above
    throw new Error(code === "ENOENT" ? "agent_origin_absent" : "agent_origin_unreadable");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("agent_origin_malformed");
  }
  const origin = validateAgentOrigin(parsed);
  if (origin?.mode !== "uid" || typeof origin.agent_uid !== "number") {
    throw new Error("agent_origin_invalid");
  }
  return origin.agent_uid;
}

async function verifyCommittedAllowlist(input: {
  fortressPath: string;
  collectResolvers: () => Promise<readonly unknown[]>;
  now: Date;
}): Promise<EndpointStaticCheck[]> {
  let rules;
  try {
    rules = await readEgressRulesFromDisk(input.fortressPath);
  } catch {
    throw new Error("allowlist_unreadable");
  }
  const verify = verifyProvisionedEgressStatically(
    rules,
    HERMES_ENDPOINT_SET,
    await input.collectResolvers(),
    input.now.toISOString(),
  );
  if (!verify.ok) {
    const failed = verify.checks.filter((check) => !check.allowed).map((check) => check.name);
    const failedDetail =
      failed.length > 0 ? `no allow match for ${failed.join(", ")}` : "declared endpoints unresolved";
    const dnsDetail = verify.dnsRulePresent ? "" : "; scoped DNS allow unavailable";
    throw new Error(`allowlist_unverified: ${failedDetail}${dnsDetail}`);
  }
  return verify.checks.filter((check) => check.host !== "");
}

function printResult(
  out: Writable,
  result: CosLivenessOutcome,
  json: boolean,
): void {
  if (json) {
    write(out, `${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  write(out, `${formatLivenessProbeResultLine(result)}\n`);
}

export function formatLivenessProbeResultLine(result: CosLivenessOutcome): string {
  if (result.kind === "cos_liveness_verified") {
    const evidence = result.evidence;
    if (!isVerifiedCosLivenessReachabilityEvidence(evidence)) {
      return "unverified reason=declared_endpoints_unreachable detail=invalid_verified_evidence";
    }
    return (
      `verified: confined path verified: the agent uid reaches all ` +
      `${evidence.declaredEndpointCount} declared endpoints and remains blocked elsewhere.`
    );
  }
  const subreason = result.subreason !== undefined ? ` subreason=${result.subreason}` : "";
  const detail = result.detail !== undefined ? ` detail=${result.detail}` : "";
  return `unverified reason=${result.reason}${subreason}${detail}`;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary liveness-probe [--fortress <path>] [--json]

Runs the as-uid reachability differential using:
  <fortress>/policy/egress/agent-origin.json
  <fortress>/policy/egress/rules/*.json

Exit codes:
  0  verified
  1  unverified
  2  config or custody error
`,
  );
}
