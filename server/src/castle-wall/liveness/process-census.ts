/**
 * The process census: a strict `ps -axww -o pid=,ppid=,uid=,lstart=,command=`
 * parser, gateway selection with its generation, and the MCP stale-child
 * check. Detection only: nothing here signals, kills or restarts a process.
 */
import { createHash } from "node:crypto";
import { LABEL_BYTES, MAX_STALE_CHILDREN, PROCESS_BYTES, PROCESS_ROWS } from "./constants.js";
import type { McpConfig } from "./schema.js";

export interface ProcessRow {
  pid: number;
  ppid: number;
  uid: number;
  /** The `lstart` text normalized to single spaces, for example `Sun Nov 9 07:57:01 2026`. */
  lstart: string;
  /** Epoch milliseconds of `lstart` read as a UTC wall time; only compared with other rows of the same host. */
  lstartMs: number;
  /** The `command=` text split on whitespace; argv text with spaces cannot be recovered. */
  argv: string[];
}

export type ProcessRead = { status: "ok"; rows: ProcessRow[] } | { status: "failed"; detail: string };

/** pid, ppid, uid, then the five `lstart` tokens (weekday, month, day, time, year). */
const LEADING_FIELDS = 3;
const LSTART_TOKENS = 5;
const MONTHS: readonly string[] = Object.freeze(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]);
const WEEKDAYS: ReadonlySet<string> = new Set(["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]);
const DECIMAL = /^[0-9]+$/;
/** Unix pids and uids are 32-bit unsigned; a year fits the same bound. */
const UINT32_MAX = 0xffffffff;
const TIME_OF_DAY = /^(\d{2}):(\d{2}):(\d{2})$/;
const DAY_MAX = 31;
const HOURS_MAX = 23;
const MINUTES_MAX = 59;
/** 60 admits a leap second as printed. */
const SECONDS_MAX = 60;

function uint(text: string, max: number): number | null {
  if (!DECIMAL.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) && value <= max ? value : null;
}

/** Parse the five `lstart` tokens with the strict C-locale shape; Date.UTC keeps it independent of the host zone. */
export function parseLstart(tokens: readonly string[]): { text: string; ms: number } | null {
  if (tokens.length !== LSTART_TOKENS) return null;
  const [weekday, month, dayText, time, yearText] = tokens as [string, string, string, string, string];
  const monthIndex = MONTHS.indexOf(month);
  const day = uint(dayText, DAY_MAX);
  const year = uint(yearText, UINT32_MAX);
  const clock = TIME_OF_DAY.exec(time);
  if (!WEEKDAYS.has(weekday) || monthIndex < 0 || day === null || day === 0 || year === null || !clock) return null;
  const [hours, minutes, seconds] = [Number(clock[1]), Number(clock[2]), Number(clock[3])];
  if (hours > HOURS_MAX || minutes > MINUTES_MAX || seconds > SECONDS_MAX) return null;
  const ms = Date.UTC(year, monthIndex, day, hours, minutes, seconds);
  if (!Number.isFinite(ms)) return null;
  return { text: tokens.join(" "), ms };
}

/** Parse one process read; over the byte or row cap, or any malformed row, fails the whole read (never a partial list). */
export function parseProcessRead(text: string): ProcessRead {
  if (Buffer.byteLength(text) > PROCESS_BYTES) return { status: "failed", detail: "process_bytes" };
  const lines = text.split("\n").filter(line => line.trim() !== "");
  if (lines.length > PROCESS_ROWS) return { status: "failed", detail: "process_rows" };
  const rows: ProcessRow[] = [];
  for (const line of lines) {
    // Must match ARGV_SEPARATOR_TEXT in server/src/castle-wall/liveness/schema.ts, which refuses a configured MCP script path this split could break.
    const tokens = line.trim().split(/\s+/);
    if (tokens.length <= LEADING_FIELDS + LSTART_TOKENS) return { status: "failed", detail: "row_shape" };
    const pid = uint(tokens[0]!, UINT32_MAX);
    const ppid = uint(tokens[1]!, UINT32_MAX);
    const uid = uint(tokens[2]!, UINT32_MAX);
    const lstart = parseLstart(tokens.slice(LEADING_FIELDS, LEADING_FIELDS + LSTART_TOKENS));
    if (pid === null || ppid === null || uid === null || lstart === null) return { status: "failed", detail: "row_shape" };
    rows.push({ pid, ppid, uid, lstart: lstart.text, lstartMs: lstart.ms, argv: tokens.slice(LEADING_FIELDS + LSTART_TOKENS) });
  }
  return { status: "ok", rows };
}

function basename(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] ?? "";
}

/** The gateway generation: the first LABEL_BYTES hex characters of SHA-256 over pid and lstart joined by a newline. */
export function gatewayGeneration(pid: number, lstart: string): string {
  return createHash("sha256").update(`${pid}\n${lstart}`).digest("hex").slice(0, LABEL_BYTES);
}

export interface GatewayIdentity { pid: number; uid: number; start_identity: string; generation: string; alive: boolean }

/**
 * Select the gateway from two reads. Exactly one row by agent uid and argv[0]
 * basename in both reads, with equal pid and lstart, gives it alive; zero in
 * both reads with a known prior gives the prior dead; anything else is null.
 */
export function selectGateway(
  reads: readonly [ProcessRow[], ProcessRow[]],
  selector: { agentUid: number; processName: string },
  prior: GatewayIdentity | null,
): GatewayIdentity | null {
  const matches = reads.map(rows => rows.filter(row => row.uid === selector.agentUid && row.argv.length > 0 && basename(row.argv[0]!) === selector.processName));
  const [a, b] = matches as [ProcessRow[], ProcessRow[]];
  if (a.length === 0 && b.length === 0) return prior === null ? null : { ...prior, alive: false };
  // An ambiguous selector never picks a process: two matches, or a pid or start change between reads, reads unknown.
  if (a.length !== 1 || b.length !== 1) return null;
  const [first, second] = [a[0]!, b[0]!];
  if (first.pid !== second.pid || first.lstart !== second.lstart) return null;
  return { pid: second.pid, uid: second.uid, start_identity: second.lstart, generation: gatewayGeneration(second.pid, second.lstart), alive: true };
}

/** The lstart of a pid present with the same start in both reads, else null. */
export function stableStartIdentity(reads: readonly [ProcessRow[], ProcessRow[]], pid: number | null): string | null {
  if (pid === null) return null;
  const [a, b] = reads.map(rows => rows.filter(row => row.pid === pid));
  if (a!.length !== 1 || b!.length !== 1 || a![0]!.lstart !== b![0]!.lstart) return null;
  return b![0]!.lstart;
}

export type McpCheck = { status: "ok"; stale_child: boolean } | { status: "invalid"; detail: string };

/**
 * The MCP stale-child check. The harness identity is the launchd pid plus its
 * lstart, equal in both reads; a candidate is current only under that harness
 * pid and not started before it. Detection only: no signal follows.
 */
export function checkMcpStaleChild(
  reads: readonly [ProcessRow[], ProcessRow[]],
  harnessPid: number | null,
  config: { agentUid: number; mcp: McpConfig },
): McpCheck {
  if (harnessPid === null) return { status: "invalid", detail: "harness_unreadable" };
  const harness = reads.map(rows => rows.filter(row => row.pid === harnessPid));
  if (harness[0]!.length !== 1 || harness[1]!.length !== 1 || harness[0]![0]!.lstart !== harness[1]![0]!.lstart) {
    return { status: "invalid", detail: "harness_identity" };
  }
  const harnessRow = harness[1]![0]!;
  const scripts = new Set(config.mcp.script_paths);
  const candidates = reads[1].filter(row => row.uid === config.agentUid && row.argv.some(token => scripts.has(token)));
  if (candidates.length > MAX_STALE_CHILDREN) return { status: "invalid", detail: "candidates" };
  // A reparented child (ppid 1 or an old harness) or one older than the harness start is stale; a reused pid with a new start is a new harness.
  const stale = candidates.some(row => row.ppid !== harnessRow.pid || row.lstartMs < harnessRow.lstartMs);
  return { status: "ok", stale_child: stale };
}
