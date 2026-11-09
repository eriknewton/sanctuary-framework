/**
 * Passive messaging census: a pure parser for `netstat -anv -p tcp` text and
 * the agent-health predicate recomputed by every reader. It spawns nothing.
 *
 * Honesty bound:
 * - the census is not adversarial, and a hostile agent can trickle bytes to look alive;
 * - growth proves responses on one messaging-service connection of the gateway process, not update delivery (a 409 Conflict loop grows rx) and not handler or reply liveness; a sustained send burst on another connection can read alive while the updater is dead;
 * - only IPv4 polling connections are observed; netstat truncates IPv6 addresses, so a gateway polling over IPv6 reads down;
 * - the agent can kill or starve its canary, but cannot disable it or boot it out.
 */
import { parseIsoInstantWithOffset } from "../../core/time.js";
import {
  CENSUS_INPUT_BYTES,
  CENSUS_INPUT_ROWS,
  CENSUS_MESSAGING_PORT,
  CENSUS_PAIR_MAX,
  CENSUS_PAIR_MIN,
  CENSUS_PID_ROWS,
  CENSUS_RUN,
  COUNTER_MAX,
} from "./constants.js";
import { recordTiming } from "./timing.js";

/** The one preamble line netstat prints before its header. */
export const CENSUS_PREAMBLE = "Active Internet connections (including servers)";
/**
 * The single accepted header signature, by column name in order (macOS 26.6.2,
 * build 25G83). Any other header, including these names in another order, is
 * `census_unavailable`.
 */
export const CENSUS_HEADER_SIGNATURE: readonly string[] = Object.freeze([
  "Proto", "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "(state)",
  "rxbytes", "txbytes", "rhiwat", "shiwat", "process:pid", "state", "options",
  "gencnt", "flags", "flags1", "usecnt", "rtncnt", "fltrs",
]);
/** Columns the predicate cannot do without; a header missing one is unavailable. */
export const CENSUS_REQUIRED_COLUMNS: readonly string[] = Object.freeze([
  "process:pid", "rxbytes", "txbytes", "(state)", "gencnt",
]);
/** Header names that print as two words. */
const TWO_WORD_COLUMNS: readonly string[] = ["Local Address", "Foreign Address"];
const PROTOCOLS: ReadonlySet<string> = new Set(["tcp4", "tcp6", "tcp46"]);
export const TCP_STATES: ReadonlySet<string> = new Set([
  "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT",
  "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT",
]);
const DECIMAL = /^[0-9]+$/;
const HEX = /^[0-9a-fA-F]+$/;
const OCTET_BITS = 8;
/** 255 = 2^8 - 1, the largest value of one dotted-quad octet. */
const IPV4_OCTET_MAX = 2 ** OCTET_BITS - 1;
const IPV4_OCTETS = 4;
/** 32 = four octets of eight bits. */
const IPV4_BITS = IPV4_OCTETS * OCTET_BITS;
const PORT_MAX = 65535; // TCP ports have sixteen bits.

export interface CensusEndpoint {
  /** Host text exactly as printed; `*` is a wildcard. */
  host: string;
  /** Port text exactly as printed; `*` is a wildcard. */
  port: string;
  /** True when the host text contains `:`, whatever the Proto token says. */
  ipv6: boolean;
  /** The parsed IPv4 address as an unsigned integer, or null when not IPv4. */
  ipv4: number | null;
  /** The parsed port, or null for a wildcard. */
  portNumber: number | null;
}

export interface CensusRow {
  proto: string;
  local: string;
  foreign: string;
  localEndpoint: CensusEndpoint;
  foreignEndpoint: CensusEndpoint;
  /** The TCP state column `(state)`; never the socket `state` column. */
  tcp_state: string;
  /** The socket state column `state`, kept distinct from the TCP state. */
  socket_state: string;
  rxbytes: number;
  txbytes: number;
  gencnt: string;
  process: string;
  pid: number;
}

export type CensusParse =
  | { status: "ok"; rows: CensusRow[] }
  | { status: "census_unavailable"; detail: string };

function unavailable(detail: string): CensusParse {
  return { status: "census_unavailable", detail };
}

/** Split header text into column names, joining the two-word names. */
function headerColumns(line: string): string[] {
  const tokens = line.trim().split(/\s+/);
  const columns: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const pair = `${tokens[i]} ${tokens[i + 1] ?? ""}`;
    if (TWO_WORD_COLUMNS.includes(pair)) {
      columns.push(pair);
      i++;
    } else columns.push(tokens[i]!);
  }
  return columns;
}

function parseIpv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== IPV4_OCTETS) return null;
  let value = 0;
  for (const part of parts) {
    if (!DECIMAL.test(part)) return null;
    const octet = Number(part);
    if (octet > IPV4_OCTET_MAX) return null;
    value = value * (IPV4_OCTET_MAX + 1) + octet;
  }
  return value;
}

/** macOS prints `addr.port`; split on the last dot. Returns null for a malformed endpoint. */
function parseEndpoint(text: string): CensusEndpoint | null {
  const dot = text.lastIndexOf(".");
  if (dot <= 0 || dot === text.length - 1) return null;
  const host = text.slice(0, dot);
  const port = text.slice(dot + 1);
  let portNumber: number | null = null;
  if (port !== "*") {
    if (!DECIMAL.test(port)) return null;
    portNumber = Number(port);
    if (portNumber > PORT_MAX) return null;
  }
  const ipv6 = host.includes(":");
  if (host === "*" || ipv6) {
    // A wildcard host, or IPv6 text netstat may have truncated, is parsed and never qualifies.
    return { host, port, ipv6, ipv4: null, portNumber };
  }
  const ipv4 = parseIpv4(host);
  if (ipv4 === null) return null;
  return { host, port, ipv6, ipv4, portNumber };
}

function safeDecimal(token: string): number | null {
  if (!DECIMAL.test(token)) return null;
  const value = Number(token);
  return Number.isSafeInteger(value) ? value : null;
}

type RowResult = { kind: "row"; row: CensusRow } | { kind: "failed"; pid: number | null };

function parseRow(line: string, columns: readonly string[]): RowResult {
  const tokens = line.trim().split(/\s+/);
  const leftCount = columns.indexOf("shiwat") + 1;
  const rightCount = columns.length - columns.indexOf("state");
  if (tokens.length < leftCount + rightCount) return { kind: "failed", pid: null };
  // Fixed columns bind from the left up to shiwat and from the right back to state; the residual is the agent-controlled process name.
  const residual = tokens.slice(leftCount, tokens.length - rightCount).join(" ");
  const left = (name: string): string => tokens[columns.indexOf(name)]!;
  const right = (name: string): string => tokens[tokens.length - (columns.length - columns.indexOf(name))]!;
  const colon = residual.lastIndexOf(":");
  const pidText = colon < 0 ? "" : residual.slice(colon + 1);
  const pid = residual.length === 0 ? null : safeDecimal(pidText);
  if (pid === null) return { kind: "failed", pid: null };
  const proto = left("Proto");
  const localText = left("Local Address");
  const foreignText = left("Foreign Address");
  const localEndpoint = parseEndpoint(localText);
  const foreignEndpoint = parseEndpoint(foreignText);
  const tcpState = left("(state)");
  const rxbytes = safeDecimal(left("rxbytes"));
  const txbytes = safeDecimal(left("txbytes"));
  const gencnt = right("gencnt");
  const valid = PROTOCOLS.has(proto) &&
    safeDecimal(left("Recv-Q")) !== null && safeDecimal(left("Send-Q")) !== null &&
    safeDecimal(left("rhiwat")) !== null && safeDecimal(left("shiwat")) !== null &&
    rxbytes !== null && txbytes !== null && TCP_STATES.has(tcpState) && HEX.test(gencnt) &&
    localEndpoint !== null && foreignEndpoint !== null;
  if (!valid) return { kind: "failed", pid };
  return {
    kind: "row",
    row: {
      proto, local: localText, foreign: foreignText,
      localEndpoint: localEndpoint!, foreignEndpoint: foreignEndpoint!,
      tcp_state: tcpState, socket_state: right("state"),
      rxbytes: rxbytes!, txbytes: txbytes!, gencnt: gencnt.toLowerCase(),
      process: residual.slice(0, colon), pid,
    },
  };
}

/**
 * Parse one `netstat -anv -p tcp` output. A failed row owned by the
 * configured gateway pid, or any failed row whose owner cannot be attributed,
 * fails the whole sample.
 */
export function parseCensus(text: string, options: { gatewayPid: number }): CensusParse {
  if (new TextEncoder().encode(text).length > CENSUS_INPUT_BYTES) return unavailable("input_bytes");
  const lines = text.split("\n");
  if (lines.length > CENSUS_INPUT_ROWS) return unavailable("input_rows");
  let index = 0;
  if (lines[index] === CENSUS_PREAMBLE) index++;
  const header = lines[index];
  if (header === undefined) return unavailable("header_missing");
  const columns = headerColumns(header);
  for (const required of CENSUS_REQUIRED_COLUMNS) {
    if (!columns.includes(required)) return unavailable(`column_missing:${required}`);
  }
  // Only the committed fixtures' exact header signature is accepted; a reordered or unknown header is never guessed at.
  if (columns.length !== CENSUS_HEADER_SIGNATURE.length ||
      columns.some((name, position) => name !== CENSUS_HEADER_SIGNATURE[position])) {
    return unavailable("header_signature");
  }
  const rows: CensusRow[] = [];
  for (const line of lines.slice(index + 1)) {
    if (line.trim().length === 0) continue;
    const parsed = parseRow(line, columns);
    if (parsed.kind === "failed") {
      if (parsed.pid === null || parsed.pid === options.gatewayPid) return unavailable("row_invalid");
      continue;
    }
    rows.push(parsed.row);
  }
  return { status: "ok", rows };
}

// ---------------------------------------------------------------------------
// Messaging set and stored samples.
// ---------------------------------------------------------------------------
export interface Ipv4Prefix {
  network: number;
  bits: number;
}

/** Parse `a.b.c.d/len`; null for anything else. */
export function parseIpv4Prefix(text: string): Ipv4Prefix | null {
  const slash = text.lastIndexOf("/");
  if (slash < 0) return null;
  const address = parseIpv4(text.slice(0, slash));
  const bitsText = text.slice(slash + 1);
  if (address === null || !DECIMAL.test(bitsText)) return null;
  const bits = Number(bitsText);
  if (bits > IPV4_BITS) return null;
  return { network: address, bits };
}

function ipv4InPrefix(address: number, prefix: Ipv4Prefix): boolean {
  const span = 2 ** (IPV4_BITS - prefix.bits);
  return Math.floor(address / span) === Math.floor(prefix.network / span);
}

/** IPv6 never qualifies in this contract: netstat truncates IPv6 host text, so only IPv4 is credited. */
export function endpointInMessagingSet(endpoint: CensusEndpoint, ipv4Set: readonly Ipv4Prefix[]): boolean {
  if (endpoint.ipv6 || endpoint.ipv4 === null) return false;
  return ipv4Set.some(prefix => ipv4InPrefix(endpoint.ipv4!, prefix));
}

export interface CensusGatewayIdentity {
  pid: number;
  start_identity: string;
  uid: number;
  generation: string;
}

export interface StoredCensusRow {
  local: string;
  foreign: string;
  tcp_state: string;
  rxbytes: number;
  txbytes: number;
  gencnt: string;
}

export interface StoredCensusSample {
  observed_at: string;
  observed_uptime_ms: number;
  boot_id: string;
  gateway: CensusGatewayIdentity;
  rows: StoredCensusRow[];
  /** Saturating count of the gateway's other rows; a saturated count reads observation_invalid. */
  other_rows: number;
}

function rowQualifies(row: Pick<CensusRow, "tcp_state" | "foreignEndpoint">, ipv4Set: readonly Ipv4Prefix[]): boolean {
  return row.tcp_state === "ESTABLISHED" &&
    row.foreignEndpoint.portNumber === CENSUS_MESSAGING_PORT &&
    endpointInMessagingSet(row.foreignEndpoint, ipv4Set);
}

/**
 * Keep only the configured gateway pid's ESTABLISHED messaging-set IPv4 :443
 * rows, plus a saturating count of its other rows. More candidate rows than
 * CENSUS_PID_ROWS is `census_unavailable`.
 */
export function buildStoredSample(
  parsed: CensusParse,
  input: { gateway: CensusGatewayIdentity; ipv4Set: readonly Ipv4Prefix[]; observed_at: string; observed_uptime_ms: number; boot_id: string },
): { status: "ok"; sample: StoredCensusSample } | { status: "census_unavailable"; detail: string } {
  if (parsed.status !== "ok") return parsed;
  const rows: StoredCensusRow[] = [];
  let other = 0;
  for (const row of parsed.rows) {
    if (row.pid !== input.gateway.pid) continue;
    if (!rowQualifies(row, input.ipv4Set)) {
      other = Math.min(COUNTER_MAX, other + 1);
      continue;
    }
    rows.push({ local: row.local, foreign: row.foreign, tcp_state: row.tcp_state, rxbytes: row.rxbytes, txbytes: row.txbytes, gencnt: row.gencnt });
  }
  if (rows.length > CENSUS_PID_ROWS) return { status: "census_unavailable", detail: "pid_rows" };
  return {
    status: "ok",
    sample: {
      observed_at: input.observed_at, observed_uptime_ms: input.observed_uptime_ms, boot_id: input.boot_id,
      gateway: { ...input.gateway }, rows, other_rows: other,
    },
  };
}

// ---------------------------------------------------------------------------
// Predicate.
// ---------------------------------------------------------------------------
export interface CensusRunInput {
  samples: readonly StoredCensusSample[];
  /** The full identity of the gateway the observer reports as current; every credited sample must carry all of it. */
  gateway: CensusGatewayIdentity;
  /** The commissioned agent uid from config.json; a credited sample's gateway must run under it. */
  agentUid: number;
  ipv4Set: readonly Ipv4Prefix[];
  bootId: string;
  nowMs: number;
  /** The reader's current uptime, so each current-boot sample's two clocks are checked against the reader's. */
  uptimeMs: number;
  agentWindowMs: number;
}

export interface CensusRunResult {
  /** The latest qualifying run, or null when none satisfies every healthy condition. */
  run: { firstObservedAtMs: number; latestObservedAtMs: number } | null;
  /** Earliest current-boot, current-generation sample time, or null when none is stored. */
  generationStartMs: number | null;
  counterRegression: boolean;
  invalid: boolean;
  /** A current-boot sample whose clocks fail the record-timing rule; it is never credited. */
  timeUntrusted: boolean;
  /** A sample of the current boot and generation whose process identity contradicts the current gateway. */
  identityContradiction: boolean;
}

function storedRowQualifies(row: StoredCensusRow, ipv4Set: readonly Ipv4Prefix[]): boolean {
  const foreign = parseEndpoint(row.foreign);
  return foreign !== null && rowQualifies({ tcp_state: row.tcp_state, foreignEndpoint: foreign }, ipv4Set);
}

function identityKey(pid: number, row: StoredCensusRow): string {
  return JSON.stringify([pid, row.local, row.foreign, row.gencnt]);
}

/**
 * Recompute the healthy predicate from raw samples: one qualifying identity in
 * CENSUS_RUN + 1 consecutive samples, strictly growing rx in every pair, each
 * pair spaced inside [CENSUS_PAIR_MIN, CENSUS_PAIR_MAX], one generation, the
 * reader's boot, and the run's latest sample no older than the agent window.
 */
export function evaluateCensusRun(input: CensusRunInput): CensusRunResult {
  const parsedTimes = input.samples.map(sample => parseIsoInstantWithOffset(sample.observed_at) ?? Number.NaN);
  // Every current-boot sample passes the same clock rule as the envelope records before it is credited or dates a
  // generation start: the fresh observer wrapper says nothing about the times nested inside it.
  const clockTrusted = input.samples.map(sample =>
    sample.boot_id !== input.bootId || recordTiming(sample.observed_at, sample.observed_uptime_ms, input.nowMs, input.uptimeMs).ok);
  const timeUntrusted = clockTrusted.includes(false);
  const current = input.gateway;
  // A sample of the current boot and generation claims to describe the current gateway process.
  const claimsCurrent = (sample: StoredCensusSample): boolean =>
    sample.boot_id === input.bootId && sample.gateway.generation === current.generation;
  // Every identity field is evidence, not only the pid: a pid can be reused by another process or another uid, so a
  // credited sample must name the current gateway's pid, start identity and uid, and that uid must be the commissioned one.
  const identityMatches = (sample: StoredCensusSample): boolean =>
    sample.gateway.pid === current.pid &&
    sample.gateway.start_identity === current.start_identity &&
    (sample.gateway.uid === current.uid && sample.gateway.uid === input.agentUid);
  const credited = input.samples.map((sample, position) => clockTrusted[position]! && claimsCurrent(sample) && identityMatches(sample));
  // A current-generation sample that names another process is contradictory evidence, never an older generation to skip.
  const identityContradiction = input.samples.some(sample => claimsCurrent(sample) && !identityMatches(sample));
  let generationStartMs: number | null = null;
  let counterRegression = false;
  let invalid = false;
  input.samples.forEach((sample, position) => {
    if (sample.other_rows >= COUNTER_MAX) invalid = true;
    if (credited[position]) {
      const time = parsedTimes[position]!;
      if (generationStartMs === null || time < generationStartMs) generationStartMs = time;
    }
  });
  // Same identity across adjacent samples must never lose received bytes.
  for (let i = 1; i < input.samples.length; i++) {
    const before = input.samples[i - 1]!;
    const after = input.samples[i]!;
    if (before.observed_uptime_ms >= after.observed_uptime_ms && before.boot_id === after.boot_id) invalid = true;
    const earlier = new Map(before.rows.map(row => [identityKey(before.gateway.pid, row), row.rxbytes]));
    for (const row of after.rows) {
      const prior = earlier.get(identityKey(after.gateway.pid, row));
      if (prior !== undefined && row.rxbytes < prior) counterRegression = true;
    }
  }
  let run: CensusRunResult["run"] = null;
  for (let end = input.samples.length - 1; end >= CENSUS_RUN && run === null; end--) {
    const window = input.samples.slice(end - CENSUS_RUN, end + 1);
    // Every sample of the window is credited: the reader's boot, the current generation, the full current identity and trusted clocks.
    if (!credited.slice(end - CENSUS_RUN, end + 1).every(Boolean)) continue;
    let spaced = true;
    for (let i = 1; i < window.length; i++) {
      const gap = window[i]!.observed_uptime_ms - window[i - 1]!.observed_uptime_ms;
      if (gap < CENSUS_PAIR_MIN || gap > CENSUS_PAIR_MAX) spaced = false;
    }
    if (!spaced) continue;
    // One identity must carry every pair; growth spread across identities never forms a run.
    const first = window[0]!;
    for (const candidate of first.rows) {
      if (!storedRowQualifies(candidate, input.ipv4Set)) continue;
      const key = identityKey(first.gateway.pid, candidate);
      let previous = candidate.rxbytes;
      let grows = true;
      for (const sample of window.slice(1)) {
        const row = sample.rows.find(item => identityKey(sample.gateway.pid, item) === key);
        if (!row || !storedRowQualifies(row, input.ipv4Set) || !(row.rxbytes > previous)) { grows = false; break; }
        previous = row.rxbytes;
      }
      if (grows) {
        run = { firstObservedAtMs: parsedTimes[end - CENSUS_RUN]!, latestObservedAtMs: parsedTimes[end]! };
        break;
      }
    }
  }
  // The reader-time bound: a run whose latest sample is older than the agent window no longer proves anything.
  if (run !== null && !(input.nowMs - run.latestObservedAtMs <= input.agentWindowMs)) run = null;
  return { run, generationStartMs, counterRegression, invalid, timeUntrusted, identityContradiction };
}
