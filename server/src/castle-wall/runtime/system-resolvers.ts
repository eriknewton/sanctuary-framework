/**
 * Enumerate the host's ACTUAL active DNS resolver set for the derived DNS
 * allow (#380).
 *
 * Drill-found bug (Mini1 egress drill, 2026-07-12): the daemon composes and
 * signs the manifest, and inside a long-lived daemon `dns.getServers()` is a
 * SNAPSHOT taken at first DNS use (c-ares reads the resolv.conf view once per
 * process). A daemon started at boot predates the network's DNS
 * configuration: on the drill host, Tailscale MagicDNS (100.100.100.100)
 * became the system resolver after boot, so a boot-started daemon's snapshot
 * never carries it and the derived DNS allow scopes to a stale set. The
 * resolv.conf view is also structurally incomplete on macOS: the
 * authoritative live configuration is configd's (`scutil --dns`), which
 * additionally carries scoped/supplemental resolvers (the drill host's DHCP
 * resolver appears ONLY there once MagicDNS overrides the global set).
 *
 * Fix: on macOS the resolver set is a FRESH, deadline-bounded `scutil --dns`
 * nameserver read (all resolver blocks, scoped and supplemental included) --
 * scutil is the authoritative superset of the resolv.conf view there, and a
 * fresh subprocess makes every compose see the CURRENT configuration instead
 * of a process-lifetime snapshot. On other platforms the set is
 * `dns.getServers()` unchanged.
 *
 * Security posture (adversarial review of the first cut hardened all three):
 *   - macOS FAILS CLOSED: a scutil failure/timeout yields an EMPTY resolver
 *     set, so the derivation emits NO rule and provisioning surfaces a loud
 *     refuse-to-arm. It NEVER falls back to the daemon's possibly-stale
 *     `dns.getServers()` snapshot -- signing a grant from a stale snapshot is
 *     the exact bug class this module exists to close (review BLOCKER).
 *   - Zone-scoped entries (`fe80::1%en0`) are DROPPED, not zone-stripped: the
 *     manifest/evaluator has no interface axis, so a stripped `fe80::1` would
 *     match that address on EVERY interface (review MED).
 *   - Non-unicast entries are classified by parsed address bytes (via the
 *     same net.BlockList machinery the rule matcher uses), so noncanonical
 *     spellings (`0:0:0:0:0:0:0:0`, `::ffff:224.0.0.251`) cannot slip a
 *     multicast/unspecified/broadcast destination into the grant (review LOW).
 *   - The scutil subprocess is deadline-bounded; the daemon reload path this
 *     feeds must never hang on a slow host call (the PR #912 lesson).
 */

import { execFile } from "node:child_process";
import { getServers } from "node:dns";
import { promisify } from "node:util";
import { isValidIp, cidrMatches } from "../allowlist/ip-cidr.js";

const execFileAsync = promisify(execFile);

/** Deadline on the `scutil --dns` subprocess (reload paths must never hang). */
const SCUTIL_TIMEOUT_MS = 3_000;

/**
 * Address blocks that must never appear as a resolver destination in the
 * derived port-53 grant: unspecified/this-network, multicast, broadcast, and
 * their IPv4-mapped IPv6 equivalents. Byte-level membership via the same
 * CIDR machinery the rule matcher uses, so noncanonical spellings normalize
 * before classification.
 */
const NON_UNICAST_RESOLVER_BLOCKS = [
  "0.0.0.0/8",
  "224.0.0.0/4",
  "255.255.255.255/32",
  "::/128",
  "ff00::/8",
  "::ffff:0.0.0.0/104",
  "::ffff:224.0.0.0/100",
  "::ffff:255.255.255.255/128",
];

/**
 * True when an entry must not be included as a unicast resolver destination:
 * not an IP, zone-scoped (`fe80::1%en0` -- the evaluator has no interface
 * axis, so including the bare address would widen it to every interface), or
 * inside a non-unicast block.
 */
function isNonUnicastResolver(raw: string): boolean {
  if (raw.includes("%")) return true;
  if (!isValidIp(raw)) return true;
  return cidrMatches(NON_UNICAST_RESOLVER_BLOCKS, raw);
}

/**
 * Parse the `nameserver[N] : <address>` entries out of `scutil --dns` output
 * (all resolver blocks, scoped and supplemental included), deduped in first-
 * seen order, with zone-scoped, non-unicast, and non-IP entries dropped.
 * Pure; exported for tests.
 */
export function parseScutilDnsNameservers(output: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of output.split("\n")) {
    const match = /^\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$/.exec(line);
    if (match === null) continue;
    const addr = match[1];
    if (isNonUnicastResolver(addr)) continue;
    if (seen.has(addr)) continue;
    seen.add(addr);
    out.push(addr);
  }
  return out;
}

/** Injectable seams for {@link collectSystemResolvers}; tests only. */
export interface CollectSystemResolversOptions {
  /** Defaults to the real `process.platform`. */
  platform?: NodeJS.Platform;
  /** Defaults to the real `dns.getServers` (non-darwin platforms only). */
  getServersFn?: () => string[];
  /** Defaults to running `/usr/sbin/scutil --dns` (deadline-bounded). */
  runScutilDns?: () => Promise<string>;
}

async function runScutilDnsReal(): Promise<string> {
  const { stdout } = await execFileAsync("/usr/sbin/scutil", ["--dns"], {
    timeout: SCUTIL_TIMEOUT_MS,
    maxBuffer: 1024 * 1024,
  });
  return stdout;
}

/**
 * The host's active resolver set, for {@link deriveDnsRuleForHostnameRules}
 * via `composeEffectiveRules` (daemon signing path) and the provisioning
 * static verify. macOS: a fresh `scutil --dns` nameserver read, EMPTY on
 * failure (fail closed: no derived rule -> loud refuse-to-arm downstream,
 * never a grant signed from a stale snapshot). Elsewhere: `dns.getServers()`.
 * Entries are raw resolver strings; the derivation's `normalizeResolvers`
 * does the final normalization and dedupe.
 */
export async function collectSystemResolvers(
  options: CollectSystemResolversOptions = {},
): Promise<string[]> {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") {
    return (options.getServersFn ?? getServers)();
  }
  let scutilOutput: string;
  try {
    scutilOutput = await (options.runScutilDns ?? runScutilDnsReal)();
  } catch {
    return [];
  }
  return parseScutilDnsNameservers(scutilOutput);
}
