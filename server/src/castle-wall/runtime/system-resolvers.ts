/**
 * Enumerate the host's ACTUAL active DNS resolver set for the derived DNS
 * allow (#380).
 *
 * Drill-found bug (Mini1 egress drill, 2026-07-12): the daemon composes and
 * signs the manifest, and inside a long-lived daemon `dns.getServers()` is a
 * SNAPSHOT taken at first DNS use (c-ares reads the resolv.conf view once per
 * process). A daemon started at boot predates the network's DNS
 * configuration: on the drill host, Tailscale MagicDNS (100.100.100.100)
 * became the system resolver after boot, the daemon's snapshot never carried
 * it, the derived DNS allow scoped to the stale set, and the agent's live
 * queries were default-denied (observed: api.venice.ai queried via
 * 100.100.100.100:53, denied with rule=None -> endpoint unresolvable in the
 * armed state). The resolv.conf view is also structurally incomplete on
 * macOS: the authoritative live configuration is configd's (`scutil --dns`),
 * which additionally carries scoped/supplemental resolvers (the drill host's
 * DHCP resolver appears ONLY there once MagicDNS overrides the global set).
 *
 * Fix: on macOS, union `dns.getServers()` with every `nameserver[N]` entry
 * `scutil --dns` reports, across scoped and supplemental resolvers too; any
 * of them is a destination the system resolver may legitimately send port-53
 * traffic to, and the fresh subprocess makes every compose see the CURRENT
 * configuration instead of a process-lifetime snapshot. On other platforms
 * the set is `dns.getServers()` unchanged.
 *
 * Security posture:
 *   - A scutil failure or timeout falls back to `dns.getServers()` alone.
 *     The fallback is strictly narrower than the union, and the #380
 *     fail-closed invariant is preserved downstream: an empty set derives NO
 *     rule (deny DNS rather than emit an any-resolver grant).
 *   - Multicast, unspecified, broadcast, and non-IP entries are dropped from
 *     the scutil contribution, so a degenerate resolver entry can never widen
 *     the grant beyond plausible unicast resolver destinations.
 *   - The scutil subprocess is deadline-bounded; the daemon reload path this
 *     feeds must never hang on a slow host call (the PR #912 lesson).
 */

import { execFile } from "node:child_process";
import { getServers } from "node:dns";
import { promisify } from "node:util";
import { isValidIp } from "../allowlist/ip-cidr.js";

const execFileAsync = promisify(execFile);

/** Deadline on the `scutil --dns` subprocess (reload paths must never hang). */
const SCUTIL_TIMEOUT_MS = 3_000;

/**
 * True when an address must not be treated as a unicast resolver destination:
 * not an IP at all, IPv4/IPv6 multicast, unspecified, or IPv4 broadcast.
 * Zone ids (`fe80::1%en0`) are stripped for the check only; the caller keeps
 * the raw form (downstream normalization strips the zone the same way).
 */
function isNonUnicastResolver(raw: string): boolean {
  let addr = raw;
  const zone = addr.indexOf("%");
  if (zone >= 0) addr = addr.slice(0, zone);
  if (!isValidIp(addr)) return true;
  const lower = addr.toLowerCase();
  if (lower.includes(":")) {
    if (lower === "::") return true;
    // ff00::/8 is the entire IPv6 multicast space.
    return lower.startsWith("ff");
  }
  if (addr === "0.0.0.0" || addr === "255.255.255.255") return true;
  const firstOctet = Number(addr.split(".")[0]);
  return firstOctet >= 224 && firstOctet <= 239;
}

/**
 * Parse the `nameserver[N] : <address>` entries out of `scutil --dns` output
 * (all resolver blocks, scoped and supplemental included), deduped in first-
 * seen order, with non-unicast and non-IP entries dropped. Pure; exported for
 * tests.
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
  /** Defaults to the real `dns.getServers`. */
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
 * static verify. macOS: `dns.getServers()` unioned with the `scutil --dns`
 * nameserver set; elsewhere: `dns.getServers()`. Entries are raw resolver
 * strings; the derivation's `normalizeResolvers` does the final
 * normalization and dedupe.
 */
export async function collectSystemResolvers(
  options: CollectSystemResolversOptions = {},
): Promise<string[]> {
  const platform = options.platform ?? process.platform;
  const getServersFn = options.getServersFn ?? getServers;
  const base = getServersFn();
  if (platform !== "darwin") return base;
  let scutilOutput: string;
  try {
    scutilOutput = await (options.runScutilDns ?? runScutilDnsReal)();
  } catch {
    // Fall back to the resolv.conf view alone: strictly narrower than the
    // union, and the derivation stays fail-closed on an empty set. The
    // refuse-to-arm surface reports unresolvable endpoints loudly, so this
    // cannot silently confine an agent into non-functionality.
    return base;
  }
  const out = [...base];
  const seen = new Set(base);
  for (const addr of parseScutilDnsNameservers(scutilOutput)) {
    if (seen.has(addr)) continue;
    seen.add(addr);
    out.push(addr);
  }
  return out;
}
