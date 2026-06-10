/**
 * IP / CIDR matching for Castle Wall allowlist rules (#380).
 *
 * A hostname allow-rule can never match a DNS flow: DNS flows carry a nil
 * `destinationHost` (a raw-IP query to a resolver has no SNI/hostname), so the
 * host axis can never resolve. The only host-less rule the legacy schema could
 * express was `port: 53` with no destination, which matches port 53 to ANY IP,
 * i.e. an any-resolver open-port-53 grant that is a DNS-tunneling exfil channel.
 *
 * This module adds an IP/CIDR destination axis so a DNS allow can be scoped to
 * the system resolver set ONLY. It is the single source of truth for both:
 *   1. manifest-build-time validation (reject malformed ip/cidr — fail closed), and
 *   2. the TS evaluator (egress-proxy) destination match,
 * keeping the two in lockstep with the Swift evaluator (`AllowlistEvaluator`).
 *
 * Matching semantics MUST agree byte-for-byte with the Swift side:
 *   - exact `ip`: family-aware equality on the normalized address bytes
 *     (so `::1` equals `0:0:0:0:0:0:0:1`, `192.168.1.1` does not equal an IPv6).
 *   - `cidr`: family-aware prefix containment; a mismatched family never matches.
 *
 * We use Node's built-in `net.BlockList`, which performs correct family-aware
 * address and subnet membership for both IPv4 and IPv6, rather than hand-rolling
 * IPv6 parsing.
 */

import net from "node:net";

/** Family tag used by `net.BlockList` add/check calls. */
type BlockListFamily = "ipv4" | "ipv6";

function familyTag(version: 4 | 6): BlockListFamily {
  return version === 4 ? "ipv4" : "ipv6";
}

/** A parsed CIDR: base address, prefix length, and family (4 or 6). */
export interface ParsedCidr {
  address: string;
  prefix: number;
  family: 4 | 6;
}

/** True iff `value` is a syntactically valid IPv4 or IPv6 literal. */
export function isValidIp(value: unknown): boolean {
  return typeof value === "string" && net.isIP(value) !== 0;
}

/**
 * Parse a CIDR string (`addr/prefix`) into its components, or return null when
 * malformed. Validates: exactly one `/`, a valid IP base, an integer prefix in
 * the family's legal range ([0,32] for IPv4, [0,128] for IPv6). A bare integer
 * with no slash, a non-numeric prefix, or an out-of-range prefix all reject.
 */
export function parseCidr(value: unknown): ParsedCidr | null {
  if (typeof value !== "string") return null;
  const slash = value.indexOf("/");
  if (slash < 0) return null;
  const address = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  const version = net.isIP(address);
  if (version === 0) return null;
  if (!/^\d+$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  const max = version === 4 ? 32 : 128;
  if (prefix < 0 || prefix > max) return null;
  return { address, prefix, family: version === 4 ? 4 : 6 };
}

/** True iff `value` is a syntactically valid CIDR. */
export function isValidCidr(value: string): boolean {
  return parseCidr(value) !== null;
}

function asArray(spec: string | string[]): string[] {
  return Array.isArray(spec) ? spec : [spec];
}

/**
 * True iff `address` (a destination IP literal) exactly equals any IP in `spec`,
 * family-aware. Returns false when `address` is not an IP literal (e.g. a
 * hostname): the IP axis only matches concrete addresses.
 */
export function ipMatches(spec: string | string[], address: string): boolean {
  const version = net.isIP(address);
  if (version === 0) return false;
  const block = new net.BlockList();
  let added = false;
  for (const candidate of asArray(spec)) {
    const candVersion = net.isIP(candidate);
    if (candVersion === 0) continue; // malformed entries never match (validated at build time)
    block.addAddress(candidate, familyTag(candVersion === 4 ? 4 : 6));
    added = true;
  }
  if (!added) return false;
  return block.check(address, familyTag(version === 4 ? 4 : 6));
}

/**
 * True iff `address` (a destination IP literal) falls inside any CIDR in `spec`,
 * family-aware. Returns false when `address` is not an IP literal, or when no
 * candidate CIDR shares its family.
 */
export function cidrMatches(spec: string | string[], address: string): boolean {
  const version = net.isIP(address);
  if (version === 0) return false;
  const block = new net.BlockList();
  let added = false;
  for (const candidate of asArray(spec)) {
    const parsed = parseCidr(candidate);
    if (!parsed) continue; // malformed entries never match (validated at build time)
    block.addSubnet(parsed.address, parsed.prefix, familyTag(parsed.family));
    added = true;
  }
  if (!added) return false;
  return block.check(address, familyTag(version === 4 ? 4 : 6));
}
