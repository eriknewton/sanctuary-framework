import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export enum SsrfRejectionReason {
  invalid_scheme = "invalid_scheme",
  loopback = "loopback",
  private_network = "private_network",
  link_local = "link_local",
  multicast = "multicast",
  metadata_service = "metadata_service",
  ipv6_loopback = "ipv6_loopback",
  ipv6_local = "ipv6_local",
  dns_resolution_failed = "dns_resolution_failed",
  dns_resolved_to_blocked = "dns_resolved_to_blocked",
}

export type SsrfValidationResult =
  | { ok: true }
  | { ok: false; reason: SsrfRejectionReason };

export interface SsrfValidationOptions {
  allowPrivateNetworks?: boolean;
  dnsTimeoutMs?: number;
}

const DEFAULT_DNS_TIMEOUT_MS = 3000;
const IPV4_METADATA = new Set(["169.254.169.254"]);
const IPV6_METADATA = ["fd00:ec2::254", "2606:f0:1000::4"] as const;

export async function validateUpstreamSseUrl(
  url: string,
  options: SsrfValidationOptions = {}
): Promise<SsrfValidationResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: SsrfRejectionReason.invalid_scheme };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, reason: SsrfRejectionReason.invalid_scheme };
  }

  const host = normalizeHost(parsed.hostname);
  const literalCheck = checkIpAddress(host, options);
  if (literalCheck.blocked) {
    return { ok: false, reason: literalCheck.reason };
  }
  if (literalCheck.isIp) {
    return { ok: true };
  }

  let addresses: Array<{ address: string }>;
  try {
    addresses = await withTimeout(
      lookup(host, { all: true, family: 0 }),
      options.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS
    );
  } catch {
    return { ok: false, reason: SsrfRejectionReason.dns_resolution_failed };
  }

  if (addresses.length === 0) {
    return { ok: false, reason: SsrfRejectionReason.dns_resolution_failed };
  }

  for (const { address } of addresses) {
    const resolvedCheck = checkIpAddress(address, options);
    if (!resolvedCheck.isIp || resolvedCheck.blocked) {
      return { ok: false, reason: SsrfRejectionReason.dns_resolved_to_blocked };
    }
  }

  return { ok: true };
}

function normalizeHost(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1).toLowerCase() : host.toLowerCase();
}

function checkIpAddress(
  address: string,
  options: SsrfValidationOptions
):
  | { isIp: false; blocked: false }
  | { isIp: true; blocked: false }
  | { isIp: true; blocked: true; reason: SsrfRejectionReason } {
  const family = isIP(address);
  if (family === 0) {
    return { isIp: false, blocked: false };
  }

  if (family === 4) {
    return checkIpv4Address(address, options.allowPrivateNetworks === true);
  }

  return checkIpv6Address(address, options.allowPrivateNetworks === true);
}

function checkIpv4Address(
  address: string,
  allowPrivateNetworks: boolean
):
  | { isIp: true; blocked: false }
  | { isIp: true; blocked: true; reason: SsrfRejectionReason } {
  const parts = address.split(".").map(Number);
  const [a, b] = parts as [number, number, number, number];

  if (IPV4_METADATA.has(address)) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.metadata_service };
  }
  if (a === 127) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.loopback };
  }
  if (a === 169 && b === 254) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.link_local };
  }
  if (a >= 224 && a <= 239) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.multicast };
  }
  if (!allowPrivateNetworks && (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.private_network };
  }

  return { isIp: true, blocked: false };
}

function checkIpv6Address(
  address: string,
  allowPrivateNetworks: boolean
):
  | { isIp: true; blocked: false }
  | { isIp: true; blocked: true; reason: SsrfRejectionReason } {
  const value = parseIpv6ToBigInt(address.toLowerCase());
  if (value === null) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.dns_resolved_to_blocked };
  }

  for (const metadataAddress of IPV6_METADATA) {
    if (value === parseIpv6ToBigInt(metadataAddress)) {
      return { isIp: true, blocked: true, reason: SsrfRejectionReason.metadata_service };
    }
  }
  if (value === 1n) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.ipv6_loopback };
  }
  if (isIpv6InPrefix(value, 0xfe80n << 112n, 10)) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.link_local };
  }
  if (isIpv6InPrefix(value, 0xff00n << 112n, 8)) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.multicast };
  }
  if (!allowPrivateNetworks && isIpv6InPrefix(value, 0xfc00n << 112n, 7)) {
    return { isIp: true, blocked: true, reason: SsrfRejectionReason.ipv6_local };
  }

  return { isIp: true, blocked: false };
}

function isIpv6InPrefix(value: bigint, prefixValue: bigint, prefixBits: number): boolean {
  const suffixBits = 128n - BigInt(prefixBits);
  const mask = ((1n << BigInt(prefixBits)) - 1n) << suffixBits;
  return (value & mask) === (prefixValue & mask);
}

function parseIpv6ToBigInt(address: string): bigint | null {
  const withoutZone = address.split("%")[0]!;
  const [headRaw, tailRaw, extra] = withoutZone.split("::");
  if (extra !== undefined) return null;

  const head = parseIpv6Hextets(headRaw);
  const tail = tailRaw === undefined ? [] : parseIpv6Hextets(tailRaw);
  if (!head || !tail) return null;

  const missing = tailRaw === undefined ? 0 : 8 - head.length - tail.length;
  if (missing < 0) return null;

  const hextets = [...head, ...Array(missing).fill(0), ...tail];
  if (hextets.length !== 8) return null;

  return hextets.reduce((acc, hextet) => (acc << 16n) + BigInt(hextet), 0n);
}

function parseIpv6Hextets(section: string): number[] | null {
  if (section === "") return [];
  const hextets = section.split(":");
  const parsed: number[] = [];
  for (const hextet of hextets) {
    if (!/^[0-9a-f]{1,4}$/i.test(hextet)) return null;
    parsed.push(Number.parseInt(hextet, 16));
  }
  return parsed;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("DNS resolution timed out")), timeoutMs);
  });

  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
