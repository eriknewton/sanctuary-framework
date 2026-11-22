import { isIP } from "node:net";

// Must match the selector caller in intelligence/selector.ts; generation uses this same predicate.
export function isLoopbackOllamaEndpoint(endpoint: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return false;
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) return false;
  const rawHost = parsed.hostname.toLowerCase();
  const host = rawHost.startsWith("[") && rawHost.endsWith("]")
    ? rawHost.slice(1, -1)
    : rawHost;
  if (host === "localhost" || host === "::1") return true;
  if (isIP(host) !== 4) return false;
  // The IPv4 loopback block occupies 127.0.0.0/8.
  return host.split(".")[0] === "127";
}

export interface LoopbackConnectTarget {
  readonly address: string;
  readonly port: number;
  readonly family: 4 | 6;
}
export type LoopbackTargetResult = { ok: true; target: LoopbackConnectTarget } | { ok: false; reason: "not_loopback" };
const DEFAULT_HTTP_PORT = 80; // The registered default port for HTTP.
const MAX_TCP_PORT = 2 ** 16 - 1; // TCP carries an unsigned 16-bit port.

export function resolveLoopbackConnectTarget(endpoint: string): LoopbackTargetResult {
  if (!isLoopbackOllamaEndpoint(endpoint)) return { ok: false, reason: "not_loopback" };
  const url = new URL(endpoint);
  if (url.protocol !== "http:" || url.pathname !== "/" || url.search || url.hash) return { ok: false, reason: "not_loopback" };
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const address = host === "localhost" ? "127.0.0.1" : host;
  const family = isIP(address);
  const port = url.port ? Number(url.port) : DEFAULT_HTTP_PORT;
  if ((family !== 4 && family !== 6) || !Number.isInteger(port) || port < 1 || port > MAX_TCP_PORT) return { ok: false, reason: "not_loopback" };
  // Only a literal leaves this boundary; localhost never reaches a DNS resolver.
  return { ok: true, target: Object.freeze({ address, port, family }) };
}
