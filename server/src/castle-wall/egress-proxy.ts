import { promises as dns } from "node:dns";
import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";
import { domainToASCII } from "node:url";

import type { AllowlistRule } from "./allowlist/schema.js";
import { ipMatches, cidrMatches } from "./allowlist/ip-cidr.js";
import type { AuditEntryInput } from "../operational/audit-log.js";
import type { PluginContribution } from "../substrate/attribution.js";
import { intersectVerdicts, type EnforcementDecision, type HostDecision } from "../substrate/verdict.js";

export interface CanonicalConnectAuthority {
  host: string;
  port: number;
  authority: string;
  isIpLiteral: boolean;
}

export type CanonicalizationErrorCode =
  | "empty_authority"
  | "control_character"
  | "userinfo_forbidden"
  | "missing_port"
  | "invalid_port"
  | "invalid_host"
  | "bare_ipv6_literal";

export class ConnectAuthorityError extends Error {
  public readonly code: CanonicalizationErrorCode;

  constructor(code: CanonicalizationErrorCode) {
    super(code);
    this.name = "ConnectAuthorityError";
    this.code = code;
  }
}

export type EgressProxyDecision =
  | {
      disposition: "deny";
      reason:
        | "canonicalization_failed"
        | "allowlist_miss"
        | "non_public_resolved_address"
        | "plugin_decision"
        | "audit_failed";
      contributors?: PluginContribution[];
    }
  | { disposition: "allow"; target: CanonicalConnectAuthority; address: string; contributors?: PluginContribution[] };

export interface EgressPluginConsultationRequest {
  target: CanonicalConnectAuthority;
  hostDecision: HostDecision;
  protocol: "tcp";
}

export interface EgressPluginConsultationResult {
  decisions: EnforcementDecision[];
  contributors: PluginContribution[];
}

export interface EgressPluginConsultant {
  consultEgress(request: EgressPluginConsultationRequest): Promise<EgressPluginConsultationResult>;
}

export interface EgressAuditSink {
  appendCritical(entry: AuditEntryInput): Promise<void>;
}

export interface EgressProxyResolver {
  resolve(host: string): Promise<string[]>;
}

export interface EgressProxyOptions {
  rules: AllowlistRule[];
  resolver?: EgressProxyResolver;
  /** Override the public-routability check (for testing with local upstreams). */
  isRoutable?: (address: string) => boolean;
  /** Optional plugin-host S4 hook. Absence preserves the pre-plugin path exactly. */
  pluginConsultant?: EgressPluginConsultant;
  /** Optional audit sink for egress decisions with plugin participation. */
  auditSink?: EgressAuditSink;
  auditIdentityId?: string;
  /** Called after every CONNECT decision, before the response is sent. */
  onDecision?: (authority: string, decision: EgressProxyDecision) => void;
}

export function canonicalizeConnectAuthority(input: string): CanonicalConnectAuthority {
  if (input.length === 0) {
    throw new ConnectAuthorityError("empty_authority");
  }
  if (/[\r\n\t]/u.test(input)) {
    throw new ConnectAuthorityError("control_character");
  }
  if (input.includes("@")) {
    throw new ConnectAuthorityError("userinfo_forbidden");
  }

  let host: string;
  let portText: string;
  if (input.startsWith("[")) {
    const close = input.indexOf("]");
    if (close < 0 || input.charAt(close + 1) !== ":") {
      throw new ConnectAuthorityError("missing_port");
    }
    host = input.slice(1, close);
    portText = input.slice(close + 2);
  } else {
    const lastColon = input.lastIndexOf(":");
    if (lastColon < 0) {
      throw new ConnectAuthorityError("missing_port");
    }
    host = input.slice(0, lastColon);
    portText = input.slice(lastColon + 1);
    if (host.includes(":")) {
      throw new ConnectAuthorityError("bare_ipv6_literal");
    }
  }

  const port = Number(portText);
  if (!/^[0-9]+$/u.test(portText) || !Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ConnectAuthorityError("invalid_port");
  }

  host = host.trim();
  if (host.length === 0 || /[\r\n\t]/u.test(host) || host.includes("@")) {
    throw new ConnectAuthorityError("invalid_host");
  }

  const ipVersion = net.isIP(host);
  if (ipVersion !== 0) {
    const normalizedIp = ipVersion === 6 ? host.toLowerCase() : host;
    return {
      host: normalizedIp,
      port,
      authority: ipVersion === 6 ? `[${normalizedIp}]:${port}` : `${normalizedIp}:${port}`,
      isIpLiteral: true,
    };
  }

  const withoutTrailingDot = host.endsWith(".") ? host.slice(0, -1) : host;
  if (withoutTrailingDot.length === 0) {
    throw new ConnectAuthorityError("invalid_host");
  }
  const ascii = domainToASCII(withoutTrailingDot).toLowerCase();
  if (ascii.length === 0 || ascii.includes("[") || ascii.includes("]") || ascii.includes(":")) {
    throw new ConnectAuthorityError("invalid_host");
  }
  return {
    host: ascii,
    port,
    authority: `${ascii}:${port}`,
    isIpLiteral: false,
  };
}

export function isPublicRoutableIp(address: string): boolean {
  const ipVersion = net.isIP(address);
  if (ipVersion === 4) {
    return isPublicRoutableIpv4(address);
  }
  if (ipVersion === 6) {
    return isPublicRoutableIpv6(address);
  }
  return false;
}

export function allowlistAllowsTarget(rules: AllowlistRule[], target: CanonicalConnectAuthority): boolean {
  return rules.some((rule) => rule.disposition === "allow" && ruleMatchesTarget(rule, target));
}

export async function decideEgressProxyConnect(
  authority: string,
  options: EgressProxyOptions
): Promise<EgressProxyDecision> {
  let target: CanonicalConnectAuthority;
  try {
    target = canonicalizeConnectAuthority(authority);
  } catch {
    return { disposition: "deny", reason: "canonicalization_failed" };
  }

  if (!allowlistAllowsTarget(options.rules, target)) {
    return applyEgressPlugins(authority, { disposition: "deny", reason: "allowlist_miss" }, target, options);
  }

  const addresses = target.isIpLiteral
    ? [target.host]
    : await (options.resolver ?? defaultResolver).resolve(target.host);
  const routableCheck = options.isRoutable ?? isPublicRoutableIp;
  const publicAddress = addresses.find(routableCheck);
  if (!publicAddress) {
    return applyEgressPlugins(
      authority,
      { disposition: "deny", reason: "non_public_resolved_address" },
      target,
      options
    );
  }
  return applyEgressPlugins(authority, { disposition: "allow", target, address: publicAddress }, target, options);
}

async function applyEgressPlugins(
  authority: string,
  hostDecision: EgressProxyDecision,
  target: CanonicalConnectAuthority,
  options: EgressProxyOptions
): Promise<EgressProxyDecision> {
  if (!options.pluginConsultant) return hostDecision;

  const hostVerdict: HostDecision = hostDecision.disposition === "allow" ? "permit" : "deny";
  let consultation: EgressPluginConsultationResult;
  try {
    consultation = await options.pluginConsultant.consultEgress({
      target,
      hostDecision: hostVerdict,
      protocol: "tcp",
    });
  } catch {
    if (hostVerdict === "deny") return hostDecision;
    return { disposition: "deny", reason: "plugin_decision" };
  }

  const contributors =
    consultation.contributors.length > 0 ? { contributors: consultation.contributors } : {};
  const composed = intersectVerdicts(hostVerdict, consultation.decisions);
  const decision =
    hostVerdict === "deny"
      ? { ...hostDecision, ...contributors }
      : composed === "permit"
        ? { ...hostDecision, ...contributors }
        : ({ disposition: "deny", reason: "plugin_decision", ...contributors } as EgressProxyDecision);
  return appendPluginAuditIfConfigured(authority, decision, options);
}

async function appendPluginAuditIfConfigured(
  authority: string,
  decision: EgressProxyDecision,
  options: EgressProxyOptions
): Promise<EgressProxyDecision> {
  if (!options.auditSink || !decision.contributors || decision.contributors.length === 0) {
    return decision;
  }
  try {
    await options.auditSink.appendCritical({
      layer: "l1",
      operation: "egress_decision",
      identity_id: options.auditIdentityId ?? "system",
      result: decision.disposition === "allow" ? "success" : "failure",
      details: {
        authority,
        disposition: decision.disposition,
        reason: decision.disposition === "deny" ? decision.reason : "allow",
      },
      contributors: decision.contributors,
    });
    return decision;
  } catch {
    return {
      disposition: "deny",
      reason: "audit_failed",
      contributors: decision.contributors,
    };
  }
}

export function createCastleWallEgressProxyServer(options: EgressProxyOptions): http.Server {
  const server = http.createServer();
  server.on("connect", (request, clientSocket, head) => {
    void handleConnect(request, clientSocket, head, options);
  });
  return server;
}

async function handleConnect(
  request: http.IncomingMessage,
  clientSocket: Duplex,
  head: Buffer,
  options: EgressProxyOptions
): Promise<void> {
  const authority = request.url ?? "";
  const decision = await decideEgressProxyConnect(authority, options);
  options.onDecision?.(authority, decision);
  if (decision.disposition === "deny") {
    clientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }

  const upstream = net.connect({
    host: decision.address,
    port: decision.target.port,
  });
  upstream.once("connect", () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length > 0) {
      upstream.write(head);
    }
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.once("error", () => {
    clientSocket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });
}

function ruleMatchesTarget(rule: AllowlistRule, target: CanonicalConnectAuthority): boolean {
  if (rule.match.protocol !== undefined && rule.match.protocol !== "tcp" && rule.match.protocol !== "tcp+udp") {
    return false;
  }
  if (rule.match.port !== undefined && !portMatches(rule.match.port, target.port)) {
    return false;
  }

  // Destination axes compose as an OR (parity with the Swift evaluator): when
  // none is specified the destination is "match any" (only protocol/port
  // constrain); when any is specified, at least one must match. The ip/cidr
  // axes match `target.host` only when it is an IP literal (a DNS flow to a
  // resolver connects by raw IP), so a hostname target never spuriously matches.
  const hasHost = rule.match.host !== undefined;
  const hasHostPattern = rule.match.host_pattern !== undefined && rule.match.host_pattern.length > 0;
  const hasIp = rule.match.ip !== undefined;
  const hasCidr = rule.match.cidr !== undefined;
  if (!hasHost && !hasHostPattern && !hasIp && !hasCidr) {
    return true;
  }

  if (rule.match.host !== undefined && hostMatches(rule.match.host, target.host)) {
    return true;
  }
  if (rule.match.host_pattern !== undefined && rule.match.host_pattern.length > 0 && hostPatternMatches(rule.match.host_pattern, target.host)) {
    return true;
  }
  if (rule.match.ip !== undefined && ipMatches(rule.match.ip, target.host)) {
    return true;
  }
  if (rule.match.cidr !== undefined && cidrMatches(rule.match.cidr, target.host)) {
    return true;
  }
  return false;
}

function portMatches(spec: number | number[], port: number): boolean {
  return Array.isArray(spec) ? spec.includes(port) : spec === port;
}

function hostMatches(spec: string | string[], host: string): boolean {
  const values = Array.isArray(spec) ? spec : [spec];
  return values.some((candidate) => canonicalizeRuleHost(candidate) === host);
}

function hostPatternMatches(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = canonicalizeRuleHost(pattern.slice(2));
    return host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return canonicalizeRuleHost(pattern) === host;
}

function canonicalizeRuleHost(host: string): string {
  const ipVersion = net.isIP(host);
  if (ipVersion !== 0) {
    return ipVersion === 6 ? host.toLowerCase() : host;
  }
  return canonicalizeConnectAuthority(`${host}:443`).host;
}

function isPublicRoutableIpv4(address: string): boolean {
  const octets = address.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = octets as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224 || a >= 240) {
    return false;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return false;
  }
  if (a === 169 && b === 254) {
    return false;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return false;
  }
  if (a === 192 && b === 168) {
    return false;
  }
  if (a === 192 && b === 0 && octets[2] === 0) {
    return false;
  }
  if (a === 192 && b === 0 && octets[2] === 2) {
    return false;
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return false;
  }
  if (a === 198 && b === 51 && octets[2] === 100) {
    return false;
  }
  if (a === 203 && b === 0 && octets[2] === 113) {
    return false;
  }
  return true;
}

function isPublicRoutableIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === "::" || lower === "::1") {
    return false;
  }
  if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("ff")) {
    return false;
  }
  if (lower.startsWith("::ffff:")) {
    return isPublicRoutableIpv4(lower.slice("::ffff:".length));
  }
  if (lower.startsWith("2001:db8:")) {
    return false;
  }
  return true;
}

const defaultResolver: EgressProxyResolver = {
  async resolve(host: string): Promise<string[]> {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    return records.map((record) => record.address);
  },
};
