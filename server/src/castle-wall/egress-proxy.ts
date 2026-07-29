import { promises as dns } from "node:dns";
import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";

import type { AllowlistRule } from "./allowlist/schema.js";
import {
  canonicalizeConnectAuthority,
  allowlistAllowsTarget,
  type CanonicalConnectAuthority,
} from "./allowlist/match.js";
import type { AuditEntryInput } from "../operational/audit-log.js";
import type { PluginContribution } from "../substrate/attribution.js";
import { intersectVerdicts, type EnforcementDecision, type HostDecision } from "../substrate/verdict.js";

// Canonicalization + rule matching moved VERBATIM to `allowlist/match.ts`
// (2026-07-14, observe-fold idempotency chokepoint) so the observe engine's
// allowlist-aware fold shares the identical matcher without importing this
// evaluator module (THE RED-LINE structural pin). Re-exported here so every
// existing consumer of this module's surface is unchanged.
export {
  canonicalizeConnectAuthority,
  allowlistAllowsTarget,
  ruleMatchesTarget,
  ConnectAuthorityError,
  type CanonicalConnectAuthority,
  type CanonicalizationErrorCode,
} from "./allowlist/match.js";

export type EgressProxyDecision =
  | {
      disposition: "deny";
      reason:
        | "canonicalization_failed"
        | "allowlist_miss"
        | "resolution_failed"
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

/**
 * Decide one CONNECT request. CONTRACT: this function NEVER rejects; every
 * failure mode resolves to a deny decision. Both CONNECT handlers (the
 * castle-wall proxy below and `egress-gate/gate-server.ts`) invoke it from a
 * void-discarded async path, so an escaping rejection would become an
 * unhandledRejection that kills the whole enforcement process -- and a
 * rejecting DNS lookup (ENOTFOUND on an allowlisted-but-unresolvable name,
 * or a transient outage on a legit one) is agent-triggerable at will.
 */
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

  let addresses: string[];
  if (target.isIpLiteral) {
    addresses = [target.host];
  } else {
    try {
      addresses = await (options.resolver ?? defaultResolver).resolve(target.host);
    } catch {
      // Fail-closed chokepoint (see the never-rejects contract above): a
      // resolver rejection is a DENY, never an escaping rejection.
      return applyEgressPlugins(
        authority,
        { disposition: "deny", reason: "resolution_failed" },
        target,
        options
      );
    }
  }
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
    handleConnect(request, clientSocket, head, options).catch(() => {
      // Backstop (deny-direction): a rejection escaping the handler would
      // surface as an unhandledRejection and kill the whole proxy process
      // (letting the client kill its own enforcement path). Same hardened
      // shape as the exclusive-egress gate (egress-gate/gate-server.ts).
      if (!clientSocket.destroyed) {
        clientSocket.destroy();
      }
    });
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

  // Swallow client-socket errors BEFORE the first await (same hazard and fix
  // as the exclusive-egress gate's handler, egress-gate/gate-server.ts): the
  // client can reset the connection during the async decision window below
  // (which performs real DNS resolution), and a listener-less 'error' event
  // would crash the whole proxy process (uncaughtException). The handler
  // also tears down the upstream leg once one exists.
  let upstream: net.Socket | null = null;
  clientSocket.on("error", () => {
    upstream?.destroy();
  });

  const decision = await decideEgressProxyConnect(authority, options);
  options.onDecision?.(authority, decision);
  if (decision.disposition === "deny") {
    clientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }

  // The client may have reset during the async window above; don't dial the
  // upstream for a dead client leg.
  if (clientSocket.destroyed) {
    return;
  }
  const upstreamSocket = net.connect({
    host: decision.address,
    port: decision.target.port,
  });
  upstream = upstreamSocket;
  let established = false;
  upstreamSocket.once("connect", () => {
    established = true;
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length > 0) {
      upstreamSocket.write(head);
    }
    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
  });
  upstreamSocket.once("error", () => {
    // Pre-establishment: report a clean 502. Post-establishment the client
    // treats the stream as raw tunneled bytes (e.g. mid-TLS); injecting an
    // HTTP status line would be in-band garbage, so just drop the client leg.
    if (established) {
      clientSocket.destroy();
    } else {
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    }
  });
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
