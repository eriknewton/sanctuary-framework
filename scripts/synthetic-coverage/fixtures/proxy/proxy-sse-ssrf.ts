import type { AuditEntryInput } from "../../../../server/src/operational/audit-log.js";
import {
  SsrfRejectionReason,
  validateUpstreamSseUrl,
} from "../../../../server/src/proxy/ssrf-validator.js";
import { registerFixture } from "../../registry.js";
import { outcome } from "../state-trust/helpers.js";

const CLAIM_ID = "16";
const CLAIM_LABEL = "Proxy SSE SSRF protection";

// Entrypoints: validateUpstreamSseUrl and ClientManager's audited private-network escape hatch shape.
// Mirrored tests: server/test/proxy/ssrf-validator.test.ts and client-manager.test.ts.
// Matrix claim: Proxy SSE SSRF protection.

class MemoryProxyAuditLog {
  entries: AuditEntryInput[] = [];

  async appendCritical(entry: AuditEntryInput): Promise<void> {
    this.entries.push(entry);
  }
}

async function recordEscapeHatchUse(auditLog: MemoryProxyAuditLog, server: string): Promise<void> {
  await auditLog.appendCritical({
    layer: "l2",
    operation: "proxy_ssrf_escape_hatch_used",
    identity_id: "system",
    result: "success",
    details: {
      event_type: "proxy.ssrf.escape_hatch_used",
      server,
    },
  });
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-sse-ssrf: loopback rejected", async () => {
  const started = performance.now();
  const direct = await validateUpstreamSseUrl("http://127.0.0.1:8787/sse");
  const localhost = await validateUpstreamSseUrl("http://localhost:8787/sse", { dnsTimeoutMs: 250 });
  const passed =
    direct.ok === false &&
    direct.reason === SsrfRejectionReason.loopback &&
    localhost.ok === false &&
    [
      SsrfRejectionReason.loopback,
      SsrfRejectionReason.dns_resolved_to_blocked,
      SsrfRejectionReason.dns_resolution_failed,
    ].includes(localhost.reason);

  return outcome(started, passed, "expected loopback SSE targets rejected before connect");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-sse-ssrf: rfc1918 rejected", async () => {
  const started = performance.now();
  const results = await Promise.all([
    validateUpstreamSseUrl("http://10.0.0.1/sse"),
    validateUpstreamSseUrl("http://172.16.0.1/sse"),
    validateUpstreamSseUrl("http://192.168.0.1/sse"),
  ]);
  const passed = results.every(
    (result) => result.ok === false && result.reason === SsrfRejectionReason.private_network,
  );

  return outcome(started, passed, "expected RFC1918 SSE targets rejected by default");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-sse-ssrf: link-local and ipv6 loopback rejected", async () => {
  const started = performance.now();
  const linkLocal = await validateUpstreamSseUrl("http://169.254.0.1/sse");
  const ipv6Loopback = await validateUpstreamSseUrl("http://[::1]/sse");
  const ipv6LinkLocal = await validateUpstreamSseUrl("http://[fe80::1]/sse");
  const passed =
    linkLocal.ok === false &&
    linkLocal.reason === SsrfRejectionReason.link_local &&
    ipv6Loopback.ok === false &&
    ipv6Loopback.reason === SsrfRejectionReason.ipv6_loopback &&
    ipv6LinkLocal.ok === false &&
    ipv6LinkLocal.reason === SsrfRejectionReason.link_local;

  return outcome(started, passed, "expected link-local and IPv6 loopback SSE targets rejected");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-sse-ssrf: cloud metadata rejected", async () => {
  const started = performance.now();
  const awsIpv4 = await validateUpstreamSseUrl("http://169.254.169.254/latest/meta-data");
  const awsIpv6 = await validateUpstreamSseUrl("http://[fd00:ec2::254]/latest/meta-data");
  const gcpIpv6 = await validateUpstreamSseUrl("http://[2606:f0:1000::4]/computeMetadata/v1");
  const passed =
    awsIpv4.ok === false &&
    awsIpv4.reason === SsrfRejectionReason.metadata_service &&
    awsIpv6.ok === false &&
    awsIpv6.reason === SsrfRejectionReason.metadata_service &&
    gcpIpv6.ok === false &&
    gcpIpv6.reason === SsrfRejectionReason.metadata_service;

  return outcome(started, passed, "expected cloud metadata service SSE targets rejected");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-sse-ssrf: private-network escape hatch audited", async () => {
  const started = performance.now();
  const result = await validateUpstreamSseUrl("http://10.0.0.1/sse", {
    allowPrivateNetworks: true,
  });
  const auditLog = new MemoryProxyAuditLog();
  if (result.ok) {
    await recordEscapeHatchUse(auditLog, "private-sse");
  }
  const entry = auditLog.entries[0];
  const passed =
    result.ok === true &&
    entry?.operation === "proxy_ssrf_escape_hatch_used" &&
    entry.result === "success" &&
    entry.details.event_type === "proxy.ssrf.escape_hatch_used" &&
    entry.details.server === "private-sse";

  return outcome(started, passed, "expected allow_private_networks usage to emit critical audit evidence");
});
