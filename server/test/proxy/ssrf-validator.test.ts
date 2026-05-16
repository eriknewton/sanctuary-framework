import { describe, it, expect, vi, beforeEach } from "vitest";
import { lookup } from "node:dns/promises";
import {
  SsrfRejectionReason,
  validateUpstreamSseUrl,
} from "../../src/proxy/ssrf-validator.js";

vi.mock("node:dns/promises", () => ({
  lookup: vi.fn(),
}));

const mockLookup = vi.mocked(lookup);

describe("validateUpstreamSseUrl", () => {
  beforeEach(() => {
    mockLookup.mockReset();
  });

  it.each(["ftp://example.com/sse", "file:///tmp/sse", "javascript:alert(1)"])(
    "rejects unsupported scheme %s",
    async (url) => {
      await expect(validateUpstreamSseUrl(url)).resolves.toEqual({
        ok: false,
        reason: SsrfRejectionReason.invalid_scheme,
      });
    }
  );

  it.each(["127.0.0.1", "127.0.0.5", "127.255.255.255"])(
    "rejects direct IPv4 loopback %s",
    async (host) => {
      await expect(validateUpstreamSseUrl(`http://${host}/sse`)).resolves.toEqual({
        ok: false,
        reason: SsrfRejectionReason.loopback,
      });
    }
  );

  it.each(["10.0.0.1", "172.16.0.1", "192.168.1.1"])(
    "rejects direct IPv4 RFC1918 %s",
    async (host) => {
      await expect(validateUpstreamSseUrl(`http://${host}/sse`)).resolves.toEqual({
        ok: false,
        reason: SsrfRejectionReason.private_network,
      });
    }
  );

  it("rejects direct IPv4 link-local", async () => {
    await expect(validateUpstreamSseUrl("http://169.254.1.1/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.link_local,
    });
  });

  it("rejects direct IPv4 multicast", async () => {
    await expect(validateUpstreamSseUrl("http://224.0.0.1/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.multicast,
    });
  });

  it("rejects cloud metadata IPv4", async () => {
    await expect(validateUpstreamSseUrl("http://169.254.169.254/latest")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.metadata_service,
    });
  });

  it.each(["fd00:ec2::254", "2606:f0:1000::4"])(
    "rejects cloud metadata IPv6 %s",
    async (host) => {
      await expect(validateUpstreamSseUrl(`http://[${host}]/latest`)).resolves.toEqual({
        ok: false,
        reason: SsrfRejectionReason.metadata_service,
      });
    }
  );

  it("rejects IPv6 loopback", async () => {
    await expect(validateUpstreamSseUrl("http://[::1]/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.ipv6_loopback,
    });
  });

  it("rejects IPv6 link-local", async () => {
    await expect(validateUpstreamSseUrl("http://[fe80::1]/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.link_local,
    });
  });

  it("rejects IPv6 multicast", async () => {
    await expect(validateUpstreamSseUrl("http://[ff02::1]/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.multicast,
    });
  });

  it("rejects DNS names resolving to private IPs", async () => {
    mockLookup.mockResolvedValue([{ address: "10.0.0.2", family: 4 }]);

    await expect(validateUpstreamSseUrl("https://private.example/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.dns_resolved_to_blocked,
    });
  });

  it("rejects DNS names resolving to multiple IPs when one is private", async () => {
    mockLookup.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "192.168.1.10", family: 4 },
    ]);

    await expect(validateUpstreamSseUrl("https://mixed.example/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.dns_resolved_to_blocked,
    });
  });

  it("rejects DNS resolution failures", async () => {
    mockLookup.mockRejectedValue(new Error("ENOTFOUND"));

    await expect(validateUpstreamSseUrl("https://missing.example/sse")).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.dns_resolution_failed,
    });
  });

  it("accepts a public hostname resolving cleanly", async () => {
    mockLookup.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);

    await expect(validateUpstreamSseUrl("https://public.example/sse")).resolves.toEqual({
      ok: true,
    });
  });

  it("allows private networks with the operator escape hatch", async () => {
    await expect(
      validateUpstreamSseUrl("http://10.0.0.1/sse", { allowPrivateNetworks: true })
    ).resolves.toEqual({ ok: true });
  });

  it("rejects loopback even with the operator escape hatch", async () => {
    await expect(
      validateUpstreamSseUrl("http://127.0.0.1/sse", { allowPrivateNetworks: true })
    ).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.loopback,
    });
  });

  it("rejects metadata service addresses even with the operator escape hatch", async () => {
    await expect(
      validateUpstreamSseUrl("http://169.254.169.254/latest", { allowPrivateNetworks: true })
    ).resolves.toEqual({
      ok: false,
      reason: SsrfRejectionReason.metadata_service,
    });
  });
});
