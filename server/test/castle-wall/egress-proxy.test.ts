import { describe, expect, it } from "vitest";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import {
  allowlistAllowsTarget,
  canonicalizeConnectAuthority,
  decideEgressProxyConnect,
  isPublicRoutableIp,
  type EgressProxyResolver,
} from "../../src/castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";

function allowHost(host: string | string[], port = 443): AllowlistRule {
  return {
    id: "allow-test",
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-05-29T00:00:00.000Z",
    match: { host, port, protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function resolverReturning(addresses: string[], calls: string[] = []): EgressProxyResolver {
  return {
    async resolve(host: string): Promise<string[]> {
      calls.push(host);
      return addresses;
    },
  };
}

describe("castle-wall/egress-proxy", () => {
  it("denies a non-allowlisted host by default", async () => {
    const decision = await decideEgressProxyConnect("blocked.example:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
    });
    expect(decision).toEqual({ disposition: "deny", reason: "allowlist_miss" });
  });

  it("checks the allowlist before resolving denied hostnames", async () => {
    const calls: string[] = [];
    const decision = await decideEgressProxyConnect("blocked.example:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"], calls),
    });
    expect(decision).toEqual({ disposition: "deny", reason: "allowlist_miss" });
    expect(calls).toEqual([]);
  });

  it.each([
    "127.0.0.1",
    "10.0.0.7",
    "172.16.0.1",
    "192.168.1.9",
    "169.254.10.20",
    "224.0.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
  ])("denies post-resolve non-public address %s", async (address) => {
    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning([address]),
    });
    expect(decision).toEqual({ disposition: "deny", reason: "non_public_resolved_address" });
  });

  it("resolves a rejecting resolver to a DENY, never an escaping rejection (fail-closed chokepoint)", async () => {
    // Regression: a DNS failure on an allowlisted name (ENOTFOUND, timeout,
    // SERVFAIL) is agent-triggerable; both CONNECT handlers invoke this
    // evaluator from a void async path, so a rejection here would become an
    // unhandledRejection that kills the enforcement process.
    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: {
        resolve: () => Promise.reject(new Error("getaddrinfo ENOTFOUND api.example.com")),
      },
    });
    expect(decision).toEqual({ disposition: "deny", reason: "resolution_failed" });
  });

  it("allows an allowlisted host only after a public post-resolve address", async () => {
    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
    });
    expect(decision).toEqual({
      disposition: "allow",
      target: {
        host: "api.example.com",
        port: 443,
        authority: "api.example.com:443",
        isIpLiteral: false,
      },
      address: "93.184.216.34",
    });
  });

  it.each([
    ["bücher.example:443", "xn--bcher-kva.example", true],
    ["BÜCHER.EXAMPLE.:443", "xn--bcher-kva.example", true],
    ["Api.Example.Com.:443", "api.example.com", true],
    ["user@api.example.com:443", "api.example.com", false],
    ["api.example.com\r\n\t:443", "api.example.com", false],
    ["2001:4860:4860::8888:443", "2001:4860:4860::8888", false],
    ["[2001:4860:4860::8888]:443", "2001:4860:4860::8888", true],
  ])("canonicalizes %s without bypassing allowlist", (authority, allowedHost, shouldMatch) => {
    let matches = false;
    try {
      const target = canonicalizeConnectAuthority(authority);
      matches = allowlistAllowsTarget([allowHost(allowedHost)], target);
    } catch {
      matches = false;
    }
    expect(matches).toBe(shouldMatch);
  });

  it.each([
    ["127.0.0.1", false],
    ["192.168.0.1", false],
    ["169.254.1.1", false],
    ["224.0.0.1", false],
    ["93.184.216.34", true],
    ["::1", false],
    ["fc00::1", false],
    ["fe80::1", false],
    ["ff02::1", false],
    ["2606:4700:4700::1111", true],
  ])("classifies public routability for %s", (address, expected) => {
    expect(isPublicRoutableIp(address)).toBe(expected);
  });

  // IP / CIDR matcher parity with the Swift evaluator (#380). The TS evaluator
  // matches ip/cidr against an IP-literal CONNECT target host.
  function allowIpRule(ip: string | string[]): AllowlistRule {
    return {
      id: "allow-ip",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-06-10T00:00:00.000Z",
      match: { ip, port: 53, protocol: "tcp+udp" },
      scope: {},
      disposition: "allow",
    };
  }
  function allowCidrRule(cidr: string | string[]): AllowlistRule {
    return {
      id: "allow-cidr",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-06-10T00:00:00.000Z",
      match: { cidr, protocol: "tcp" },
      scope: {},
      disposition: "allow",
    };
  }

  it("matches an ip-scoped rule against an IP-literal target", () => {
    const target = canonicalizeConnectAuthority("1.1.1.1:53");
    expect(allowlistAllowsTarget([allowIpRule(["1.1.1.1", "8.8.8.8"])], target)).toBe(true);
  });

  it("does NOT match an ip-scoped rule for a non-listed IP (the security property)", () => {
    const target = canonicalizeConnectAuthority("9.9.9.9:53");
    expect(allowlistAllowsTarget([allowIpRule(["1.1.1.1", "8.8.8.8"])], target)).toBe(false);
  });

  it("matches a cidr-scoped rule by prefix containment, family-aware", () => {
    expect(
      allowlistAllowsTarget([allowCidrRule("10.0.0.0/24")], canonicalizeConnectAuthority("10.0.0.5:443"))
    ).toBe(true);
    expect(
      allowlistAllowsTarget([allowCidrRule("10.0.0.0/24")], canonicalizeConnectAuthority("10.0.1.5:443"))
    ).toBe(false);
    expect(
      allowlistAllowsTarget([allowCidrRule("2001:db8::/32")], canonicalizeConnectAuthority("[2001:db8::1]:443"))
    ).toBe(true);
  });

  it("never matches ip/cidr against a hostname target", () => {
    const target = canonicalizeConnectAuthority("api.example.com:53");
    expect(allowlistAllowsTarget([allowIpRule("1.1.1.1")], target)).toBe(false);
    expect(allowlistAllowsTarget([allowCidrRule("10.0.0.0/8")], target)).toBe(false);
  });
});
