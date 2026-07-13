/**
 * Active-resolver-set enumeration tests (the 2026-07-12 Mini1 drill bug).
 *
 * The derived DNS allow (#380) must scope to the resolver set the host's
 * queries ACTUALLY go to. On macOS `dns.getServers()` and `scutil --dns`
 * diverge under NetworkExtension DNS providers (Tailscale MagicDNS at
 * 100.100.100.100 was the live resolver on the drill host while
 * `dns.getServers()` never reported it), so `collectSystemResolvers` unions
 * the two there. These tests exercise the parse, the non-unicast filtering,
 * the union/dedupe, the non-darwin passthrough, the narrower-never-wider
 * scutil-failure fallback, and the end-to-end derivation composition.
 */

import { describe, it, expect, vi } from "vitest";
import {
  collectSystemResolvers,
  parseScutilDnsNameservers,
} from "../../../src/castle-wall/runtime/system-resolvers.js";
import {
  deriveDnsRuleForHostnameRules,
  DERIVED_DNS_RULE_ID,
} from "../../../src/castle-wall/allowlist/dns-derivation.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

/** Trimmed-down but structurally faithful `scutil --dns` output from a
 *  Tailscale MagicDNS host (the drill-host shape): the MagicDNS resolver in
 *  the global block, a scoped supplemental resolver, the DHCP resolver in a
 *  scoped block, and an mdns resolver block with no nameserver entries. */
const SCUTIL_TAILSCALE_SAMPLE = `DNS configuration

resolver #1
  search domain[0] : example.ts.net
  nameserver[0] : 100.100.100.100
  nameserver[1] : fd7a:115c:a1e0::53
  if_index : 22 (utun4)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)

resolver #3
  nameserver[0] : 192.168.1.1
  if_index : 14 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : 100.100.100.100
  if_index : 14 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`;

function hostRule(): AllowlistRule {
  return {
    id: "provisioned-hermes-venice",
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-12T00:00:00.000Z",
    match: { host: "api.venice.ai", port: 443, protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

describe("castle-wall/runtime/system-resolvers parseScutilDnsNameservers", () => {
  it("collects every nameserver across resolver blocks, deduped in order", () => {
    expect(parseScutilDnsNameservers(SCUTIL_TAILSCALE_SAMPLE)).toEqual([
      "100.100.100.100",
      "fd7a:115c:a1e0::53",
      "192.168.1.1",
    ]);
  });

  it("drops multicast, unspecified, broadcast, and non-IP entries", () => {
    const output = [
      "  nameserver[0] : 224.0.0.251",
      "  nameserver[1] : ff02::fb",
      "  nameserver[2] : 0.0.0.0",
      "  nameserver[3] : 255.255.255.255",
      "  nameserver[4] : ::",
      "  nameserver[5] : not-an-ip",
      "  nameserver[6] : 9.9.9.9",
    ].join("\n");
    expect(parseScutilDnsNameservers(output)).toEqual(["9.9.9.9"]);
  });

  it("keeps link-local resolvers with a zone id (normalization is downstream)", () => {
    expect(parseScutilDnsNameservers("  nameserver[0] : fe80::1%en0")).toEqual([
      "fe80::1%en0",
    ]);
  });

  it("ignores non-nameserver lines (domains, flags, if_index)", () => {
    const output = [
      "  search domain[0] : example.ts.net",
      "  if_index : 22 (utun4)",
      "  flags    : Scoped",
    ].join("\n");
    expect(parseScutilDnsNameservers(output)).toEqual([]);
  });
});

describe("castle-wall/runtime/system-resolvers collectSystemResolvers", () => {
  it("darwin: unions dns.getServers() with the scutil nameserver set, deduped", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn: () => ["192.168.1.1"],
      runScutilDns: async () => SCUTIL_TAILSCALE_SAMPLE,
    });
    expect(resolvers).toEqual([
      "192.168.1.1",
      "100.100.100.100",
      "fd7a:115c:a1e0::53",
    ]);
  });

  it("non-darwin: returns dns.getServers() unchanged and never runs scutil", async () => {
    const runScutilDns = vi.fn(async () => SCUTIL_TAILSCALE_SAMPLE);
    const resolvers = await collectSystemResolvers({
      platform: "linux",
      getServersFn: () => ["10.0.0.1"],
      runScutilDns,
    });
    expect(resolvers).toEqual(["10.0.0.1"]);
    expect(runScutilDns).not.toHaveBeenCalled();
  });

  it("darwin: a scutil failure falls back to dns.getServers() alone (narrower, never wider)", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn: () => ["192.168.1.1"],
      runScutilDns: async () => {
        throw new Error("scutil timed out");
      },
    });
    expect(resolvers).toEqual(["192.168.1.1"]);
  });

  it("darwin: scutil failure with an empty getServers() stays empty (fail-closed downstream: no derived rule)", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn: () => [],
      runScutilDns: async () => {
        throw new Error("boom");
      },
    });
    expect(resolvers).toEqual([]);
    expect(
      deriveDnsRuleForHostnameRules({
        rules: [hostRule()],
        resolvers,
        createdAt: "2026-07-12T00:00:00.000Z",
      }),
    ).toBeNull();
  });

  it("end-to-end: the derived DNS rule now carries the Tailscale MagicDNS resolver (the drill bug)", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn: () => ["192.168.1.1"],
      runScutilDns: async () => SCUTIL_TAILSCALE_SAMPLE,
    });
    const derived = deriveDnsRuleForHostnameRules({
      rules: [hostRule()],
      resolvers,
      createdAt: "2026-07-12T00:00:00.000Z",
    });
    expect(derived?.id).toBe(DERIVED_DNS_RULE_ID);
    expect(derived?.match.ip).toContain("100.100.100.100");
    expect(derived?.match.ip).toContain("fd7a:115c:a1e0::53");
    expect(derived?.match.port).toEqual([53]);
  });
});
