/**
 * Active-resolver-set enumeration tests (the 2026-07-12 Mini1 drill bug).
 *
 * The derived DNS allow (#380) must scope to the resolver set the host's
 * queries ACTUALLY go to. On macOS a long-lived daemon's `dns.getServers()`
 * is a process-lifetime snapshot and the resolv.conf view misses configd's
 * scoped resolvers, so `collectSystemResolvers` reads `scutil --dns` fresh
 * there and FAILS CLOSED (empty set -> no derived rule -> loud refuse-to-arm)
 * when that read is unavailable -- it never falls back to the possibly-stale
 * snapshot (adversarial-review BLOCKER on the first cut). These tests
 * exercise the parse, the byte-level non-unicast classification, zone-scoped
 * entry rejection, the non-darwin passthrough, the fail-closed failure path,
 * and the end-to-end derivation composition.
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

  it("drops noncanonical non-unicast spellings by parsed bytes (review LOW)", () => {
    const output = [
      "  nameserver[0] : 0:0:0:0:0:0:0:0",
      "  nameserver[1] : 0000::",
      "  nameserver[2] : ::ffff:255.255.255.255",
      "  nameserver[3] : ::ffff:224.0.0.251",
      "  nameserver[4] : ::ffff:9.9.9.9",
      "  nameserver[5] : FF02::FB",
      "  nameserver[6] : 0.1.2.3",
    ].join("\n");
    expect(parseScutilDnsNameservers(output)).toEqual(["::ffff:9.9.9.9"]);
  });

  it("drops zone-scoped link-local entries instead of widening them (review MED)", () => {
    const output = [
      "  nameserver[0] : fe80::1%en0",
      "  nameserver[1] : 9.9.9.9",
    ].join("\n");
    expect(parseScutilDnsNameservers(output)).toEqual(["9.9.9.9"]);
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
  it("darwin: returns the fresh scutil nameserver set and never reads the getServers snapshot", async () => {
    const getServersFn = vi.fn(() => ["10.99.99.99"]);
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn,
      runScutilDns: async () => SCUTIL_TAILSCALE_SAMPLE,
    });
    expect(resolvers).toEqual([
      "100.100.100.100",
      "fd7a:115c:a1e0::53",
      "192.168.1.1",
    ]);
    expect(getServersFn).not.toHaveBeenCalled();
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

  it("darwin: a scutil failure FAILS CLOSED to an empty set, never the stale snapshot (review BLOCKER)", async () => {
    const getServersFn = vi.fn(() => ["192.168.1.1"]);
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
      getServersFn,
      runScutilDns: async () => {
        throw new Error("scutil timed out");
      },
    });
    expect(resolvers).toEqual([]);
    expect(getServersFn).not.toHaveBeenCalled();
  });

  it("darwin: the fail-closed empty set derives NO rule (deny DNS, never an any-resolver or stale grant)", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
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

  it("end-to-end: the derived DNS rule carries the Tailscale MagicDNS resolver (the drill bug)", async () => {
    const resolvers = await collectSystemResolvers({
      platform: "darwin",
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
    expect(derived?.match.ip).toContain("192.168.1.1");
    expect(derived?.match.port).toEqual([53]);
  });
});
