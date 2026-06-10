/**
 * IP / CIDR matcher tests (#380).
 *
 * These mirror the Swift `AllowlistEvaluatorTests` IP/CIDR cases so the two
 * evaluators agree on every input. Matching is family-aware: exact-IP equality
 * on normalized addresses, CIDR by prefix containment, mismatched family never
 * matches.
 */

import { describe, it, expect } from "vitest";
import {
  isValidIp,
  isValidCidr,
  parseCidr,
  ipMatches,
  cidrMatches,
} from "../../../src/castle-wall/allowlist/ip-cidr.js";

describe("castle-wall/allowlist/ip-cidr validation", () => {
  it("validates IPv4 and IPv6 literals", () => {
    expect(isValidIp("1.1.1.1")).toBe(true);
    expect(isValidIp("::1")).toBe(true);
    expect(isValidIp("2001:db8::1")).toBe(true);
    expect(isValidIp("999.1.1.1")).toBe(false);
    expect(isValidIp("10.0.0.0/8")).toBe(false); // a CIDR is not an IP
    expect(isValidIp("")).toBe(false);
    expect(isValidIp(1234 as unknown)).toBe(false);
  });

  it("validates and parses CIDRs, rejecting bad prefixes and missing slash", () => {
    expect(isValidCidr("10.0.0.0/8")).toBe(true);
    expect(isValidCidr("2001:db8::/32")).toBe(true);
    expect(parseCidr("10.0.0.0/24")).toEqual({ address: "10.0.0.0", prefix: 24, family: 4 });
    expect(parseCidr("2001:db8::/48")).toEqual({ address: "2001:db8::", prefix: 48, family: 6 });
    expect(isValidCidr("10.0.0.0/33")).toBe(false); // out of range for IPv4
    expect(isValidCidr("::/129")).toBe(false); // out of range for IPv6
    expect(isValidCidr("10.0.0.0")).toBe(false); // no slash
    expect(isValidCidr("10.0.0.0/")).toBe(false); // empty prefix
    expect(isValidCidr("10.0.0.0/x")).toBe(false); // non-numeric prefix
    expect(isValidCidr("not-an-ip/24")).toBe(false);
  });
});

describe("castle-wall/allowlist/ip-cidr ipMatches", () => {
  it("matches exact IPv4 in single and array form", () => {
    expect(ipMatches("1.1.1.1", "1.1.1.1")).toBe(true);
    expect(ipMatches(["1.1.1.1", "8.8.8.8"], "8.8.8.8")).toBe(true);
    expect(ipMatches(["1.1.1.1", "8.8.8.8"], "9.9.9.9")).toBe(false);
  });

  it("matches IPv6 across textual forms and respects family", () => {
    expect(ipMatches("0:0:0:0:0:0:0:1", "::1")).toBe(true);
    expect(ipMatches("2001:db8::1", "2001:0db8:0000::1")).toBe(true);
    expect(ipMatches("1.1.1.1", "::1")).toBe(false); // family mismatch
    expect(ipMatches("::1", "1.1.1.1")).toBe(false);
  });

  it("never matches a non-IP destination (e.g. a hostname)", () => {
    expect(ipMatches("1.1.1.1", "api.example.com")).toBe(false);
  });

  it("ignores malformed candidate entries", () => {
    expect(ipMatches(["not-an-ip", "8.8.8.8"], "8.8.8.8")).toBe(true);
    expect(ipMatches(["not-an-ip"], "8.8.8.8")).toBe(false);
  });
});

describe("castle-wall/allowlist/ip-cidr cidrMatches", () => {
  it("contains IPv4 addresses inside the prefix, excludes boundaries", () => {
    expect(cidrMatches("10.0.0.0/24", "10.0.0.1")).toBe(true);
    expect(cidrMatches("10.0.0.0/24", "10.0.0.255")).toBe(true);
    expect(cidrMatches("10.0.0.0/24", "10.0.1.0")).toBe(false);
    expect(cidrMatches("10.0.0.0/24", "9.255.255.255")).toBe(false);
  });

  it("treats /32 and /128 as exact-host", () => {
    expect(cidrMatches("203.0.113.7/32", "203.0.113.7")).toBe(true);
    expect(cidrMatches("203.0.113.7/32", "203.0.113.8")).toBe(false);
    expect(cidrMatches("2001:db8::1/128", "2001:db8::1")).toBe(true);
    expect(cidrMatches("2001:db8::1/128", "2001:db8::2")).toBe(false);
  });

  it("contains IPv6 addresses inside the prefix", () => {
    expect(cidrMatches("2001:db8::/32", "2001:db8:dead:beef::1")).toBe(true);
    expect(cidrMatches("2001:db8::/32", "2001:db9::1")).toBe(false);
  });

  it("never matches across families", () => {
    expect(cidrMatches("10.0.0.0/8", "::1")).toBe(false);
    expect(cidrMatches("2001:db8::/32", "10.0.0.1")).toBe(false);
  });

  it("ignores malformed CIDR candidates and non-IP destinations", () => {
    expect(cidrMatches(["10.0.0.0/33", "10.0.0.0/24"], "10.0.0.5")).toBe(true);
    expect(cidrMatches(["10.0.0.0/33"], "10.0.0.5")).toBe(false);
    expect(cidrMatches("10.0.0.0/24", "api.example.com")).toBe(false);
  });
});
