import { describe, it, expect, vi } from "vitest";
import {
  BLOCKED_EGRESS_HOST_MAX_CHARS, BLOCKED_EGRESS_LABEL_MAX_CHARS,
  BLOCKED_EGRESS_IP_MAX_CHARS, BLOCKED_EGRESS_METADATA_MAX_BYTES,
  parseBlockedEgressHost, parseBlockedEgressIp, parseBlockedEgressMetadata,
  BLOCKED_EGRESS_SUBJECT_MAX_CHARS,
} from "../../src/contracts/v1.1/index.js";

const attribution = {
  subject: "castle_wall_producer", evidence_source: "producer_signature",
  verifier: "castle_wall_audit_consumer", state: "verified",
};

describe("bounded blocked-egress parser", () => {
  it("accepts DNS name and label limits without normalization", () => {
    const label = "a".repeat(BLOCKED_EGRESS_LABEL_MAX_CHARS);
    // Three full labels and separators, then the remaining final label fill the cap.
    const prefix = `${label}.${label}.${label}.`;
    const host = prefix + "b".repeat(BLOCKED_EGRESS_HOST_MAX_CHARS - prefix.length);
    expect(parseBlockedEgressHost(host)).toEqual({ ok: true, value: host });
    expect(parseBlockedEgressHost(host + "a")).toEqual({ ok: false, reason: "too_long" });
    expect(parseBlockedEgressHost(label)).toEqual({ ok: true, value: label });
    expect(parseBlockedEgressHost(label + "a")).toEqual({ ok: false, reason: "invalid_host" });
    expect(parseBlockedEgressHost(host.slice(0, -1) + ".").ok).toBe(true);
    expect(parseBlockedEgressHost("MiXeD-host.example.")).toEqual({ ok: true, value: "MiXeD-host.example." });
  });
  it.each(["", "a\u0000b", "a\nb", "a\n", "a b", " a", "a\tb", "é.example", "a:b", "a/b", "a@b", "a?b", "a#b", ".a", "a..b", "a..", "-a", "a-", "a_b"])("refuses invalid DNS text %j", (raw) => {
    expect(parseBlockedEgressHost(raw)).toEqual({ ok: false, reason: "invalid_host" });
  });
  it("refuses literal IPs as host text", () => {
    expect(parseBlockedEgressHost("192.0.2.1")).toEqual({ ok: false, reason: "literal_ip" });
    expect(parseBlockedEgressHost("192.0.2.1.").ok).toBe(false);
    expect(parseBlockedEgressHost("2001:db8::1").ok).toBe(false);
  });
  it("accepts IP literals through the longest embedded-IPv4 form", () => {
    const longest = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
    expect(longest.length).toBe(BLOCKED_EGRESS_IP_MAX_CHARS);
    for (const ip of [longest, "2001:db8::1", "::1", "192.0.2.1"]) {
      expect(parseBlockedEgressIp(ip)).toEqual({ ok: true, value: ip });
    }
    expect(parseBlockedEgressIp(longest + "0")).toEqual({ ok: false, reason: "too_long" });
  });
  it.each(["", "[::1]", "fe80::1%eth0", "192.0.2.1:443", "192.0.2.1/24", "::1/128", "[::1]:443", "256.0.0.1", "01.2.3.4", "a b", "é", "::1\n"])("refuses nonliteral IP text %j", (raw) => {
    expect(parseBlockedEgressIp(raw)).toEqual({ ok: false, reason: "invalid_ip" });
  });
  it("checks encoded metadata size before JSON parsing", () => {
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(parseBlockedEgressMetadata("{".repeat(BLOCKED_EGRESS_METADATA_MAX_BYTES + 1))).toEqual({ ok: false, reason: "too_large" });
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
    const prefix = JSON.stringify({ attribution, subject: "" });
    const subject = "a".repeat(BLOCKED_EGRESS_METADATA_MAX_BYTES - Buffer.byteLength(prefix));
    const exact = JSON.stringify({ attribution, subject });
    expect(Buffer.byteLength(exact)).toBe(BLOCKED_EGRESS_METADATA_MAX_BYTES);
    expect(parseBlockedEgressMetadata(exact)).toEqual({ ok: false, reason: "invalid_subject" });
    expect(parseBlockedEgressMetadata({ attribution, subject: subject + "a" })).toEqual({ ok: false, reason: "too_large" });
    expect(parseBlockedEgressMetadata({ attribution, subject: "é".repeat(subject.length) })).toEqual({ ok: false, reason: "too_large" });
  });
  it("validates all fields and returns detached metadata", () => {
    const raw = { attribution: { ...attribution }, destination_host: "example.test", destination_ip: "::1", subject: "fortress/uid-1" };
    const parsed = parseBlockedEgressMetadata(raw);
    expect(parsed).toEqual({ ok: true, value: raw });
    expect(parseBlockedEgressMetadata(JSON.stringify(raw))).toEqual(parsed);
    if (parsed.ok) expect(parsed.value.attribution).not.toBe(raw.attribution);
    expect(parseBlockedEgressMetadata({ ...raw, destination_host: "bad/host" }).ok).toBe(false);
    expect(parseBlockedEgressMetadata({ ...raw, destination_ip: "bad" }).ok).toBe(false);
    expect(parseBlockedEgressMetadata({ ...raw, destination_ip: undefined }).ok).toBe(false);
  });
  it("refuses unknown fields and incomplete or neutral attribution", () => {
    expect(parseBlockedEgressMetadata({ attribution, extra: true })).toEqual({ ok: false, reason: "unknown_field" });
    expect(parseBlockedEgressMetadata({ attribution: { ...attribution, extra: true } })).toEqual({ ok: false, reason: "unknown_field" });
    for (const key of Object.keys(attribution)) {
      expect(parseBlockedEgressMetadata({ attribution: { ...attribution, [key]: undefined } })).toEqual({ ok: false, reason: "invalid_attribution" });
      expect(parseBlockedEgressMetadata({ attribution: { ...attribution, [key]: "other" } })).toEqual({ ok: false, reason: "invalid_attribution" });
    }
    for (const attr of [null, [], {}, { ...attribution, state: "neutral" }]) {
      expect(parseBlockedEgressMetadata({ attribution: attr })).toEqual({ ok: false, reason: "invalid_attribution" });
    }
  });
  it("accepts unsigned metadata only without a subject", () => {
    const unsigned = { attribution: { ...attribution, state: "unverified" } };
    expect(parseBlockedEgressMetadata(unsigned)).toEqual({ ok: true, value: unsigned });
    for (const subject of ["", 1, null, "claimed-subject"]) {
      expect(parseBlockedEgressMetadata({ ...unsigned, subject })).toEqual({ ok: false, reason: "invalid_subject" });
    }
    for (const subject of ["", 1, null]) {
      expect(parseBlockedEgressMetadata({ attribution, subject })).toEqual({ ok: false, reason: "invalid_subject" });
    }
  });
  it("returns closed reasons for malformed and non-object inputs", () => {
    for (const raw of [undefined, null, 1, [], true]) {
      expect(parseBlockedEgressMetadata(raw)).toEqual({ ok: false, reason: "type" });
      expect(parseBlockedEgressHost(raw)).toEqual({ ok: false, reason: "type" });
      expect(parseBlockedEgressIp(raw)).toEqual({ ok: false, reason: "type" });
    }
    expect(parseBlockedEgressMetadata("{")).toEqual({ ok: false, reason: "malformed" });
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    expect(parseBlockedEgressMetadata(cyclic)).toEqual({ ok: false, reason: "malformed" });
  });
  it.each(["0177.0.0.1", "192.168.001.1", "0x7f.0.0.1", "0X7f.0.0.1", "2130706433", "127.1", "0x7f000001", "01.2.3.4", "a.123", "a.0Xff.example"])("refuses numeric IPv4 host form %s", (host) => {
    expect(parseBlockedEgressHost(host)).toEqual({ ok: false, reason: "literal_ip" });
  });
  it.each(["a1.example", "1a.example"])("accepts ordinary digit-bearing name %s", (host) => {
    expect(parseBlockedEgressHost(host)).toEqual({ ok: true, value: host });
  });
  it("bounds subjects and refuses controls and markup", () => {
    const subject = "a".repeat(BLOCKED_EGRESS_SUBJECT_MAX_CHARS);
    expect(parseBlockedEgressMetadata({ attribution, subject })).toEqual({ ok: true, value: { attribution, subject } });
    for (const bad of [subject + "a", "x\0", "x\n", "x\t", "x\x7f", "<x>", "é"]) {
      expect(parseBlockedEgressMetadata({ attribution, subject: bad })).toEqual({ ok: false, reason: "invalid_subject" });
    }
  });
  it("bounds object work before serialization without invoking getters or toJSON", () => {
    const stringify = vi.spyOn(JSON, "stringify");
    const getter = vi.fn(() => "secret");
    const toJSON = vi.fn(() => ({}));
    try {
      expect(parseBlockedEgressMetadata({ attribution, subject: "a".repeat(BLOCKED_EGRESS_METADATA_MAX_BYTES + 1) })).toEqual({ ok: false, reason: "too_large" });
      expect(parseBlockedEgressMetadata(Object.fromEntries(Array.from({ length: 10000 }, (_, i) => [String(i), "x"])))).toEqual({ ok: false, reason: "unknown_field" });
      expect(parseBlockedEgressMetadata(Object.defineProperty({}, "subject", { enumerable: true, get: getter }))).toEqual({ ok: false, reason: "malformed" });
      expect(parseBlockedEgressMetadata({ toJSON })).toEqual({ ok: false, reason: "malformed" });
      expect(parseBlockedEgressMetadata(new Date(0))).toEqual({ ok: false, reason: "type" });
      expect(stringify).not.toHaveBeenCalled();
      expect(getter).not.toHaveBeenCalled();
      expect(toJSON).not.toHaveBeenCalled();
    } finally { stringify.mockRestore(); }
  });
});
