/** Capability: forward parsing, bounded admission, status mapping and framing. */
import { describe, expect, it } from "vitest";
import {
  parseSurrogateForwardTarget, reconcileSurrogateHost, checkSurrogateRawHeaders,
  scanSurrogateRequest, buildSurrogateUpstreamHeaders, surrogateContentLength,
  SURROGATE_STATUS, mintSurrogatePlaceholder, MAX_PLACEHOLDERS_PER_REQUEST,
} from "../../src/credential-surrogate/index.js";

describe("surrogate forward pure functions", () => {
  it.each(["https://api.example.test/", "http://a@api.example.test/", "http://api.example.test:443/", "http://127.0.0.1/", "http://[::1]/", "http://0x7f000001/", "http://2130706433/", "/relative", "http://api.example.test/#frag", "http://api.example.test\\evil/", "http://api.example.test:080/"])("refuses ambiguous target %s", (target) => {
    expect(parseSurrogateForwardTarget(target)).toBeNull();
  });
  it("canonicalizes a DNS target and retains query and path", () => {
    expect(parseSurrogateForwardTarget("http://API.example.test:80/a?q=1")).toEqual({ host: "api.example.test", authority: "api.example.test:443", path: "/a?q=1" });
    expect(parseSurrogateForwardTarget("http://api.example.test?q=1")?.path).toBe("/?q=1");
  });
  it("reconciles Host without normalizing a foreign authority", () => {
    expect(reconcileSurrogateHost("api.example.test", "API.example.test:80")).toBe(true);
    expect(reconcileSurrogateHost("api.example.test", undefined)).toBe(true);
    for (const host of ["other.example.test", "api.example.test:443", ["api.example.test"]]) expect(reconcileSurrogateHost("api.example.test", host)).toBe(false);
  });
  it.each(["Host", "Authorization", "Proxy-Authorization", "Content-Length", "Connection", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Expect", "X-Api-Key"])("refuses duplicate %s before normalization", (name) => {
    expect(checkSurrogateRawHeaders([name, "a", name.toLowerCase(), "b"])).toBe("duplicate_header");
  });
  it("refuses transfer coding and protocol upgrade", () => {
    expect(checkSurrogateRawHeaders(["Transfer-Encoding", "chunked"])).toBe("transfer_encoding");
    expect(checkSurrogateRawHeaders(["Upgrade", "websocket"])).toBe("upgrade");
  });
  it("bounds retained occurrences and preserves original offsets", () => {
    const p = mintSurrogatePlaceholder();
    expect(scanSurrogateRequest("/", { authorization: `Bearer ${p}` })?.[0]).toMatchObject({ start: 7, header: "authorization", location: "header:authorization" });
    expect(scanSurrogateRequest(p, { "x-other": [p, p] })).toHaveLength(3);
    expect(scanSurrogateRequest("/", { authorization: Array(MAX_PLACEHOLDERS_PER_REQUEST + 1).fill(p).join(" ") })).toBeNull();
  });
  it("rebuilds framing and pins identity encoding on a swap", () => {
    const headers = buildSurrogateUpstreamHeaders({ host: "foreign", "content-length": "0003", connection: "x-drop", "x-drop": "hidden", "proxy-authorization": "hidden", expect: "100-continue", "accept-encoding": "gzip", authorization: "kept" }, "api.example.test", 3, true);
    expect(headers).toEqual({ host: "api.example.test", connection: "close", "content-length": 3, "accept-encoding": "identity", authorization: "kept" });
    expect(surrogateContentLength({ "content-length": "0003" })).toBe(3);
    expect(surrogateContentLength({})).toBe(0);
    for (const length of ["-1", "2e3", "9007199254740992", "1,1"]) expect(surrogateContentLength({ "content-length": length })).toBeNull();
  });
  it("maps every helper denial and client failure by the coordinator clarification", () => {
    expect(Object.fromEntries(["unknown", "misroute", "wrong_location", "limit"].map(k => [k, SURROGATE_STATUS[k as keyof typeof SURROGATE_STATUS][0]]))).toEqual({ unknown: 403, misroute: 403, wrong_location: 403, limit: 403 });
    for (const reason of ["locked", "expired", "rate_limited", "malformed", "helper_timeout", "helper_malformed", "helper_id_mismatch", "helper_connect_failed"] as const) expect(SURROGATE_STATUS[reason][0]).toBe(503);
    expect(SURROGATE_STATUS.expired[1]).toBe("surrogate-locked");
  });
});
