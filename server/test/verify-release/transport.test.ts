/**
 * The verify-release transport under a fault schedule: per-resource URLs and
 * redirect edges, byte caps, Content-Length, the stall timeout and the run
 * deadline, late completions, and repeated use. Every request goes to an
 * injected requester; time is a manual clock.
 */
import { syncBuiltinESMExports } from "node:module";
import { describe, expect, it } from "vitest";
import { MAX_ATTESTATIONS_BYTES, MAX_MANIFEST_BYTES, MAX_TARBALL_BYTES, MAX_VERSION_DOCUMENT_BYTES, RUN_DEADLINE_MS, STALL_TIMEOUT_MS } from "../../src/verify-release/constants.js";
import { Deadline } from "../../src/verify-release/deadline.js";
import { fetchResource, httpsRequester, resourcePolicies, type RawResponse } from "../../src/verify-release/transport.js";
import type { FetchResource } from "../../src/verify-release/reasons.js";
import { ManualClock, denyAllNetwork, modelledRequester, response } from "./helpers.js";

const network = denyAllNetwork();

const VERSION = "1.8.4";
const POLICIES = resourcePolicies(VERSION);
const MANIFEST_URL = POLICIES.manifest.url;
const ASSET = "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sig=abc&x=1";
const RESOURCES: FetchResource[] = ["version-document", "attestations", "tarball", "manifest"];
const CAPS: Record<FetchResource, number> = {
  "version-document": MAX_VERSION_DOCUMENT_BYTES, attestations: MAX_ATTESTATIONS_BYTES, tarball: MAX_TARBALL_BYTES, manifest: MAX_MANIFEST_BYTES,
};

function run(resource: FetchResource, requester: Parameters<typeof fetchResource>[1], clock = new ManualClock()) {
  const deadline = new Deadline(clock, RUN_DEADLINE_MS);
  return fetchResource(POLICIES[resource], requester, deadline).finally(() => deadline.dispose());
}

/** A body that records destroy() and yields the given chunks. */
function trackedBody(chunks: Buffer[], between?: () => void): RawResponse["body"] & { destroyed: boolean } {
  const tracked = {
    destroyed: false,
    destroy() { tracked.destroyed = true; },
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) {
        between?.();
        await Promise.resolve();
        yield chunk;
      }
    },
  };
  return tracked;
}

describe("fixed URLs", () => {
  it("composes the four version-specific URLs", () => {
    expect(Object.fromEntries(RESOURCES.map(r => [r, POLICIES[r].url]))).toEqual({
      "version-document": "https://registry.npmjs.org/@sanctuary-framework/mcp-server/1.8.4",
      attestations: "https://registry.npmjs.org/-/npm/v1/attestations/@sanctuary-framework%2fmcp-server@1.8.4",
      tarball: "https://registry.npmjs.org/@sanctuary-framework/mcp-server/-/mcp-server-1.8.4.tgz",
      manifest: "https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/release-manifest.json",
    });
  });

  it.each(RESOURCES)("%s: a 200 body is returned, with or without Content-Length", async resource => {
    const url = POLICIES[resource].url;
    expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc", { "content-length": "3" }) }))).toEqual({ ok: true, evidence: Buffer.from("abc") });
    expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc") }))).toEqual({ ok: true, evidence: Buffer.from("abc") });
  });
});

describe.each(RESOURCES)("faults at %s", resource => {
  const url = POLICIES[resource].url;
  it("a non-200 status refuses fetch-failed", async () => {
    expect(await run(resource, modelledRequester({ [url]: () => response(500) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
    expect(await run(resource, modelledRequester({ [url]: () => response(204) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
  });
  it("a requester error refuses fetch-failed", async () => {
    expect(await run(resource, async () => { throw new Error("ECONNRESET"); })).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
  });
  it("a body that errors midway refuses fetch-failed and destroys the body", async () => {
    const tracked = trackedBody([]);
    tracked[Symbol.asyncIterator] = async function* () { yield Buffer.from("a"); throw new Error("reset"); };
    expect(await run(resource, async () => ({ status: 200, headers: {}, body: tracked }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
    expect(tracked.destroyed).toBe(true);
  });
  it("a Content-Length over the cap refuses fetch-oversize before reading", async () => {
    const tracked = trackedBody([Buffer.from("x")]);
    expect(await run(resource, async () => ({ status: 200, headers: { "content-length": String(CAPS[resource] + 1) }, body: tracked }))).toEqual({ ok: false, reason: `fetch-oversize:${resource}` });
    expect(tracked.destroyed).toBe(true);
  });
  it("a body over the cap with no Content-Length refuses fetch-oversize", async () => {
    const tracked = trackedBody([Buffer.alloc(CAPS[resource]), Buffer.alloc(1)]);
    expect(await run(resource, async () => ({ status: 200, headers: {}, body: tracked }))).toEqual({ ok: false, reason: `fetch-oversize:${resource}` });
    expect(tracked.destroyed).toBe(true);
  });
  it("a body exactly at the cap passes", async () => {
    const result = await run(resource, async () => ({ status: 200, headers: {}, body: trackedBody([Buffer.alloc(CAPS[resource])]) }));
    expect(result.ok).toBe(true);
  });
  it("a Content-Length that differs from the body refuses fetch-failed", async () => {
    expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc", { "content-length": "4" }) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
    expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc", { "content-length": "2" }) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
  });
  it("a Content-Length that is not a decimal integer refuses fetch-failed", async () => {
    expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc", { "content-length": "3, 3" }) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
    // Forms Number() would read as 3: only plain decimal digits are a length.
    for (const length of ["+3", "3.0", " 3", "0x3"]) {
      expect(await run(resource, modelledRequester({ [url]: () => response(200, "abc", { "content-length": length }) })), length).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
    }
    expect(await run(resource, async () => ({ status: 200, headers: { "content-length": ["3", "3"] as unknown as string }, body: trackedBody([Buffer.from("abc")]) }))).toEqual({ ok: false, reason: `fetch-failed:${resource}` });
  });
});

describe("redirect policy", () => {
  it.each(["version-document", "attestations", "tarball"] as const)("%s: any 3xx refuses fetch-redirect-refused, even to the registry itself", async resource => {
    const url = POLICIES[resource].url;
    const requester = modelledRequester({ [url]: () => response(302, "", { location: url.replace("/1.8.4", "/1.8.5") }) });
    expect(await run(resource, requester)).toEqual({ ok: false, reason: `fetch-redirect-refused:${resource}` });
    expect(requester.calls).toEqual([url]);
  });

  it.each(["objects.githubusercontent.com", "release-assets.githubusercontent.com"])("manifest: one hop to %s passes and keeps the path and query", async host => {
    const target = `https://${host}/a/b?sig=1&x=y`;
    const requester = modelledRequester({ [MANIFEST_URL]: () => response(302, "", { location: target }), [target]: () => response(200, "{}") });
    expect(await run("manifest", requester)).toEqual({ ok: true, evidence: Buffer.from("{}") });
    expect(requester.calls).toEqual([MANIFEST_URL, target]);
  });

  it("manifest: a relative Location resolves against the hop's URL and then must pass the host rule", async () => {
    const requester = modelledRequester({ [MANIFEST_URL]: () => response(302, "", { location: "/elsewhere" }) });
    expect(await run("manifest", requester)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
  });

  it("manifest: three hops between asset hosts pass; a fourth refuses", async () => {
    const hop = (n: number) => `https://release-assets.githubusercontent.com/hop${n}`;
    const three = modelledRequester({
      [MANIFEST_URL]: () => response(302, "", { location: hop(1) }),
      [hop(1)]: () => response(301, "", { location: hop(2) }),
      [hop(2)]: () => response(307, "", { location: hop(3) }),
      [hop(3)]: () => response(200, "{}"),
    });
    expect((await run("manifest", three)).ok).toBe(true);
    const four = modelledRequester({
      [MANIFEST_URL]: () => response(302, "", { location: hop(1) }),
      [hop(1)]: () => response(302, "", { location: hop(2) }),
      [hop(2)]: () => response(302, "", { location: hop(3) }),
      [hop(3)]: () => response(302, "", { location: hop(4) }),
      [hop(4)]: () => response(200, "{}"),
    });
    expect(await run("manifest", four)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
    expect(four.calls).not.toContain(hop(4));
  });

  it("manifest: a loop refuses", async () => {
    const requester = modelledRequester({ [MANIFEST_URL]: () => response(302, "", { location: ASSET }), [ASSET]: () => response(302, "", { location: ASSET }) });
    expect(await run("manifest", requester)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
    // The loop is caught on the repeat, not by running out of hops.
    expect(requester.calls).toEqual([MANIFEST_URL, ASSET]);
  });

  it.each([
    ["a non-enumerated host", "https://evil.example/release-manifest.json"],
    ["a host that only ends with an enumerated name", "https://evilrelease-assets.githubusercontent.com/x"],
    ["an edge back to github.com", "https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/release-manifest.json?again=1"],
    ["an enumerated registry host through a forbidden transition", "https://registry.npmjs.org/@sanctuary-framework/mcp-server/1.8.4"],
    ["plain http", "http://release-assets.githubusercontent.com/x"],
    ["another port", "https://release-assets.githubusercontent.com:8443/x"],
    ["userinfo", "https://user:pw@release-assets.githubusercontent.com/x"],
    ["a malformed Location", "https://[::1"],
  ])("manifest: a redirect to %s refuses", async (_label, location) => {
    const requester = modelledRequester({ [MANIFEST_URL]: () => response(302, "", { location }) });
    expect(await run("manifest", requester)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
    expect(requester.calls).toEqual([MANIFEST_URL]);
  });

  it("manifest: a second hop back to github.com refuses", async () => {
    const requester = modelledRequester({ [MANIFEST_URL]: () => response(302, "", { location: ASSET }), [ASSET]: () => response(302, "", { location: MANIFEST_URL }) });
    expect(await run("manifest", requester)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
  });

  it("manifest: a redirect without Location, or with two, refuses", async () => {
    expect(await run("manifest", modelledRequester({ [MANIFEST_URL]: () => response(302) }))).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
    // Two Location values are refused outright, even when joining them would name an allowed host that answers.
    let calls = 0;
    const two = async () => (++calls === 1
      ? { status: 302, headers: { location: [ASSET, ASSET] as unknown as string }, body: trackedBody([]) }
      : response(200, "{}"));
    expect(await run("manifest", two)).toEqual({ ok: false, reason: "fetch-redirect-refused:manifest" });
    expect(calls).toBe(1);
  });

  it("the redirect response body is destroyed", async () => {
    const tracked = trackedBody([]);
    await run("manifest", async () => ({ status: 302, headers: { location: "https://evil.example/" }, body: tracked }));
    expect(tracked.destroyed).toBe(true);
  });
});

describe("time", () => {
  it("a stall of STALL_TIMEOUT_MS with no bytes refuses fetch-failed", async () => {
    const clock = new ManualClock();
    const tracked = trackedBody([]);
    tracked[Symbol.asyncIterator] = async function* () {
      yield Buffer.from("a");
      clock.advance(STALL_TIMEOUT_MS);
      await new Promise(() => undefined);
    };
    expect(await run("tarball", async () => ({ status: 200, headers: {}, body: tracked }), clock)).toEqual({ ok: false, reason: "fetch-failed:tarball" });
    expect(tracked.destroyed).toBe(true);
  });

  it("a slow trickle that never stalls but passes the run deadline refuses deadline-exceeded", async () => {
    const clock = new ManualClock();
    const step = STALL_TIMEOUT_MS - 1;
    const chunks = Array.from({ length: Math.ceil(RUN_DEADLINE_MS / step) + 2 }, () => Buffer.from("t"));
    const tracked = trackedBody(chunks, () => clock.advance(step));
    expect(await run("tarball", async () => ({ status: 200, headers: {}, body: tracked }), clock)).toEqual({ ok: false, reason: "deadline-exceeded" });
    expect(tracked.destroyed).toBe(true);
  });

  it("a response that arrives after the deadline is discarded and destroyed: timeout, then late success", async () => {
    const clock = new ManualClock();
    let deliver!: (r: RawResponse) => void;
    const pending = new Promise<RawResponse>(resolve => { deliver = resolve; });
    // Earlier resources used most of the run, so the deadline, not the stall timer, ends this request.
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    clock.advance(RUN_DEADLINE_MS - STALL_TIMEOUT_MS / 2);
    const result = fetchResource(POLICIES.tarball, () => pending, deadline);
    await Promise.resolve();
    clock.advance(STALL_TIMEOUT_MS / 2);
    expect(await result).toEqual({ ok: false, reason: "deadline-exceeded" });
    const late = trackedBody([Buffer.from("late")]);
    deliver({ status: 200, headers: {}, body: late });
    await new Promise(resolve => setImmediate(resolve));
    expect(late.destroyed).toBe(true);
  });

  it("a stall, then a late completion of the same request, stays refused and destroys the late body", async () => {
    const clock = new ManualClock();
    let deliver!: (r: RawResponse) => void;
    const pending = new Promise<RawResponse>(resolve => { deliver = resolve; });
    const result = run("manifest", () => pending, clock);
    await Promise.resolve();
    clock.advance(STALL_TIMEOUT_MS);
    expect(await result).toEqual({ ok: false, reason: "fetch-failed:manifest" });
    const late = trackedBody([Buffer.from("{}")]);
    deliver({ status: 200, headers: {}, body: late });
    await new Promise(resolve => setImmediate(resolve));
    expect(late.destroyed).toBe(true);
  });

  it("a body that completes after the deadline contributes nothing", async () => {
    const clock = new ManualClock();
    const tracked = trackedBody([Buffer.from("x")]);
    tracked[Symbol.asyncIterator] = async function* () { yield Buffer.from("x"); };
    // The clock jumps past the deadline between the last chunk and the end, with no timer able to fire first.
    const requester = async () => ({ status: 200, headers: {}, body: { ...tracked, async *[Symbol.asyncIterator]() { yield Buffer.from("x"); (clock as any).now = () => RUN_DEADLINE_MS + 1; } } });
    expect(await run("version-document", requester, clock)).toEqual({ ok: false, reason: "deadline-exceeded" });
  });

  it("an already expired deadline makes no request", async () => {
    const clock = new ManualClock();
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    clock.advance(RUN_DEADLINE_MS);
    const requester = modelledRequester({});
    expect(await fetchResource(POLICIES.tarball, requester, deadline)).toEqual({ ok: false, reason: "deadline-exceeded" });
    expect(requester.calls).toEqual([]);
  });

  it("repeated invocation in one process carries no state: a refused fetch does not affect the next", async () => {
    const url = POLICIES["version-document"].url;
    let calls = 0;
    const requester = modelledRequester({ [url]: () => (++calls === 1 ? response(500) : response(200, "ok")) });
    expect(await run("version-document", requester)).toEqual({ ok: false, reason: "fetch-failed:version-document" });
    expect(await run("version-document", requester)).toEqual({ ok: true, evidence: Buffer.from("ok") });
    const clock = new ManualClock();
    const expired = new Deadline(clock, RUN_DEADLINE_MS);
    clock.advance(RUN_DEADLINE_MS);
    expect(await fetchResource(POLICIES["version-document"], requester, expired)).toEqual({ ok: false, reason: "deadline-exceeded" });
    expect(await run("version-document", requester)).toEqual({ ok: true, evidence: Buffer.from("ok") });
  });
});

describe("production requester", () => {
  it("goes through https.request with no agent pool, no credentials and no redirect following", async () => {
    const https = (await import("node:https")).default;
    const seen: Array<{ url: string; options: Record<string, unknown> }> = [];
    const original = https.request;
    (https as any).request = (url: URL, options: Record<string, unknown>) => {
      seen.push({ url: url.href, options });
      const handlers: Record<string, (e: Error) => void> = {};
      queueMicrotask(() => handlers.error?.(new Error("not connected in tests")));
      return { on: (event: string, fn: (e: Error) => void) => { handlers[event] = fn; }, end: () => undefined };
    };
    syncBuiltinESMExports();
    try {
      await expect(httpsRequester(new URL(POLICIES.tarball.url), new AbortController().signal)).rejects.toThrow("not connected in tests");
    } finally {
      (https as any).request = original;
      syncBuiltinESMExports();
    }
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(POLICIES.tarball.url);
    expect(seen[0]!.options).toMatchObject({ method: "GET", agent: false });
    expect(Object.keys(seen[0]!.options.headers as object).sort()).toEqual(["accept", "user-agent"]);
    expect(network.attempts).toEqual([]);
  });
});
