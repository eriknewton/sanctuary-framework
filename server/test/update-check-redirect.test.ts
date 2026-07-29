/**
 * Tests for bounded, allowlisted redirect-following in httpGetText (F1 fix).
 *
 * Why this matters: GitHub release assets (`browser_download_url` and the API
 * octet-stream route) return a 302 to `*.githubusercontent.com`. Without
 * redirect-following, `fetchLatestSignedManifest` would see `302 !== 200`,
 * resolve null, and the signed advisory would NEVER fire even after the real
 * key is pinned. This suite proves the follow mechanism works AND that the
 * production SSRF allowlist rejects non-GitHub hosts.
 *
 * The follow MECHANISM is exercised against local http servers using an
 * injected localhost-permitting policy; the production https-only + GitHub-host
 * allowlist is asserted separately so we prove both the mechanism and the
 * guard without needing TLS certs.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import {
  httpGetText,
  isAllowedRedirectHost,
  productionRedirectPolicy,
} from "../src/update-check.js";

/** Servers stood up during a test, torn down in afterEach. */
const servers: Server[] = [];

/** Start an http server on an ephemeral port; return its base URL. */
function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (s) => new Promise<void>((res) => s.close(() => res())),
    ),
  );
});

/** A policy that permits following redirects to any localhost http target. */
const localhostPolicy = (next: URL): boolean =>
  next.hostname === "127.0.0.1" || next.hostname === "localhost";

describe("httpGetText redirect-following (F1)", () => {
  it("follows a single 302 to a second endpoint and returns the body", async () => {
    // The destination server returns the JSON body.
    const destBase = await listen((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, from: "dest" }));
    });
    // The origin server 302-redirects to the destination.
    const originBase = await listen((_req, res) => {
      res.writeHead(302, { location: `${destBase}/asset` });
      res.end();
    });

    const body = await httpGetText(`${originBase}/latest`, 2, localhostPolicy);
    expect(body).not.toBeNull();
    expect(JSON.parse(body as string)).toEqual({ ok: true, from: "dest" });
  });

  it("returns null when redirects exceed the hop cap (loop protection)", async () => {
    // A server that always redirects to itself would loop; the hop cap stops it.
    let base = "";
    base = await listen((_req, res) => {
      res.writeHead(302, { location: `${base}/again` });
      res.end();
    });
    const body = await httpGetText(`${base}/start`, 2, localhostPolicy);
    expect(body).toBeNull();
  });

  it("returns null when a redirect target is rejected by the policy", async () => {
    // Origin redirects to a target the policy will reject (simulating a
    // non-allowlisted host). The default-shaped policy below rejects it.
    const originBase = await listen((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data" });
      res.end();
    });
    // A policy that permits ONLY 127.0.0.1 rejects the metadata-host redirect.
    const body = await httpGetText(`${originBase}/latest`, 2, localhostPolicy);
    expect(body).toBeNull();
  });

  it("policy-gates the INITIAL url, not only followed redirects", async () => {
    // A live server that WOULD return a body if reached. If the initial-url
    // SSRF gate is missing, this fetch succeeds; with the gate, a policy that
    // rejects this host makes hop 0 resolve null WITHOUT opening the socket.
    let reached = false;
    const base = await listen((_req, res) => {
      reached = true;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    // A policy that rejects EVERY host: the initial url must be refused.
    const rejectAll = (): boolean => false;
    const body = await httpGetText(`${base}/latest`, 2, rejectAll);
    expect(body).toBeNull();
    // The gate must short-circuit BEFORE any request is made.
    expect(reached).toBe(false);
  });

  it("returns null (never throws) on an unparsable initial url", async () => {
    // A malformed url must resolve null, not throw — httpGetText is contractually
    // non-throwing on every failure path, including a bad initial url.
    const body = await httpGetText("not a url", 2, localhostPolicy);
    expect(body).toBeNull();
  });
});

describe("production redirect policy: SSRF allowlist", () => {
  it("accepts exactly github.com, api.github.com, and *.githubusercontent.com", () => {
    expect(isAllowedRedirectHost("github.com")).toBe(true);
    expect(isAllowedRedirectHost("api.github.com")).toBe(true);
    expect(isAllowedRedirectHost("objects.githubusercontent.com")).toBe(true);
    expect(isAllowedRedirectHost("release-assets.githubusercontent.com")).toBe(
      true,
    );
    expect(isAllowedRedirectHost("githubusercontent.com")).toBe(true);
  });

  it("REJECTS non-GitHub hosts (SSRF guard holds)", () => {
    expect(isAllowedRedirectHost("evil.com")).toBe(false);
    expect(isAllowedRedirectHost("169.254.169.254")).toBe(false);
    expect(isAllowedRedirectHost("localhost")).toBe(false);
    expect(isAllowedRedirectHost("127.0.0.1")).toBe(false);
    // A lookalike that merely contains the allowed domain as a substring but is
    // not a real subdomain must be rejected.
    expect(isAllowedRedirectHost("githubusercontent.com.evil.com")).toBe(false);
    expect(isAllowedRedirectHost("notgithub.com")).toBe(false);
  });

  it("productionRedirectPolicy requires https AND an allowlisted host", () => {
    // Right host but wrong scheme -> rejected (no plaintext downgrade).
    expect(
      productionRedirectPolicy(new URL("http://objects.githubusercontent.com/x")),
    ).toBe(false);
    // https + allowlisted host -> accepted.
    expect(
      productionRedirectPolicy(
        new URL("https://objects.githubusercontent.com/x"),
      ),
    ).toBe(true);
    // https but non-allowlisted host -> rejected.
    expect(productionRedirectPolicy(new URL("https://evil.com/x"))).toBe(false);
  });

  it("default httpGetText refuses a non-GitHub INITIAL url before fetching", async () => {
    // fetchLatestSignedManifest hands httpGetText an asset browser_download_url
    // read from the untrusted release JSON body. With the DEFAULT (production)
    // policy, an initial url whose host is not an allowlisted GitHub host must
    // resolve null WITHOUT opening a socket. The local server here would answer
    // 200 if reached, so `reached === false` proves the hop-0 SSRF gate holds.
    let reached = false;
    const base = await listen((_req, res) => {
      reached = true;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    // No policy arg -> productionRedirectPolicy (https-only + GitHub allowlist).
    // The base url here is http://127.0.0.1 -> rejected on BOTH scheme and host.
    const body = await httpGetText(`${base}/release-manifest.json`);
    expect(body).toBeNull();
    expect(reached).toBe(false);
  });
});
