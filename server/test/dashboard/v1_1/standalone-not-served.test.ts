/**
 * v1.1 dashboard standalone-mode optional panel rendering.
 *
 * Optional panel reads that the standalone dashboard positively marks
 * as unavailable must render as unavailable in that mode, while unrelated
 * missing routes keep the honest read-failure surface.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

function liftReadRenderer(): {
  readAndRender: (
    path: string,
    response: { status: number; body: unknown },
  ) => Promise<string>;
} {
  const src = getClientScript();
  const end = src.indexOf('document.addEventListener("click"');
  let chunk = src.slice(0, end);
  chunk = chunk.replace(/const\s+state\s*=/, "var state =");
  const wrapper = `
    var document = {
      activeElement: null,
      documentElement: { setAttribute: function () {}, removeAttribute: function () {} },
      addEventListener: function () {},
      getElementById: function () { return null; },
      querySelectorAll: function () { return []; }
    };
    var window = { matchMedia: function () { return null; } };
    var sessionStorage = { getItem: function () { return null; }, setItem: function () {} };
    var location = { hash: "", host: "test", origin: "http://test", search: "" };
    var navigator = {};
    var Element = function () {};
    var HTMLInputElement = function () {};
    var fetch = function () { return fetchImpl(); };
    ${chunk}
    rerender = function () {};
    return {
      readAndRender: async function (path, response) {
        fetchImpl = async function () {
          return new Response(JSON.stringify(response.body), {
            status: response.status,
            headers: { "Content-Type": "application/json" }
          });
        };
        try { await readResponse(path, { cache: "no-store" }, DASHBOARD_READ_DEADLINE_MS); }
        catch (_e) {}
        return renderSourceRead(path);
      }
    };
  `;
  let fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true, data: {} }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  // eslint-disable-next-line no-new-func
  const factory = new Function("Response", "fetchImpl", wrapper) as (
    responseCtor: typeof Response,
    fetcher: typeof fetchImpl,
  ) => ReturnType<typeof liftReadRenderer>;
  return factory(Response, fetchImpl);
}

describe("v1.1 dashboard standalone-mode panel signal", () => {
  it("renders the typed standalone-mode signal without Retry", async () => {
    const { readAndRender } = liftReadRenderer();

    const html = await readAndRender("/api/honeypot/tool-traps", {
      status: 503,
      body: {
        ok: false,
        error: "dashboard_mode_not_served",
        mode: "standalone",
        unavailable: true,
        message: "Not available in this dashboard mode.",
      },
    });

    expect(html).toContain("Tool honeypots: Not available in this dashboard mode.");
    expect(html).not.toContain("Retry");
    expect(html).not.toContain("Read failed");
  });

  it("keeps bare 404s on the existing read-failure surface", async () => {
    const { readAndRender } = liftReadRenderer();

    const html = await readAndRender("/api/honeypot/tool-traps", {
      status: 404,
      body: { error: "not_found" },
    });

    expect(html).toContain("Tool honeypots: Unknown. Read failed (HTTP 404).");
    expect(html).toContain("Retry");
  });
});
