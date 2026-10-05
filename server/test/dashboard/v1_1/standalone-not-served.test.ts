/**
 * v1.1 dashboard standalone-mode optional panel rendering.
 *
 * Optional panel reads that the standalone dashboard positively marks
 * as unavailable must render as unavailable in that mode, while unrelated
 * missing routes keep the honest read-failure surface.
 */

import { describe, expect, it } from "vitest";
import * as clientSignal from "../../../src/dashboard/v1_1/client.js";
import {
  DASHBOARD_MODE_NOT_SERVED_ERROR,
  DASHBOARD_MODE_NOT_SERVED_MESSAGE,
  DASHBOARD_MODE_NOT_SERVED_STATUS,
  dashboardModeNotServedBody,
} from "../../../src/dashboard/standalone-mode-signal.js";

function liftReadRenderer(): {
  readAndRender: (
    path: string,
    response: { status: number; body: unknown },
  ) => Promise<string>;
} {
  const src = clientSignal.getClientScript();
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
  it("keeps the client pinned signal tuple in parity with the server writer", () => {
    expect(clientSignal.DASHBOARD_CLIENT_MODE_NOT_SERVED_STATUS).toBe(
      DASHBOARD_MODE_NOT_SERVED_STATUS,
    );
    expect(clientSignal.DASHBOARD_CLIENT_MODE_NOT_SERVED_ERROR).toBe(
      DASHBOARD_MODE_NOT_SERVED_ERROR,
    );
    expect(clientSignal.DASHBOARD_CLIENT_MODE_NOT_SERVED_MODE).toBe(
      dashboardModeNotServedBody("standalone").mode,
    );
    expect(clientSignal.DASHBOARD_CLIENT_MODE_NOT_SERVED_MESSAGE).toBe(
      DASHBOARD_MODE_NOT_SERVED_MESSAGE,
    );
  });

  it("renders the typed standalone-mode signal without Retry", async () => {
    const { readAndRender } = liftReadRenderer();

    const html = await readAndRender("/api/honeypot/tool-traps", {
      status: DASHBOARD_MODE_NOT_SERVED_STATUS,
      body: dashboardModeNotServedBody("standalone"),
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

  it.each([
    [
      "non-503 status",
      {
        status: 500,
        body: dashboardModeNotServedBody("standalone"),
      },
      "Read failed (HTTP 500).",
    ],
    [
      "missing typed field",
      {
        status: DASHBOARD_MODE_NOT_SERVED_STATUS,
        body: {
          error: DASHBOARD_MODE_NOT_SERVED_ERROR,
          mode: "standalone",
          unavailable: true,
          message: DASHBOARD_MODE_NOT_SERVED_MESSAGE,
        },
      },
      "Read failed (HTTP 503).",
    ],
    [
      "spoofed message",
      {
        status: DASHBOARD_MODE_NOT_SERVED_STATUS,
        body: {
          ...dashboardModeNotServedBody("standalone"),
          message: "0",
        },
      },
      "Read failed (HTTP 503).",
    ],
  ])("keeps %s on the existing read-failure surface", async (_name, response, expected) => {
    const { readAndRender } = liftReadRenderer();

    const html = await readAndRender("/api/honeypot/tool-traps", response);

    expect(html).toContain(`Tool honeypots: Unknown. ${expected}`);
    expect(html).toContain("Retry");
    expect(html).not.toContain("Tool honeypots: Not available in this dashboard mode.");
    expect(html).not.toContain("Tool honeypots: 0");
  });
});
