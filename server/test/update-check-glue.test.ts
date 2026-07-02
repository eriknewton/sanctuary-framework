/**
 * Call-site glue tests for the update-check entry points.
 *
 * The seam functions (formatUpdateMessage, detectWrappedInstall,
 * extractNewerRegistryVersion) are covered directly in update-check.test.ts;
 * this suite drives `checkForUpdate` and `checkForSignedUpdate` END TO END so
 * the wiring between them is pinned: each call site must await
 * `detectWrappedInstall()` and pass the result as the third argument to
 * `formatUpdateMessage`. Reverting either call site to the two-argument form
 * (which silently reintroduces the wrapped-install bare-npx defect) fails the
 * wrapped-install tests here.
 *
 * Test doubles, scoped deliberately:
 * - `node:https` is mocked so no test touches the network; responses are
 *   dispatched by URL (npm registry vs GitHub Releases API vs manifest asset).
 * - `verifyReleaseManifest` is mocked to accept, ONLY because the production
 *   pinned-key path cannot verify a test-signed manifest (the release-signing
 *   private key is not, and must never be, available to tests). The verifier
 *   itself keeps its own adversarial suites (release-manifest.test.ts,
 *   sign-release-manifest.test.ts); nothing here weakens them. Everything
 *   else on the signed path (fetch, asset selection, version comparison,
 *   wrapped-install detection, message formatting) runs real code.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { httpsGetMock } = vi.hoisted(() => ({ httpsGetMock: vi.fn() }));

vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  return { ...actual, get: httpsGetMock };
});

vi.mock("../src/release-manifest.js", async (importOriginal) => {
  const actual = await importOriginal<
    typeof import("../src/release-manifest.js")
  >();
  return {
    ...actual,
    verifyReleaseManifest: vi.fn(() => ({
      ok: true as const,
      body: { version: "9.9.9", artifact_hashes: {} },
    })),
  };
});

import { checkForUpdate, checkForSignedUpdate } from "../src/update-check.js";

/** Minimal IncomingMessage stand-in satisfying what the fetch paths touch. */
function respond(status: number, body: string): EventEmitter {
  const res = Object.assign(new EventEmitter(), {
    statusCode: status,
    headers: {} as Record<string, string>,
    setEncoding: () => {},
    resume: () => {},
    destroy: () => {},
  });
  // Emit after the callback has attached its data/end handlers.
  queueMicrotask(() => {
    res.emit("data", body);
    res.emit("end");
  });
  return res;
}

/** Minimal ClientRequest stand-in (error/timeout listeners, destroy). */
function fakeRequest(): EventEmitter {
  return Object.assign(new EventEmitter(), { destroy: () => {} });
}

/** Route mocked https GETs by URL: registry, GitHub API, manifest asset. */
function installHttpsFixture(): void {
  httpsGetMock.mockImplementation(
    (url: unknown, _options: unknown, cb: unknown) => {
      const u = String(url);
      let body: string;
      if (u.includes("registry.npmjs.org")) {
        body = JSON.stringify({ version: "9.9.9" });
      } else if (u.includes("api.github.com")) {
        body = JSON.stringify({
          assets: [
            {
              name: "release-manifest.json",
              browser_download_url:
                "https://github.com/eriknewton/sanctuary-framework/releases/download/v9.9.9/release-manifest.json",
            },
          ],
        });
      } else {
        // The manifest asset body; content is irrelevant because
        // verifyReleaseManifest is mocked to accept (see header comment).
        body = JSON.stringify({ body: { version: "9.9.9" }, signature: "x" });
      }
      (cb as (res: EventEmitter) => void)(respond(200, body));
      return fakeRequest();
    },
  );
}

describe("update-check call-site glue (wrapped flag wiring)", () => {
  let storageDir: string;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  const savedStorage = process.env.SANCTUARY_STORAGE_PATH;
  const savedNoCheck = process.env.SANCTUARY_NO_UPDATE_CHECK;

  beforeEach(async () => {
    storageDir = await mkdtemp(join(tmpdir(), "sanctuary-update-glue-"));
    process.env.SANCTUARY_STORAGE_PATH = storageDir;
    delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    installHttpsFixture();
  });

  afterEach(async () => {
    errorSpy.mockRestore();
    httpsGetMock.mockReset();
    if (savedStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = savedStorage;
    if (savedNoCheck === undefined) delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    else process.env.SANCTUARY_NO_UPDATE_CHECK = savedNoCheck;
    await rm(storageDir, { recursive: true, force: true });
  });

  async function markWrapped(): Promise<void> {
    await mkdir(join(storageDir, "backup"), { recursive: true });
    await writeFile(
      join(storageDir, "backup", "wrap-meta.json"),
      JSON.stringify({ backupPath: "/x", originalPath: "/y" }),
    );
  }

  /** The single advisory line the entry point printed to stderr. */
  function printedMessage(): string {
    expect(errorSpy).toHaveBeenCalledTimes(1);
    return String(errorSpy.mock.calls[0][0]);
  }

  it("checkForUpdate prints the wrapped (protect) advice for a wrapped install", async () => {
    await markWrapped();
    await checkForUpdate("1.0.0");
    const msg = printedMessage();
    expect(msg).toContain("npx @sanctuary-framework/mcp-server@9.9.9 protect");
    expect(msg).toContain("sanctuary protect");
  });

  it("checkForUpdate prints the bare npx advice for an unwrapped install", async () => {
    await checkForUpdate("1.0.0");
    const msg = printedMessage();
    expect(msg).toContain("Run: npx @sanctuary-framework/mcp-server@9.9.9");
    expect(msg).not.toContain("protect");
  });

  it("checkForSignedUpdate prints the wrapped (protect) advice for a wrapped install", async () => {
    await markWrapped();
    await checkForSignedUpdate("1.0.0");
    const msg = printedMessage();
    expect(msg).toContain("npx @sanctuary-framework/mcp-server@9.9.9 protect");
    expect(msg).toContain("sanctuary protect");
  });

  it("checkForSignedUpdate prints the bare npx advice for an unwrapped install", async () => {
    await checkForSignedUpdate("1.0.0");
    const msg = printedMessage();
    expect(msg).toContain("Run: npx @sanctuary-framework/mcp-server@9.9.9");
    expect(msg).not.toContain("protect");
  });
});
