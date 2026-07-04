/**
 * Tests for the startup update check module.
 *
 * Tests version comparison logic and message formatting.
 * Network-dependent tests (fetchLatestVersion) are not included
 * to avoid flaky CI from registry availability.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  isNewerVersion,
  formatUpdateMessage,
  outboundUpdateChecksEnabled,
  checkForUpdate,
  checkForSignedUpdate,
} from "../src/update-check.js";

// node:https / node:http ESM namespaces are not configurable, so `get`
// cannot be vi.spyOn'd directly on the real module (Vitest throws "Module
// namespace is not configurable in ESM"). Mock both modules with spy
// wrappers instead so the "no outbound call" assertions below can observe
// whether the update-check gate ever reaches the transport layer. `vi.mock`
// factories are hoisted above imports, so the spies must be created via
// `vi.hoisted` rather than a plain top-level const.
const { httpsGetSpy, httpGetSpy } = vi.hoisted(() => ({
  httpsGetSpy: vi.fn(),
  httpGetSpy: vi.fn(),
}));
vi.mock("node:https", () => ({ get: httpsGetSpy }));
vi.mock("node:http", () => ({ get: httpGetSpy }));

describe("outboundUpdateChecksEnabled", () => {
  it("returns false when neither env var is set (zero-outbound default)", () => {
    expect(outboundUpdateChecksEnabled({})).toBe(false);
  });

  it("returns true when SANCTUARY_UPDATE_CHECK=1 is the only var set", () => {
    expect(outboundUpdateChecksEnabled({ SANCTUARY_UPDATE_CHECK: "1" })).toBe(
      true,
    );
  });

  it("returns false when both vars are set (the back-compat alias wins)", () => {
    expect(
      outboundUpdateChecksEnabled({
        SANCTUARY_UPDATE_CHECK: "1",
        SANCTUARY_NO_UPDATE_CHECK: "1",
      }),
    ).toBe(false);
  });

  it("returns false when only SANCTUARY_NO_UPDATE_CHECK=1 is set", () => {
    expect(
      outboundUpdateChecksEnabled({ SANCTUARY_NO_UPDATE_CHECK: "1" }),
    ).toBe(false);
  });

  it("treats any other value as not opted in", () => {
    expect(outboundUpdateChecksEnabled({ SANCTUARY_UPDATE_CHECK: "true" })).toBe(
      false,
    );
    expect(
      outboundUpdateChecksEnabled({ SANCTUARY_NO_UPDATE_CHECK: "0" }),
    ).toBe(false);
  });
});

describe("checkForUpdate / checkForSignedUpdate gate (zero-outbound default)", () => {
  let savedNoUpdate: string | undefined;
  let savedUpdate: string | undefined;

  beforeEach(() => {
    savedNoUpdate = process.env.SANCTUARY_NO_UPDATE_CHECK;
    savedUpdate = process.env.SANCTUARY_UPDATE_CHECK;
    httpsGetSpy.mockClear();
    httpGetSpy.mockClear();
  });

  afterEach(() => {
    if (savedNoUpdate !== undefined)
      process.env.SANCTUARY_NO_UPDATE_CHECK = savedNoUpdate;
    else delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    if (savedUpdate !== undefined)
      process.env.SANCTUARY_UPDATE_CHECK = savedUpdate;
    else delete process.env.SANCTUARY_UPDATE_CHECK;
  });

  it("checkForUpdate makes no outbound call when neither env var is set", async () => {
    delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    delete process.env.SANCTUARY_UPDATE_CHECK;
    await checkForUpdate("1.0.0");
    expect(httpsGetSpy).not.toHaveBeenCalled();
    expect(httpGetSpy).not.toHaveBeenCalled();
  });

  it("checkForSignedUpdate makes no outbound call when neither env var is set", async () => {
    delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    delete process.env.SANCTUARY_UPDATE_CHECK;
    await checkForSignedUpdate("1.0.0");
    expect(httpsGetSpy).not.toHaveBeenCalled();
    expect(httpGetSpy).not.toHaveBeenCalled();
  });

  it("checkForUpdate makes no outbound call when only the back-compat alias is set", async () => {
    process.env.SANCTUARY_NO_UPDATE_CHECK = "1";
    delete process.env.SANCTUARY_UPDATE_CHECK;
    await checkForUpdate("1.0.0");
    expect(httpsGetSpy).not.toHaveBeenCalled();
    expect(httpGetSpy).not.toHaveBeenCalled();
  });
});

describe("update-check", () => {
  describe("isNewerVersion", () => {
    it("detects newer major version", () => {
      expect(isNewerVersion("0.3.1", "1.0.0")).toBe(true);
    });

    it("detects newer minor version", () => {
      expect(isNewerVersion("0.3.1", "0.4.0")).toBe(true);
    });

    it("detects newer patch version", () => {
      expect(isNewerVersion("0.3.1", "0.3.2")).toBe(true);
    });

    it("returns false for same version", () => {
      expect(isNewerVersion("0.3.1", "0.3.1")).toBe(false);
    });

    it("returns false for older version", () => {
      expect(isNewerVersion("0.4.0", "0.3.1")).toBe(false);
    });

    it("returns false when current is newer major", () => {
      expect(isNewerVersion("1.0.0", "0.9.9")).toBe(false);
    });

    it("handles v prefix", () => {
      expect(isNewerVersion("v0.3.1", "v0.4.0")).toBe(true);
    });

    it("handles mixed v prefix", () => {
      expect(isNewerVersion("0.3.1", "v0.4.0")).toBe(true);
      expect(isNewerVersion("v0.3.1", "0.4.0")).toBe(true);
    });
  });

  describe("formatUpdateMessage", () => {
    it("includes current and latest versions", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("0.3.1");
      expect(msg).toContain("0.4.0");
    });

    it("includes an update command pinned to the announced version", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("npx @sanctuary-framework/mcp-server@0.4.0");
      expect(msg).not.toContain("@latest");
    });

    it("uses [Sanctuary] prefix", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toMatch(/^\[Sanctuary\]/);
    });

    it("is a single line", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).not.toContain("\n");
    });
  });
});
