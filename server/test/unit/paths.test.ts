/**
 * paths.ts unit tests — multi-tenancy config resolution helpers.
 *
 * These cover every precedence rule in `resolveStoragePath` and
 * `resolveDashboardPort` so two Sanctuary instances on one host can pick
 * deterministic, non-colliding locations.
 */

import { describe, it, expect } from "vitest";
import { join } from "node:path";
import {
  resolveStoragePath,
  resolveDashboardPort,
  DEFAULT_DASHBOARD_PORT,
  DEFAULT_STORAGE_DIR,
} from "../../src/paths.js";

describe("resolveStoragePath", () => {
  const fakeHome = "/home/test";

  it("returns <home>/.sanctuary when SANCTUARY_STORAGE_PATH is unset", () => {
    expect(resolveStoragePath({}, fakeHome)).toBe(
      join(fakeHome, DEFAULT_STORAGE_DIR)
    );
  });

  it("honours SANCTUARY_STORAGE_PATH when set", () => {
    expect(
      resolveStoragePath({ SANCTUARY_STORAGE_PATH: "/srv/agent-a" }, fakeHome)
    ).toBe("/srv/agent-a");
  });

  it("falls back to default when SANCTUARY_STORAGE_PATH is an empty string", () => {
    // Empty string has no useful meaning — treat it as unset.
    expect(
      resolveStoragePath({ SANCTUARY_STORAGE_PATH: "" }, fakeHome)
    ).toBe(join(fakeHome, DEFAULT_STORAGE_DIR));
  });

  it("returns distinct paths for two tenants with distinct env values", () => {
    const a = resolveStoragePath(
      { SANCTUARY_STORAGE_PATH: "/srv/agent-a" },
      fakeHome
    );
    const b = resolveStoragePath(
      { SANCTUARY_STORAGE_PATH: "/srv/agent-b" },
      fakeHome
    );
    expect(a).not.toBe(b);
  });
});

describe("resolveDashboardPort", () => {
  it("returns the default when nothing is set", () => {
    expect(resolveDashboardPort(undefined, {})).toBe(DEFAULT_DASHBOARD_PORT);
  });

  it("honours an explicit port argument (--port CLI flag path)", () => {
    expect(resolveDashboardPort(9000, {})).toBe(9000);
    // Env var must NOT override an explicit CLI flag.
    expect(
      resolveDashboardPort(9000, { SANCTUARY_DASHBOARD_PORT: "3511" })
    ).toBe(9000);
  });

  it("honours SANCTUARY_DASHBOARD_PORT when no explicit port is given", () => {
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "3502" })
    ).toBe(3502);
  });

  it("falls back to the default when SANCTUARY_DASHBOARD_PORT is unparseable", () => {
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "not-a-port" })
    ).toBe(DEFAULT_DASHBOARD_PORT);
  });

  it("does NOT silently truncate a non-integer port (80abc -> 80 hole closed)", () => {
    // Old lenient parseInt("80abc", 10) returned 80, binding the dashboard to
    // a port the operator never typed. Strict parse rejects it and falls back
    // to the default rather than binding the truncated port.
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "80abc" })
    ).toBe(DEFAULT_DASHBOARD_PORT);
  });

  it("rejects an out-of-range port and falls back to the default", () => {
    // 70000 is above the 65535 TCP ceiling; the old reader returned it
    // unchecked. Strict range guard rejects it.
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "70000" })
    ).toBe(DEFAULT_DASHBOARD_PORT);
    // 0 and negative values are not valid TCP ports either.
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "0" })
    ).toBe(DEFAULT_DASHBOARD_PORT);
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "-1" })
    ).toBe(DEFAULT_DASHBOARD_PORT);
  });

  it("accepts a clean in-range port at the boundaries", () => {
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "1" })
    ).toBe(1);
    expect(
      resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "65535" })
    ).toBe(65535);
  });

  it("returns distinct ports for two tenants with distinct env values", () => {
    const a = resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "3501" });
    const b = resolveDashboardPort(undefined, { SANCTUARY_DASHBOARD_PORT: "3502" });
    expect(a).not.toBe(b);
  });
});
