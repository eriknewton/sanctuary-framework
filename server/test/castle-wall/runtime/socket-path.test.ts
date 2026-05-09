/**
 * Castle Wall socket-path resolver tests.
 *
 * The Swift mirror at
 * `castle-wall-macos/Sources/CastleWallIPC/SocketPath.swift` MUST resolve
 * to the same path strings given the same inputs. These tests are the
 * authoritative reference for the cross-language byte-equivalent path
 * fixture set.
 */

import { describe, it, expect } from "vitest";

import { resolveCastleWallSocketPath } from "../../../src/castle-wall/runtime/socket-path.js";

describe("castle-wall/runtime/socket-path : resolveCastleWallSocketPath", () => {
  it("returns explicit override regardless of platform", () => {
    const out = resolveCastleWallSocketPath({
      platform: "linux",
      fortressId: "abc123",
      explicitOverride: "/tmp/custom.sock",
    });
    expect(out.path).toBe("/tmp/custom.sock");
    expect(out.source).toBe("explicit_override");
  });

  it("uses Linux per-fortress runtime path when fortressId given", () => {
    const out = resolveCastleWallSocketPath({
      platform: "linux",
      fortressId: "abc123",
    });
    expect(out.path).toBe("/run/sanctuary/abc123/filter.sock");
    expect(out.source).toBe("linux_per_fortress");
  });

  it("falls back to default fortressId on Linux when none provided", () => {
    const out = resolveCastleWallSocketPath({ platform: "linux" });
    expect(out.path).toBe("/run/sanctuary/default/filter.sock");
    expect(out.source).toBe("linux_per_fortress");
  });

  it("uses per-fortress macOS path when SANCTUARY_FORTRESS_PATH set", () => {
    const out = resolveCastleWallSocketPath({
      platform: "darwin",
      fortressPath: "/Users/op/.sanctuary",
    });
    expect(out.path).toBe("/Users/op/.sanctuary/castle.sock");
    expect(out.source).toBe("macos_per_fortress");
  });

  it("strips trailing slash on macOS fortress path", () => {
    const out = resolveCastleWallSocketPath({
      platform: "darwin",
      fortressPath: "/Users/op/.sanctuary/",
    });
    expect(out.path).toBe("/Users/op/.sanctuary/castle.sock");
  });

  it("falls back to ~/.sanctuary/castle.sock on macOS when only homeDir is known", () => {
    const out = resolveCastleWallSocketPath({
      platform: "darwin",
      homeDir: "/Users/op",
    });
    expect(out.path).toBe("/Users/op/.sanctuary/castle.sock");
    expect(out.source).toBe("macos_home_default");
  });

  it("falls back to /var/run/sanctuary-castle.sock on macOS when no other input", () => {
    const out = resolveCastleWallSocketPath({ platform: "darwin" });
    expect(out.path).toBe("/var/run/sanctuary-castle.sock");
    expect(out.source).toBe("macos_root_daemon");
  });

  it("ignores empty-string overrides and falls through fallback chain", () => {
    const out = resolveCastleWallSocketPath({
      platform: "darwin",
      fortressPath: "",
      homeDir: "/Users/op",
    });
    expect(out.path).toBe("/Users/op/.sanctuary/castle.sock");
    expect(out.source).toBe("macos_home_default");
  });

  it("treats unknown platform like macOS for default-path fallback", () => {
    const out = resolveCastleWallSocketPath({
      platform: "freebsd",
      homeDir: "/home/op",
    });
    expect(out.path).toBe("/home/op/.sanctuary/castle.sock");
    expect(out.source).toBe("macos_home_default");
  });
});
