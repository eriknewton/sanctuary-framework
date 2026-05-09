/**
 * Regression tests for keychainServiceFor() canonical path comparison.
 *
 * Full-sweep finding #59: path equality was string-based, not canonical.
 * Two processes targeting the same canonical path (one with `~/.sanctuary`,
 * the other with `~/.sanctuary/./`) computed different service names,
 * surfacing as `Identities loaded: 0` failures that look like data loss
 * but are routing bugs.
 *
 * Fix: `path.resolve()` normalizes both paths before comparison and hashing.
 */

import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { keychainServiceFor } from "../../src/cocoon/passphrase.js";

describe("keychainServiceFor -- canonical path comparison (#59)", () => {
  const home = "/home/test";
  const defaultService = "sanctuary-passphrase";

  it("default path with trailing /. resolves to the legacy service name", () => {
    expect(keychainServiceFor(join(home, ".sanctuary", "."), home)).toBe(
      defaultService
    );
  });

  it("default path with redundant .. resolves to the legacy service name", () => {
    expect(
      keychainServiceFor(join(home, ".sanctuary", "..", ".sanctuary"), home)
    ).toBe(defaultService);
  });

  it("default path with trailing slash resolves to the legacy service name", () => {
    // path.resolve strips trailing slashes
    expect(keychainServiceFor(home + "/.sanctuary/", home)).toBe(
      defaultService
    );
  });

  it("default path with doubled separator resolves to the legacy service name", () => {
    expect(keychainServiceFor(home + "//.sanctuary", home)).toBe(
      defaultService
    );
  });

  it("all cosmetic variants of the same default path produce the legacy service name", () => {
    const variants = [
      join(home, ".sanctuary"),
      join(home, ".sanctuary", "."),
      join(home, ".sanctuary", "..") + "/.sanctuary",
      home + "/.sanctuary/",
      home + "/.sanctuary/./",
      home + "//.sanctuary",
    ];
    for (const v of variants) {
      expect(keychainServiceFor(v, home)).toBe(defaultService);
    }
  });

  it("cosmetic variants of a custom path produce the same service name", () => {
    const base = "/srv/agent-a";
    const variants = [
      base,
      base + "/.",
      base + "/",
      base + "//",
      "/srv/./agent-a",
      "/srv/../srv/agent-a",
    ];
    const names = variants.map((v) => keychainServiceFor(v, home));
    const unique = new Set(names);
    expect(unique.size).toBe(1);
    // And it should not be the default service
    expect(names[0]).not.toBe(defaultService);
  });

  it("backward compatibility: the plain default path still returns the legacy name", () => {
    expect(keychainServiceFor(join(home, ".sanctuary"), home)).toBe(
      defaultService
    );
  });
});
