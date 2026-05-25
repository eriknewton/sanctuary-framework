/**
 * Collision-bound tests for the keychain service name suffix.
 *
 * Full-sweep finding #62: the original 12-hex-char suffix (48 bits) had a
 * birthday bound of ~2^24 paths before 50% collision probability. Bumped
 * to 16-hex-chars (64 bits) for a birthday bound of ~2^32.
 *
 * This test generates plausible storage paths and asserts no prefix
 * collisions on the 16-hex suffix, and documents the strengthening over
 * the legacy 12-hex suffix.
 */

import { describe, it, expect } from "vitest";
import {
  keychainServiceFor,
  legacyKeychainServiceFor,
} from "../../src/wrap/passphrase.js";

describe("keychainServiceFor -- collision bound (#62)", () => {
  const home = "/home/test";

  it("produces 16-hex-char suffixes for non-default paths", () => {
    const name = keychainServiceFor("/srv/agent-x", home);
    expect(name).toMatch(/^sanctuary-passphrase-[0-9a-f]{16}$/);
  });

  it("legacy function produces 12-hex-char suffixes", () => {
    const name = legacyKeychainServiceFor("/srv/agent-x", home);
    expect(name).toMatch(/^sanctuary-passphrase-[0-9a-f]{12}$/);
  });

  it("no collisions among 1000 plausible storage paths (16-hex)", () => {
    const paths: string[] = [];
    for (let i = 0; i < 1000; i++) {
      paths.push(`/srv/sanctuary-tenant-${i.toString().padStart(4, "0")}`);
    }
    const names = paths.map((p) => keychainServiceFor(p, home));
    const unique = new Set(names);
    expect(unique.size).toBe(1000);
  });

  it("no collisions among 1000 plausible storage paths (legacy 12-hex, for comparison)", () => {
    const paths: string[] = [];
    for (let i = 0; i < 1000; i++) {
      paths.push(`/srv/sanctuary-tenant-${i.toString().padStart(4, "0")}`);
    }
    const names = paths.map((p) => legacyKeychainServiceFor(p, home));
    const unique = new Set(names);
    expect(unique.size).toBe(1000);
  });

  it("16-hex suffix is a prefix-extension of the legacy 12-hex suffix", () => {
    // The first 12 chars of the new suffix match the legacy suffix, because
    // both hash the same canonical path; only the slice length differs.
    const path = "/srv/agent-verify";
    const newName = keychainServiceFor(path, home);
    const legacyName = legacyKeychainServiceFor(path, home);
    const newSuffix = newName.replace("sanctuary-passphrase-", "");
    const legacySuffix = legacyName.replace("sanctuary-passphrase-", "");
    expect(newSuffix.slice(0, 12)).toBe(legacySuffix);
    expect(newSuffix.length).toBe(16);
    expect(legacySuffix.length).toBe(12);
  });
});
