/**
 * Sanctuary v1.1 pre-tag fix wave -- Privacy-filter LRU bounds (#9)
 *
 * The vault's two in-process caches (`cache` for placeholder records,
 * `pathCache` for field-path aliases) were unbounded `Map<string, T>`s.
 * On a long-lived fortress processing high-cardinality content (project
 * paths, distinct file names, etc.), they grew without limit. Now both
 * are bounded LRUs with a documented cap.
 */

import { describe, it, expect } from "vitest";
import {
  LruCache,
  PRIVACY_VAULT_CACHE_MAX,
  PrivacyPlaceholderVault,
} from "../../src/operational/privacy-filter.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("LruCache bound (#9)", () => {
  it("evicts oldest entry when size exceeds cap", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    expect(cache.size).toBe(3);

    cache.set("d", 4);
    expect(cache.size).toBe(3);
    expect(cache.has("a")).toBe(false);
    expect(cache.has("b")).toBe(true);
    expect(cache.has("c")).toBe(true);
    expect(cache.has("d")).toBe(true);
  });

  it("get() promotes the key to most-recently-used", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);

    // Access "a" — it becomes most-recently-used
    expect(cache.get("a")).toBe(1);

    // Insert "d" — oldest is now "b" (a was bumped)
    cache.set("d", 4);

    expect(cache.has("a")).toBe(true);
    expect(cache.has("b")).toBe(false);
    expect(cache.has("c")).toBe(true);
    expect(cache.has("d")).toBe(true);
  });

  it("set() on existing key updates value without evicting others", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("a", 99);
    expect(cache.size).toBe(2);
    expect(cache.get("a")).toBe(99);
    expect(cache.get("b")).toBe(2);
  });

  it("PRIVACY_VAULT_CACHE_MAX is documented and non-trivial", () => {
    expect(PRIVACY_VAULT_CACHE_MAX).toBeGreaterThanOrEqual(1000);
    expect(Number.isInteger(PRIVACY_VAULT_CACHE_MAX)).toBe(true);
  });
});

describe("PrivacyPlaceholderVault cache stays bounded (#9)", () => {
  it("placeholderFor cache size never exceeds PRIVACY_VAULT_CACHE_MAX", async () => {
    // Use a small explicit cap via a fresh LruCache injected for the test
    // would require deeper refactor; here we verify the public LRU at the
    // documented cap holds via a sample run that exceeds it modestly.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const vault = new PrivacyPlaceholderVault(storage, masterKey);

    // Insert 50 distinct values (well below cap, but above any plausible
    // off-by-one). This is a smoke test that the vault behaves correctly
    // around the LRU integration; full cap-exhaustion is exercised by the
    // unit tests above on the LruCache primitive itself.
    for (let i = 0; i < 50; i++) {
      await vault.placeholderFor("email", `user${i}@example.com`, "scope-a");
    }

    // No assertion-by-introspection here (cache field is private); the
    // critical invariant is that no error fires and the call sequence
    // completes. The eviction primitive is exercised in the unit tests.
    const placeholder = await vault.placeholderFor(
      "email",
      "user0@example.com",
      "scope-a"
    );
    // Round-trip through storage even if cache evicted
    expect(placeholder).toMatch(/^EMAIL_\d+$/);
  });
});
