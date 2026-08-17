/**
 * Full-set parity between `ReadOnlyStorageGuard` and the storage interface it
 * decorates.
 *
 * AGENTS rule 5: a hand-mirrored registry drifts, and a parity test that
 * asserts "the first entry matches" cannot detect a MISSING entry. So this
 * asserts SET EQUALITY, in both directions, between:
 *
 *   - every method declared on `StorageBackend` + `FilesystemStorageCapabilities`
 *     in `storage/interface.ts`, and
 *   - the union of the guard's declared mutating and delegated method lists.
 *
 * The failure this exists to catch: someone adds a mutating method to the
 * storage interface (say `truncate`), the guard does not implement it, and a
 * "read-only" caller silently mutates through a method nobody classified. That
 * is invisible to a runtime test of the guard's existing methods, because the
 * new method simply is not there to test.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  READ_ONLY_STORAGE_DELEGATED_METHODS,
  READ_ONLY_STORAGE_MUTATING_METHODS,
  ReadOnlyStorageGuard,
} from "../../src/storage/read-only-guard.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const INTERFACE_FILE = join(HERE, "..", "..", "src", "storage", "interface.ts");

/** The interfaces whose methods the guard must classify. */
const GUARDED_INTERFACES = ["StorageBackend", "FilesystemStorageCapabilities"];

/**
 * Pull method names out of one `export interface X { ... }` block.
 *
 * Deliberately source-text based, like the repo's other structural guards, so
 * it fails at authoring time. It reads the brace-balanced body of the named
 * interface and matches BOTH member spellings TypeScript allows for a
 * function-shaped member at a declaration position: method style (`name(` /
 * `name?(`) and property style (`name: (…) => …` / `name?: (…) => …`). A
 * parser that saw only the method style would let a mutating member declared
 * property-style join the interface unclassified — the exact drift this test
 * exists to refuse — so the property branch requires the `(` right after the
 * colon that marks a function type, keeping data members (`key: string`)
 * unmatched.
 */
function interfaceMethodNames(source: string, interfaceName: string): string[] {
  const header = new RegExp(`interface\\s+${interfaceName}\\s*{`).exec(source);
  if (!header) {
    throw new Error(`interface ${interfaceName} not found in storage/interface.ts`);
  }
  let depth = 0;
  let end = -1;
  const start = header.index + header[0].length;
  for (let i = start - 1; i < source.length; i++) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) throw new Error(`unbalanced braces in ${interfaceName}`);
  const body = source.slice(start, end);
  const names = new Set<string>();
  // Two alternatives, one per member spelling: `name(` / `name?(` (method
  // style) and `name: (` / `name?: (` (property style holding a function
  // type). The `\(` after the colon is what keeps non-function properties
  // out of the set.
  for (const match of body.matchAll(
    /(?:^|\n)\s*([A-Za-z_$][\w$]*)\??\s*(?::\s*)?\(/g
  )) {
    names.add(match[1]!);
  }
  return [...names];
}

describe("ReadOnlyStorageGuard interface parity", () => {
  const declared = new Set<string>(
    GUARDED_INTERFACES.flatMap((name) =>
      interfaceMethodNames(readFileSync(INTERFACE_FILE, "utf8"), name)
    )
  );
  const classified = new Set<string>([
    ...READ_ONLY_STORAGE_MUTATING_METHODS,
    ...READ_ONLY_STORAGE_DELEGATED_METHODS,
  ]);

  it("finds the interfaces it is supposed to be checking", () => {
    // A parser that silently matched nothing would make every assertion below
    // vacuously pass, which is the shape this repo has shipped before.
    expect(declared.size).toBeGreaterThanOrEqual(6);
    expect(declared).toContain("write");
    expect(declared).toContain("read");
    expect(declared).toContain("writeDurable");
  });

  it("classifies every declared storage method, and classifies nothing else", () => {
    const unclassified = [...declared].filter((name) => !classified.has(name)).sort();
    const stale = [...classified].filter((name) => !declared.has(name)).sort();
    expect({ unclassified, stale }).toEqual({ unclassified: [], stale: [] });
  });

  it("implements every classified method on the guard itself", () => {
    const guard = new ReadOnlyStorageGuard(new MemoryStorage()) as unknown as Record<
      string,
      unknown
    >;
    const missing = [...classified].filter(
      (name) => typeof guard[name] !== "function"
    );
    // `listNamespaces` is present here because MemoryStorage supplies it; the
    // presence-mirroring behavior itself is asserted in the guard's own test.
    expect(missing).toEqual([]);
  });
});
