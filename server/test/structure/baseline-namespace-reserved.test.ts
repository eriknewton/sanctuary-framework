// fail-before-exempt: a pin; the blanket underscore rule already reserves the insert-record namespace, so this holds on the base source as well.
/** The namespace insert store is reserved: agent state writes refuse it and full-fortress exit export skips it. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { getReservedNamespaceViolation, isReservedNamespace } from "../../src/cognitive/state-store.js";

const SERVER_SRC = join(fileURLToPath(import.meta.url), "..", "..", "..", "src");

describe("namespace insert store", () => {
  it("the namespace insert store is reserved", () => {
    expect(isReservedNamespace("_principal_ns")).toBe(true);
    // Curated prefixes match only themselves and their "/" children; the underscore rule reserves this name.
    expect(getReservedNamespaceViolation("_principal_ns")).toBe("_principal_ns");
    // Exit export skips every namespace this predicate reserves before it lists or writes state.
    const bundle = readFileSync(join(SERVER_SRC, "exit", "bundle.ts"), "utf8");
    expect(bundle).toContain("if (isReservedNamespace(namespace)) continue;");
  });
});
