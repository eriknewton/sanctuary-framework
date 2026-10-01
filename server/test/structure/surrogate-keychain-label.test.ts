/**
 * Capability: the surrogate keychain service literal has exactly one
 * declaration in the tree, and the only keychain construction that supplies a
 * service override is the surrogate store's own.
 *
 * Those two facts are what make the separation between the two labels a
 * storage-level property rather than a convention, which is what the design
 * asks for. Both are asserted here so a later edit that added a second copy of
 * the literal, or a second override, has to change this file to land.
 *
 * Structural, not behavioral: it reads the source tree, because what it guards
 * against is a future edit rather than a runtime path.
 *
 * Defect id: SURROGATE-LABEL-CONVERGENCE.
 */

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC_ROOT = fileURLToPath(new URL("../../src/", import.meta.url));

/** Must match `SURROGATE_SERVICE_PREFIX` in `disclosure/broker/surrogate-store.ts`. */
const SURROGATE_SERVICE_PREFIX = "sanctuary-surrogate";

/** The one file allowed to declare it, relative to `src/`. */
const SOLE_DECLARATION = "disclosure/broker/surrogate-store.ts";

async function typescriptFilesUnder(dir: string, prefix = ""): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...(await typescriptFilesUnder(join(dir, entry.name), rel)));
    } else if (entry.name.endsWith(".ts")) {
      out.push(rel);
    }
  }
  return out;
}

describe("the surrogate keychain label has exactly one declaration", () => {
  it("no file under src/ besides the store declares the service literal", async () => {
    const files = await typescriptFilesUnder(SRC_ROOT);
    const offenders: string[] = [];
    for (const rel of files) {
      if (rel === SOLE_DECLARATION) continue;
      const body = await readFile(join(SRC_ROOT, rel), "utf8");
      // A quoted occurrence is a declaration. Prose that names the label in a
      // comment is fine and is how the pin on the other side is written.
      // The literal is the KEYCHAIN SERVICE, which is either the bare prefix or
      // the prefix plus a `-<hex digest>` per-fortress suffix. A quoted token
      // that merely STARTS with the prefix and continues with a word (the
      // `sanctuary-surrogate-bindings` artifact-format kind in
      // `credential-surrogate/artifacts.ts`, for instance) is an on-disk file
      // format, not a keychain service, and is not what this guard is about.
      // Matching the prefix alone would make this test fail on every future file
      // name that shares it, which trains a reader to widen the allow list.
      for (const quote of ['"', "'", "`"]) {
        const re = new RegExp(`${quote}${SURROGATE_SERVICE_PREFIX}(-[0-9a-f]+)?${quote}`);
        if (re.test(body)) {
          offenders.push(rel);
          break;
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the store declares it exactly once", async () => {
    const body = await readFile(join(SRC_ROOT, SOLE_DECLARATION), "utf8");
    const quoted = body.match(new RegExp(`"${SURROGATE_SERVICE_PREFIX}"`, "g")) ?? [];
    expect(quoted).toHaveLength(1);
  });

  it("openBroker constructs its keychain backend with NO service override", async () => {
    const body = await readFile(join(SRC_ROOT, "disclosure/broker/open.ts"), "utf8");
    const construction = body.match(/new KeychainBackend\(\{[^}]*\}\)/gs) ?? [];
    expect(construction.length).toBeGreaterThan(0);
    for (const site of construction) {
      // A `service:` here would point the broker at whatever label the caller
      // chose, including the surrogate one.
      expect(site).not.toContain("service:");
    }
  });

  it("the only service override in src/ is the store's own", async () => {
    const files = await typescriptFilesUnder(SRC_ROOT);
    const offenders: string[] = [];
    for (const rel of files) {
      if (rel === SOLE_DECLARATION) continue;
      const body = await readFile(join(SRC_ROOT, rel), "utf8");
      for (const site of body.match(/new KeychainBackend\(\{[^}]*\}\)/gs) ?? []) {
        if (site.includes("service:")) offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
  });
});
