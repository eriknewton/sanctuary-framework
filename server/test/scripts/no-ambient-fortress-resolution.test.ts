/**
 * Structural gate: no leaf module may reach for the ambient fortress.
 *
 * `getOrCreatePassphrase()` and `readStoredPassphrase()` accept an explicit
 * `storagePath`. Called with no argument they re-resolve from `process.env` and
 * `os.homedir()`, which silently overrides whatever fortress the caller already
 * chose: `sanctuary sentinel subscribe --fortress /srv/agent-b` would derive
 * its master key from a passphrase read out of, and possibly created in, the
 * HOME fortress and the OS keyring entry named after it.
 *
 * On a plain single-tenant CLI run the two answers coincide, so the bug is
 * invisible in production and only shows up where the caller genuinely supplies
 * a different path: the programmatic `runSentinelCommand({ storagePath })`
 * surface, and every test that drives these verbs. That is exactly the shape
 * that lets a defect sit unnoticed. Enumeration, not spot-fixing, is the point
 * of scanning here: the same ambient call appeared at six separate sites while
 * four neighbouring sites had already been written the correct way.
 *
 * The scan is deliberately narrow and syntactic: it catches only a call with a
 * literally empty argument list. That is the exact regression shape, it has no
 * false positives, and it needs no parser.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(SERVER_ROOT, "src");

/**
 * Functions that resolve a fortress location when called with no argument.
 * Each accepts an explicit storage path; callers must pass the one they
 * already resolved.
 */
const AMBIENT_RESOLVERS = ["getOrCreatePassphrase", "readStoredPassphrase"];

function collectTypeScriptFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      collectTypeScriptFiles(full, out);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

interface CallSite {
  path: string;
  line: number;
  text: string;
}

function findAmbientCalls(): CallSite[] {
  const found: CallSite[] = [];
  // `await fn()` / `= fn()` / `fn()` but never `function fn()` or `fn(...)`.
  const patterns = AMBIENT_RESOLVERS.map(
    (name) => new RegExp(String.raw`(?<!function\s)\b${name}\(\s*\)`),
  );
  for (const path of collectTypeScriptFiles(SRC_ROOT)) {
    const lines = readFileSync(path, "utf-8").split("\n");
    lines.forEach((text, index) => {
      const trimmed = text.trim();
      // Prose in a doc-comment naming the function is not a call site.
      if (trimmed.startsWith("*") || trimmed.startsWith("//")) return;
      if (patterns.some((pattern) => pattern.test(text))) {
        found.push({
          path: relative(SERVER_ROOT, path),
          line: index + 1,
          text: trimmed,
        });
      }
    });
  }
  return found;
}

describe("no ambient fortress resolution in src", () => {
  it("every passphrase resolution names the fortress it is for", () => {
    const found = findAmbientCalls();
    // Name the offending sites AND the fix. A bare `expected [...] to equal []`
    // tells the next engineer what tripped but not why it is wrong, and this
    // shape is subtle enough (it is correct-looking, and correct by accident on
    // a single-tenant host) that the gate has to carry its own reasoning.
    const detail = found
      .map((site) => `  ${site.path}:${site.line}  ${site.text}`)
      .join("\n");
    expect(
      found,
      `Ambient fortress resolution in src:\n${detail}\n\n` +
        `These functions re-resolve the fortress from process.env / os.homedir() when ` +
        `called with no argument, overriding the storage path the caller already chose. ` +
        `Pass the fortress you resolved: getOrCreatePassphrase({ storagePath }).`,
    ).toEqual([]);
  });

  it("the scan actually recognises the regression shape it guards", () => {
    // A gate that cannot fail is not a gate. Prove the matcher on the exact
    // text it exists to catch, rather than trusting an empty result set.
    const pattern = new RegExp(
      String.raw`(?<!function\s)\bgetOrCreatePassphrase\(\s*\)`,
    );
    expect(pattern.test("    const resolved = await getOrCreatePassphrase();")).toBe(
      true,
    );
    expect(pattern.test("const r = await getOrCreatePassphrase( );")).toBe(true);
    // The corrected form, and the declaration itself, must not match.
    expect(
      pattern.test("const r = await getOrCreatePassphrase({ storagePath });"),
    ).toBe(false);
    expect(
      pattern.test("export async function getOrCreatePassphrase("),
    ).toBe(false);
  });
});
