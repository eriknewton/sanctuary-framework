/**
 * Structural gate: no leaf module may reach for the ambient fortress.
 *
 * `getOrCreatePassphrase()`, `readStoredPassphrase()` and
 * `persistUserProvidedPassphrase()` each accept an explicit `storagePath`.
 * Called without one they re-resolve from `process.env` and `os.homedir()`,
 * which silently overrides whatever fortress the caller already chose:
 * `sanctuary sentinel subscribe --fortress /srv/agent-b` would derive its
 * master key from a passphrase read out of, and possibly created in, the HOME
 * fortress and the OS keyring entry named after it.
 *
 * On a plain single-tenant CLI run the two answers coincide, so the bug is
 * invisible in production and only shows up where the caller genuinely supplies
 * a different path: the programmatic `runSentinelCommand({ storagePath })`
 * surface, and every test that drives these verbs. That is exactly the shape
 * that lets a defect sit unnoticed. Enumeration, not spot-fixing, is the point
 * of scanning here: the same ambient call appeared at seven separate sites
 * while four neighbouring sites had already been written the correct way.
 *
 * WHAT THIS SCAN CATCHES, AND WHAT IT DOES NOT
 * -------------------------------------------
 * The scan is syntactic and lexical, not semantic. It resolves each call's
 * argument list by balancing parentheses over comment-stripped source, and
 * flags the call when that argument text does not mention `storagePath` at
 * all. So it catches every shape of "the caller did not name a fortress":
 *
 *     fn()            fn(undefined)      fn({})
 *     fn({ home })    fn(opts)           fn(\n)
 *
 * An earlier revision matched only a literally empty argument list, which left
 * `fn({ home })` and `fn(opts)` -- the realistic regression shapes, since
 * `home` is a documented `PassphraseOptions` field and passing it alone still
 * resolves `storagePath` ambiently -- invisible to a gate whose title claims
 * the whole class.
 *
 * Three bounds remain, and are stated here so nobody trusts the gate past
 * them:
 *
 *  1. **Aliased and indirect calls evade it.** `import { getOrCreatePassphrase
 *     as gp }` then `gp()`, or `const f = getOrCreatePassphrase; f()`, is not
 *     matched: the scan keys on the exported name appearing literally at the
 *     call site. Catching that needs a type-aware pass, not a scanner.
 *  2. **Lexical, not semantic.** `fn({ storagePath: maybeUndefined })` counts
 *     as naming the fortress even when the value resolves to `undefined` at
 *     runtime and the callee therefore falls back to ambient resolution. Two
 *     such sites existed (`cli/did-web.ts`, `cli/erc8004.ts`, both
 *     `storagePath: fortressFlag ?? undefined`); they were changed to resolve
 *     a concrete path so the argument is never `undefined`. A future one would
 *     pass this gate.
 *  3. **`src` only.** Test files are not scanned; they are expected to pass an
 *     explicit path or use `createTempFortress()`.
 *
 * When the scanner cannot delimit a call's argument list (unbalanced
 * parentheses within the window, e.g. a paren inside a string literal it does
 * not tokenize), it reports that call as a finding rather than skipping it.
 * "Could not look" must be representable; a scanner that silently drops the
 * calls it cannot parse is the vacuous-guard failure in a different costume.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { stripCodeComments } from "../structure/public-surface";

const SERVER_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(SERVER_ROOT, "src");

/**
 * Functions that resolve a fortress location when the caller does not name one.
 * Each accepts an explicit storage path; callers must pass the one they
 * already resolved.
 */
const AMBIENT_RESOLVERS = [
  "getOrCreatePassphrase",
  "readStoredPassphrase",
  "persistUserProvidedPassphrase",
];

/** The option every call must name. */
const REQUIRED_OPTION = "storagePath";

/** Upper bound on how far the balancer will look for a call's closing paren. */
const ARGUMENT_SCAN_LIMIT = 4000;

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
  reason: string;
}

/**
 * The one construction of the call matcher, shared by the scan and by the
 * scan's own anti-vacuity check.
 *
 * This MUST stay the single definition. An earlier revision had the self-check
 * rebuild an identical regex literal of its own, which meant the check proved a
 * COPY of the matcher rather than the matcher the scan runs. Neutering the
 * scan's regex to `/(?!)/` (a pattern that can never match) while
 * re-introducing the genuine regression into `src` left both tests green: the
 * gate silently stopped gating and reported itself healthy. Probe the
 * predicate, not a replica of it.
 *
 * Matches `await fn(` / `= fn(` / `fn(` but never `function fn(`. The match
 * ends at the open paren; the caller balances forward from there.
 */
export function ambientCallPattern(name: string): RegExp {
  return new RegExp(String.raw`(?<!function\s)\b${name}\s*\(`, "g");
}

/**
 * Given source text and the index of a call's open paren, return the argument
 * text between the parentheses, or `null` when the parentheses do not balance
 * inside {@link ARGUMENT_SCAN_LIMIT}.
 */
export function argumentTextAt(source: string, openParen: number): string | null {
  let depth = 0;
  const end = Math.min(source.length, openParen + ARGUMENT_SCAN_LIMIT);
  for (let i = openParen; i < end; i++) {
    const ch = source[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return source.slice(openParen + 1, i);
    }
  }
  return null;
}

/**
 * The predicate the gate enforces: does this call name the fortress it acts on?
 *
 * Exported so the anti-vacuity test exercises the real decision rather than
 * re-deriving it.
 */
export function callNamesFortress(argumentText: string): boolean {
  return argumentText.includes(REQUIRED_OPTION);
}

export function findAmbientCallsIn(
  source: string,
  relPath: string,
): CallSite[] {
  const found: CallSite[] = [];
  // Strip comments so prose naming the function is not read as a call site,
  // and so a commented-out call cannot trip the gate. Offsets are preserved.
  const code = stripCodeComments(source, relPath);
  for (const name of AMBIENT_RESOLVERS) {
    const pattern = ambientCallPattern(name);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(code)) !== null) {
      const openParen = match.index + match[0].length - 1;
      const args = argumentTextAt(code, openParen);
      const line = code.slice(0, match.index).split("\n").length;
      if (args === null) {
        found.push({
          path: relPath,
          line,
          text: source.split("\n")[line - 1]?.trim() ?? "",
          reason: `the scanner could not delimit the argument list of ${name}(`,
        });
        continue;
      }
      if (callNamesFortress(args)) continue;
      found.push({
        path: relPath,
        line,
        text: source.split("\n")[line - 1]?.trim() ?? "",
        reason: `${name}( ... ) does not name ${REQUIRED_OPTION}`,
      });
    }
  }
  return found.sort((a, b) => a.line - b.line);
}

function findAmbientCalls(): CallSite[] {
  const found: CallSite[] = [];
  for (const path of collectTypeScriptFiles(SRC_ROOT)) {
    const rel = relative(SERVER_ROOT, path);
    found.push(...findAmbientCallsIn(readFileSync(path, "utf-8"), rel));
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
      .map((site) => `  ${site.path}:${site.line}  ${site.text}\n    -> ${site.reason}`)
      .join("\n");
    expect(
      found,
      `Ambient fortress resolution in src:\n${detail}\n\n` +
        `These functions re-resolve the fortress from process.env / os.homedir() when ` +
        `the caller does not name one, overriding the storage path the caller already ` +
        `chose. Pass the fortress you resolved: getOrCreatePassphrase({ storagePath }).`,
    ).toEqual([]);
  });

  it("the scan actually recognises the regression shape it guards", () => {
    // A gate that cannot fail is not a gate. Prove the SCAN on the exact text
    // it exists to catch, rather than trusting an empty result set.
    //
    // This drives `findAmbientCallsIn` -- the same entry point the `src` scan
    // uses, through the same `ambientCallPattern` / `argumentTextAt` /
    // `callNamesFortress` chain -- so neutering any link in that chain fails
    // this test instead of leaving it green against a private copy of the
    // regex.
    const caught = [
      "const r = await getOrCreatePassphrase();",
      "const r = await getOrCreatePassphrase( );",
      "const r = await getOrCreatePassphrase(undefined);",
      "const r = await getOrCreatePassphrase({});",
      "const r = await getOrCreatePassphrase({ home });",
      "const r = await getOrCreatePassphrase(opts);",
      "const r = await getOrCreatePassphrase(\n);",
      "const r = await readStoredPassphrase({ home });",
      "await persistUserProvidedPassphrase(value, { home });",
    ];
    for (const source of caught) {
      expect(
        findAmbientCallsIn(source, "fixture.ts"),
        `expected the scan to flag: ${JSON.stringify(source)}`,
      ).toHaveLength(1);
    }

    const allowed = [
      "const r = await getOrCreatePassphrase({ storagePath });",
      "const r = await getOrCreatePassphrase({\n  storagePath: resolved,\n});",
      "const r = await readStoredPassphrase({ storagePath: tenant.storage_path });",
      "await persistUserProvidedPassphrase(value, { storagePath });",
      "export async function getOrCreatePassphrase(",
      "// see getOrCreatePassphrase() for precedence",
      "/** {@link getOrCreatePassphrase} resolves ambiently when called as fn(). */",
    ];
    for (const source of allowed) {
      expect(
        findAmbientCallsIn(source, "fixture.ts"),
        `expected the scan NOT to flag: ${JSON.stringify(source)}`,
      ).toEqual([]);
    }
  });

  it("reports a call it cannot delimit rather than silently skipping it", () => {
    // "Could not look" is representable. A scanner that drops the calls whose
    // argument list it cannot parse would under-report exactly where source is
    // hardest to read, which is where a defect is most likely to hide.
    const unbalanced = `const r = await getOrCreatePassphrase({ storagePath`;
    const found = findAmbientCallsIn(unbalanced, "fixture.ts");
    expect(found).toHaveLength(1);
    expect(found[0].reason).toContain("could not delimit");
  });
});
