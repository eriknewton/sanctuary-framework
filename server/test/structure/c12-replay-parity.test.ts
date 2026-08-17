/**
 * C12-REPLAY T9 — cross-stage parity structure guards (rules 5/11).
 *
 * These are source-text/structure assertions, not runtime behavior: they pin
 * that the retired hand-mirror stays retired and that the shared module is the
 * SOLE constructor of the quorum input, the SOLE freshness-assertion, and that
 * only applySync passes the weaker `sync_anchored` mode.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const MESH_SRC = join(REPO_ROOT, "server/src/mesh");
// The scans walk ALL of server/src, not a hand-picked file list: a single-file
// substring pin cannot see a new caller added elsewhere (the J5 lesson — no
// single-file substring pins).
const SERVER_SRC = join(REPO_ROOT, "server/src");

/**
 * Read a source file as EXECUTABLE code — comments removed (see stripComments).
 *
 * Every scan in this file goes through this or through `stripComments` directly,
 * with no raw reads left, because the round-3 gate reproduced the same
 * false-positive twice: a scan that reads raw source treats prose about a retired
 * construct as a use of it. Prose describing a rule is what documents why the
 * rule exists, so making it trip the rule punishes the documentation.
 */
function read(rel: string): string {
  return stripComments(readFileSync(join(REPO_ROOT, rel), "utf8"));
}

/**
 * Return the full parenthesised argument list that starts at `openIndex`,
 * matching parentheses so a nested call or object literal cannot truncate it.
 * A `[^}]*` regex stops at the FIRST closing brace, which is what let the old
 * pin read a partial call and reach the wrong conclusion.
 */
function sliceBalancedCall(source: string, openIndex: number): string {
  let depth = 0;
  for (let i = openIndex; i < source.length; i++) {
    const ch = source[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return source.slice(openIndex, i + 1);
    }
  }
  return source.slice(openIndex);
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

/**
 * Strip COMMENTS from TypeScript source, leaving executable code (and string
 * contents) intact, so a source scan cannot be fooled by prose and cannot be
 * fooled into treating prose as code.
 *
 * FAILURE-MODE NOTE, which is why this is a character scan and not two regexes:
 * the previous version ran `/\/\*[\s\S]*?\*\//` then `/^\s*\/\/.*$/gm`. That
 * pair is wrong in both directions. It misses a TRAILING `// ...` comment
 * entirely (the regex is anchored to the start of a line), so a comment
 * mentioning a retired construct false-positives the scan; and running the
 * block-comment pass first lets a `//` that lives inside a string — `"https://"`
 * is everywhere in this codebase — or a `/*` sequence inside a line comment
 * corrupt the boundaries. A scanner that has to reason about which of two
 * regexes fires first is the shape that goes wrong silently.
 *
 * String and regex-literal bodies are PRESERVED, deliberately: this function
 * only has to know where they START and END so it does not mistake their
 * contents for a comment. A construct hidden in a string literal should still
 * trip the scans below.
 *
 * Newlines are preserved everywhere, including inside block comments, so line
 * anchors (`^`/`m`) in the callers' patterns still mean what they say.
 */
function stripComments(source: string): string {
  let out = "";
  let i = 0;
  // A `/` starts a regex literal only where a VALUE may begin. Tracking the last
  // significant character is the standard disambiguation from division.
  //
  // A NEWLINE is deliberately NOT such a position, and that is the round-3
  // correction. The previous version listed `\n` here, so a division whose
  // operator OPENS a continuation line — `const r = a` then `  / b; // ...` — was
  // read as the start of a regex literal; the phantom regex ran to the first `/`
  // of the trailing comment and closed there, and the comment's remaining text was
  // then emitted as CODE. Prose about a retired construct therefore reddened the
  // very scans this function exists to keep honest, which is the failure it was
  // written to prevent, reintroduced from the other direction. ASI never inserts a
  // semicolon before a line that opens with `/`, so a line-leading `/` continues
  // the previous expression and is division whenever the previous significant
  // character could end one.
  const regexCanStart = (prev: string): boolean =>
    prev === "" || "=(,:[!&|?{};+-*%~^<>".includes(prev);
  let lastSignificant = "";
  while (i < source.length) {
    const ch = source[i]!;
    const next = source[i + 1] ?? "";
    if (ch === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) {
        if (source[i] === "\n") out += "\n";
        i++;
      }
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      out += ch;
      i++;
      while (i < source.length) {
        if (source[i] === "\\") {
          out += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        out += source[i];
        const closed = source[i] === ch;
        i++;
        if (closed) break;
      }
      lastSignificant = ch;
      continue;
    }
    if (ch === "/" && regexCanStart(lastSignificant)) {
      out += ch;
      i++;
      let inClass = false;
      while (i < source.length) {
        if (source[i] === "\\") {
          out += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        if (source[i] === "[") inClass = true;
        else if (source[i] === "]") inClass = false;
        const closed = source[i] === "/" && !inClass;
        out += source[i];
        i++;
        if (closed) break;
      }
      lastSignificant = "/";
      continue;
    }
    out += ch;
    // Whitespace of EVERY kind, newlines included, is insignificant for the
    // regex-vs-division decision — must match `regexCanStart` above, which no
    // longer treats a line break as a value position.
    if (!/\s/.test(ch)) lastSignificant = ch;
    i++;
  }
  return out;
}

describe("C12-REPLAY parity structure (T9)", () => {
  it("the retired v1 builders and their must-match pin comments are gone", () => {
    const nodeRevoke = read("server/src/mesh/recovery-flows/node-revoke.ts");
    const meshNode = read("server/src/mesh/lifecycle/mesh-node.ts");
    // The exported v1 builder is deleted.
    expect(nodeRevoke).not.toMatch(/export function revokeQuorumInput/);
    // The hand-mirror method is deleted.
    expect(meshNode).not.toMatch(/private nodeRevokeQuorumInput/);
  });

  it("NO mesh module reaches Math.random by ANY access form — the class, not one spelling", () => {
    // Fix-round correction (QI-SIBLING-02 gate finding): the prior version of
    // this guard named three files by hand and therefore could not see a FOURTH
    // `generateCeremonyId` copy with the same `Math.random` fallback living in
    // recovery-flows/canonical-audit-promotion.ts. A guard that enumerates its
    // targets has the same blind spot as a hand-mirrored registry (AGENTS.md
    // rule 5: assert over the full set, never over the entries someone
    // remembered). Every ceremony under mesh/ mints its nonces through
    // `core/random`, which throws rather than degrading (MUST-NEVER #5).
    //
    // Round-2 correction (re-gate finding): matching the literal string
    // `Math.random` pinned ONE SPELLING, not the class. `Math["random"]`,
    // `Math['random']` and `const { random } = Math` all reach the same
    // degraded source and all evaded it, and the hand-rolled comment stripping
    // it used mishandled trailing `//` comments so prose about the retired
    // fallback false-positived. Both halves are fixed: comments are removed by
    // a character scan, and every property-access form is matched.
    //
    // Round-3 correction (dry-check gate finding), about FORM:
    // `Math?.random()` evaded the pattern through optional chaining, and
    // `const M = Math; M.random()` evaded every pattern by aliasing the object.
    //
    // SCAN ROOT, and the stated bound that comes with it: this walks
    // `server/src/mesh`, not all of `server/src`, because the mesh layer is
    // where the retired duplicate ceremony-id minters lived and is the scope
    // this guard was built to keep honest. A minter carrying the same
    // weak-randomness fallback, written or renamed OUTSIDE the mesh
    // directory, is invisible to this guard — that gap is tracked as
    // QI-02-F8, not silently assumed away.
    //
    // STATED BOUND, because a broad claim that a one-line edit evades is worse
    // than a narrow honest one: this catches direct property access (optional
    // chaining included), computed access, destructuring, and a DIRECT alias
    // binding of the bare `Math` object. It cannot catch an alias laundered
    // through a value a source scan cannot follow — a returned object, a property
    // read, a computed global lookup — and no textual scan can. The mechanism
    // that actually forecloses the degradation is `core/random`, which throws
    // rather than falling back (MUST-NEVER #5); this is a tripwire on the shape
    // that has twice been hand-written in this tree, never a proof of absence.
    //
    // Optional chaining is an ACCESS FORM, not a different object, so it is
    // normalized away once rather than doubling every pattern below: two patterns
    // that have to stay in step are the drift shape rule 5 forbids.
    const propertyAccess =
      /\bMath\s*(?:\.\s*random\b|\.?\s*\[\s*(['"`])random\1\s*\])/;
    const destructured = /\{[^{}]*\brandom\b[^{}]*\}\s*=\s*Math\b/;
    // `const M = Math;` — the alias BINDING is the only part of the aliasing form
    // a source scan can see. The later `M.random()` is textually indistinguishable
    // from any other property read, so the guard refuses the binding itself.
    const aliasBinding =
      /(?:const|let|var)\s+\w+\s*(?::[^=;\n]+)?=\s*(?:(?:globalThis|global|window|self)\s*\.\s*)?Math\s*(?=[;,)\]\n])/;
    for (const file of walk(MESH_SRC)) {
      // Prose ABOUT the retired fallback is legitimate and is what documents
      // why the rule exists; only executable uses are the finding.
      const code = stripComments(readFileSync(file, "utf8")).replace(
        /\?\./g,
        "."
      );
      expect(
        propertyAccess.test(code) ||
          destructured.test(code) ||
          aliasBinding.test(code),
        `Math.random randomness fallback in ${file}`
      ).toBe(false);
    }
  });

  it("the CSPRNG ceremony-id minter has exactly ONE definition, in EVERY definition form", () => {
    // Companion to the scan above: deleting a `Math.random` fallback is not the
    // same as retiring the duplicate that carried it. A second hand-written
    // 128-bit-hex minter would pass the scan above while still being the
    // second implementation rule 5 forbids, so pin the DEFINITION count too.
    //
    // Round-2 correction (re-gate finding): the prior matcher was
    // `function (mint|generate)CeremonyId\(`, which pinned one SYNTAX. A
    // `const mintCeremonyId = () => ...`, a class method, or a name outside the
    // two hardcoded verbs evaded it completely. This matches every definition
    // form of any identifier carrying the `CeremonyId` token.
    //
    // STATED BOUND, so nobody reads this guard as more than it is: it is a
    // NAME-based scan, so a minter renamed to carry no `CeremonyId` token is
    // outside what it can see. It is not the only line of defense — the
    // degradation this class actually causes is caught by the access-form scan
    // above, which is name-independent — and a rename that also drops the
    // `Math.random` fallback is a reviewable refactor rather than the silent
    // duplication this guard exists to stop. Narrow and honest beats broad and
    // evadable by a one-line edit.
    const definitionForms = new RegExp(
      [
        // `function mintCeremonyId(`, `async function generateCeremonyId(`
        String.raw`function\s+\w*CeremonyId\s*\(`,
        // `const mintCeremonyId = () =>`, `= async function`, `= x =>`
        String.raw`(?:const|let|var)\s+\w*CeremonyId\s*(?::[^=;]+)?=\s*(?:async\s+)?(?:function\b|\(|\w+\s*=>)`,
        // class / object method: `private mintCeremonyId(): string {`
        String.raw`^[ \t]*(?:(?:private|public|protected|static|async|readonly)\s+)*\w*CeremonyId\s*\([^)]*\)\s*(?::[^{;]+)?\{`,
      ].join("|"),
      "gm"
    );
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    let definitionSites = 0;
    for (const file of walk(SERVER_SRC)) {
      const matches =
        stripComments(readFileSync(file, "utf8")).match(definitionForms) ?? [];
      if (matches.length > 0) {
        expect(
          file,
          `ceremony-id minter defined outside the shared module: ${file}`
        ).toBe(sharedModule);
        definitionSites += matches.length;
      }
    }
    expect(definitionSites).toBe(1);
  });

  it("the shared module is the ONLY constructor of the v2 MASTER-ROTATION input shape", () => {
    // QI-SIBLING-02 mirror of the revoke pin. A hand-built input assigns the
    // `schema` key (NOT the `input_schema` wire echo, which legitimately rides
    // MasterRotationPayload) to the v2 master-rotation value.
    const files = walk(SERVER_SRC);
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    const handBuilt =
      /(?<![\w])schema:\s*(?:"sanctuary\.guardian-master-rotation-quorum\.v2"|GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2)/;
    for (const file of files) {
      if (file === sharedModule) continue;
      const src = stripComments(readFileSync(file, "utf8"));
      expect(
        handBuilt.test(src),
        `unexpected hand-built v2 master-rotation input in ${file}`
      ).toBe(false);
    }
  });

  it("every acceptMasterRotation call site supplies its OWN clock", () => {
    // The `now` argument is required at the type level, so this pin is about the
    // OTHER half of rule 10: a site that reused a timestamp lifted from the
    // payload would typecheck and would enforce nothing. Each production call
    // must read a fresh clock at its own moment of verification.
    //
    // Fix-round correction (QI-SIBLING-02 gate finding): the prior matcher was
    // `acceptMasterRotation\(\{`, so a future call site passing a PRE-BUILT
    // object — `acceptMasterRotation(p)` — matched nothing and the pin passed
    // silently. Match EVERY invocation, then assert on the argument form, so a
    // shape this pin cannot reason about fails loudly instead of being absent
    // by omission (rule 11: the next instance is silently absent by omission).
    //
    // Round-3 correction (dry-check gate finding): this pin read RAW source, so a
    // doc comment naming `acceptMasterRotation(` was sliced as though it were a
    // call, its "argument list" was prose, and the pin reddened on a comment. Every
    // scan in this file now consumes `stripComments` output — comments are prose
    // ABOUT the contract, and only executable call sites are call sites.
    for (const file of walk(SERVER_SRC)) {
      const src = stripComments(readFileSync(file, "utf8"));
      // Definitions, re-exports and import statements are not call sites.
      const code = src
        .replace(/^import[\s\S]*?from\s+"[^"]*";$/gm, "")
        .replace(/export function acceptMasterRotation/g, "");
      const invocations = [...code.matchAll(/\bacceptMasterRotation\s*\(/g)];
      for (const match of invocations) {
        const call = sliceBalancedCall(code, match.index + match[0].length - 1);
        expect(
          call,
          `acceptMasterRotation called with a pre-built object (the clock cannot be verified here) in ${file}: ${call}`
        ).toMatch(/^\(\s*\{/);
        expect(
          call,
          `acceptMasterRotation without a fresh clock in ${file}`
        ).toMatch(/now:\s*new Date\(\)/);
      }
    }
  });

  it("the shared module is the ONLY constructor of the v2 revoke input shape", () => {
    // The schema literal is defined once (in the shared module) and otherwise
    // only referenced (type positions / wire echoes), never re-built by hand.
    const files = walk(SERVER_SRC);
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    // A hand-built input assigns the `schema` key (NOT the `input_schema` wire
    // echo, which legitimately rides NodeRevokePayload) to the v2 value.
    const handBuilt = /(?<![\w])schema:\s*(?:"sanctuary\.guardian-revoke-quorum\.v2"|GUARDIAN_REVOKE_QUORUM_SCHEMA_V2)/;
    for (const file of files) {
      if (file === sharedModule) continue;
      const src = stripComments(readFileSync(file, "utf8"));
      expect(
        handBuilt.test(src),
        `unexpected hand-built v2 input in ${file}`
      ).toBe(false);
    }
  });

  it("only applySync passes mode: \"sync_anchored\" — sole-caller scan over ALL of server/src", () => {
    // A VALUE-position use is `mode: "sync_anchored"` followed by `,` or `}`
    // (an object literal being passed); the shared module's FreshnessMode TYPE
    // member is followed by `;` and is the one legitimate non-call occurrence.
    const callSite = /mode:\s*"sync_anchored"\s*[,}]/g;
    const meshNodePath = join(MESH_SRC, "lifecycle", "mesh-node.ts");
    let totalCallSites = 0;
    for (const file of walk(SERVER_SRC)) {
      const matches =
        stripComments(readFileSync(file, "utf8")).match(callSite) ?? [];
      if (matches.length > 0) {
        expect(
          file,
          `sync_anchored passed outside mesh-node.ts: ${file}`
        ).toBe(meshNodePath);
        totalCallSites += matches.length;
      }
    }
    // Exactly one sync_anchored call site in ALL production code.
    expect(totalCallSites).toBe(1);
    // And it is inside applySync (the anchored call references effective_at).
    const meshNode = read("server/src/mesh/lifecycle/mesh-node.ts");
    const applySyncStart = meshNode.indexOf("async applySync(");
    const applySyncEnd = meshNode.indexOf("private admitRevoke(");
    expect(applySyncStart).toBeGreaterThan(0);
    expect(applySyncEnd).toBeGreaterThan(applySyncStart);
    const applySyncBody = meshNode.slice(applySyncStart, applySyncEnd);
    expect(applySyncBody).toMatch(/mode:\s*"sync_anchored"/);
  });

  it("TZ-WINDOW-01: every timestamp in the shared module goes through the ONE strict predicate", () => {
    // The defect class this pins shut: a timestamp field validated with a bare
    // `Date.parse` finiteness test accepts an offset-less date-time, which the
    // ECMAScript parser resolves against the READER's local zone — so one signed
    // window means a different absolute interval on every node. A per-field or
    // per-ceremony copy of the strict check is the hand-mirror shape rule 5
    // forbids, so the pin is "one call site", not "each site looks right".
    const src = read("server/src/mesh/guardian/revoke-quorum-input.ts");
    const predicateStart = src.indexOf(
      "export function parseIsoInstantWithOffset"
    );
    expect(predicateStart).toBeGreaterThan(0);
    // The predicate ends where the next top-level export begins.
    const predicateEnd = src.indexOf("export ", predicateStart + 1);
    expect(predicateEnd).toBeGreaterThan(predicateStart);

    const parseCalls = [...src.matchAll(/Date\.parse\s*\(/g)].map(
      (m) => m.index ?? -1
    );
    expect(
      parseCalls.length,
      `expected exactly one Date.parse in the shared module, found ${parseCalls.length}`
    ).toBe(1);
    expect(parseCalls[0]).toBeGreaterThan(predicateStart);
    expect(parseCalls[0]).toBeLessThan(predicateEnd);

    // Each of the four timestamp fields reaches the predicate by name. A bare
    // occurrence COUNT asserts arity, not identity: a refactor that dropped the
    // rotated_at call and added a second call on some other field would still
    // count 5 and stay green, which is exactly the defect shape this PR exists
    // to fix (a check that looks field-by-field but is actually a count). So
    // this asserts the four call-site argument spellings are ALL present, not
    // just that five calls exist.
    const predicateCallMatches = [
      ...src.matchAll(/parseIsoInstantWithOffset\s*\(/g),
    ];
    const predicateCallArgs = predicateCallMatches.map((m) => {
      const openIndex = (m.index ?? 0) + m[0].length - 1;
      return sliceBalancedCall(src, openIndex);
    });
    // 1 definition (`(value: string)`) + 4 call sites: initiated_at,
    // expires_at, effective_at, rotated_at.
    expect(predicateCallArgs.length).toBe(5);
    for (const argSpelling of [
      "initiatedAt",
      "expiresAt",
      "freshness.effective_at",
      "params.rotated_at",
    ]) {
      expect(
        predicateCallArgs.some((call) => call.includes(argSpelling)),
        `no parseIsoInstantWithOffset call site passes ${argSpelling}`
      ).toBe(true);
    }
  });

  it("no second freshness-assertion or ceremony-id generator exists under server/src", () => {
    const files = walk(SERVER_SRC);
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    for (const file of files) {
      if (file === sharedModule) continue;
      const src = stripComments(readFileSync(file, "utf8"));
      // The relying-side freshness logic is defined once.
      expect(
        src.includes("export function assertQuorumContextFresh"),
        `duplicate freshness assertion in ${file}`
      ).toBe(false);
      // The CSPRNG ceremony-id minting is defined once.
      expect(
        src.includes("export function mintRevokeCollectionContext"),
        `duplicate ceremony-id minting in ${file}`
      ).toBe(false);
    }
  });
});
