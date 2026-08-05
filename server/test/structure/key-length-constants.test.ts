/**
 * Key-length constant guard (Hygiene Retrofit PR-4, "no bare magic numbers").
 *
 * Ed25519 key and signature widths used to be written as bare `32` / `64`
 * literals at ~90 comparison sites. That is not a style problem: `32` is ALSO
 * the AES-256 key size, the SHA-256 digest size, the handshake nonce width, and
 * the symmetric fortress master-key size, and `64` is ALSO the legacy
 * `seed || public_key` private-key layout AND the hex character count of a
 * SHA-256 digest. A reader cannot tell which meaning a literal carries.
 *
 * There are TWO ways to get this wrong, and they are not equally easy to catch:
 *
 *   A. a bare literal survives, so the site still says nothing; and
 *   B. a NAMED constant is used against the wrong key class, e.g. checking an
 *      Ed25519 PRIVATE key against `ED25519_PUBLIC_KEY_BYTES`. Both are 32, so
 *      it compiles, passes every test, and reads as intentional.
 *
 * B is the dangerous one and it is what this suite exists for. It was not
 * hypothetical: the first draft of PR-4 fixed that exact shape in
 * `mesh/trust-root-hybrid.ts` and `v1/federation-revocation.ts` and left three
 * live instances in `mesh/federation-trust-root-store.ts`, in a file the same
 * PR edited. An earlier version of THIS file scanned only bare literals in a
 * hand-listed file set and would have stayed green through all three.
 *
 * So the suite now has four parts:
 *
 *   1. RECONCILIATION: the byte-width constants that must agree across files
 *      that cannot import each other actually do.
 *   2. WRONG-CONSTANT SCAN (the B case): over ALL of `server/src`, every use of
 *      an Ed25519 width constant is paired with its subject expression, and the
 *      constant's key class must match the subject's. See LIMITATIONS below for
 *      exactly what this does and does not reach.
 *   3. NO BARE LITERAL (the A case): the files PR-4 converted contain no
 *      bare-literal Ed25519 length comparison.
 *   4. SELF-CHECK: both scanners are fed known-bad and known-good fixtures, so
 *      neither can pass vacuously if a regex breaks.
 *
 * LIMITATIONS of the wrong-constant scan, stated plainly so nobody reads more
 * coverage into it than it has:
 *
 *   - It pairs a constant with the nearest preceding subject token inside the
 *     same statement or argument list. It does NOT parse TypeScript.
 *   - It can only classify a subject whose IDENTIFIER names its key class
 *     (`publicKey`, `private_key`, `seed`, `signature`, `sig`, `...Pub`). At the
 *     time of writing it classifies 67 of 100 use sites; the other 33 are
 *     generically named (`bytes`, `key`, `value`, `raw`) and are NOT checked.
 *     A wrong constant against a generically named variable will not be caught.
 *   - It does not follow a value through an assignment, a parameter, or a
 *     helper call. `assertKeyLength(value, label)` style helpers are opaque to
 *     it by construction.
 *   - It matches constants by NAME, so an aliased import
 *     (`import { ED25519_PUBLIC_KEY_BYTES as PK }`) would rename the constant
 *     out of the scan's sight and a wrong pairing written as `x.length === PK`
 *     would pass silently. Rather than build an alias resolver for an idiom this
 *     codebase does not use, part 2 REFUSES aliased imports of a tracked
 *     constant outright: the gap is closed by a loud failure, not by coverage.
 *     A re-export (`export { X as Y }`) is refused for the same reason.
 *   - `ED25519_LEGACY_SEED_AND_PUBKEY_BYTES` is deliberately exempt from the
 *     class check: it names a concatenation of both classes, so no single
 *     subject class is correct. It is NOT exempt from the alias refusal.
 *
 * The floor assertions in part 2 exist so those limits cannot quietly widen: if
 * a refactor breaks the scan, the site count or the classified count drops and
 * the suite reds instead of reporting a vacuous zero violations.
 *
 * When this reds: the message names file, line, subject class, and constant.
 * The fix is to use the right constant, NOT to rename the variable so the
 * scanner stops classifying it.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
// server/test/structure/<file> -> server/
const SERVER_DIR = join(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");

function read(rel: string): string {
  return readFileSync(join(SERVER_SRC, rel), "utf8");
}

/** Value of an `export const NAME = <int>;` or `const NAME = <int>;` declaration. */
function declaredInt(source: string, name: string): number | null {
  const m = new RegExp(
    `(?:export\\s+)?const\\s+${name}\\s*(?::\\s*[^=]+)?=\\s*(\\d+)\\s*;`,
  ).exec(source);
  return m ? Number(m[1]) : null;
}

function tsFilesUnder(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) tsFilesUnder(p, out);
    else if (entry.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

// ── The wrong-constant scanner ──────────────────────────────────────────

type KeyClass = "public" | "private" | "signature";

const CLASS_OF_CONSTANT: Record<string, KeyClass> = {
  ED25519_PUBLIC_KEY_BYTES: "public",
  ED25519_PRIVATE_KEY_BYTES: "private",
  ED25519_SIGNATURE_BYTES: "signature",
};

/**
 * Identifier shapes that reveal what class of material a subject holds. All are
 * applied case-insensitively, so `publicKey`, `public_key`, and `pub` all
 * classify; that is what lets the scan reach camelCase and snake_case sites in
 * the same pass.
 */
const SUBJECT_TOKENS: ReadonlyArray<readonly [RegExp, KeyClass]> = [
  [/public_?key|pubkey|pub\b/, "public"],
  [/private_?key|secret_?key|seed|priv\b/, "private"],
  [/signature|(^|[^a-z])sig([^a-z]|$)/, "signature"],
];

/**
 * Statement / argument boundaries. A CLOSING paren is deliberately NOT a
 * boundary: in `decodeKeyExact(readString(ed, "private_key"), CONST, ...)` the
 * subject sits inside a nested call that has already closed, and treating `)`
 * as a boundary hides exactly that shape. This was measured, not guessed: with
 * `)` included, 2 of the 3 known-bad sites were caught; without it, 3 of 3.
 */
const BOUNDARY = /[;{}(]|\|\||&&/g;

/** Blank out comments, preserving offsets so line numbers stay correct. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));
}

function classifySubject(text: string): KeyClass | null {
  let best: KeyClass | null = null;
  let bestIdx = -1;
  for (const [re, cls] of SUBJECT_TOKENS) {
    const g = new RegExp(re.source, "gi");
    let m: RegExpExecArray | null;
    let last: RegExpExecArray | null = null;
    while ((m = g.exec(text)) !== null) last = m;
    if (last && last.index > bestIdx) {
      bestIdx = last.index;
      best = cls;
    }
  }
  return best;
}

interface UseSite {
  rel: string;
  line: number;
  constant: string;
  expected: KeyClass;
  subject: KeyClass | null;
  text: string;
}

function scanUseSites(
  sources: ReadonlyArray<{ rel: string; text: string }>,
): UseSite[] {
  const sites: UseSite[] = [];
  for (const { rel, text: raw } of sources) {
    const src = stripComments(raw);
    for (const [constant, expected] of Object.entries(CLASS_OF_CONSTANT)) {
      const g = new RegExp(`\\b${constant}\\b`, "g");
      let m: RegExpExecArray | null;
      while ((m = g.exec(src)) !== null) {
        const lineStart = src.lastIndexOf("\n", m.index) + 1;
        const nl = src.indexOf("\n", m.index);
        const lineText = src.slice(lineStart, nl === -1 ? src.length : nl);
        // Skip the declaration itself and any import statement.
        if (/^\s*(export\s+)?const\s/.test(lineText)) continue;
        if (/^\s*import\b|^\s*\}\s*from\b/.test(lineText)) continue;
        const before = src.slice(Math.max(0, m.index - 400), m.index);
        if (before.lastIndexOf("import {") > before.lastIndexOf("} from")) continue;

        const head = src.slice(0, m.index);
        let cut = 0;
        BOUNDARY.lastIndex = 0;
        let b: RegExpExecArray | null;
        while ((b = BOUNDARY.exec(head)) !== null) cut = b.index + b[0].length;
        // A CONSTANT name is never the subject; strip SCREAMING_CASE first.
        const window = head.slice(cut).replace(/\b[A-Z][A-Z0-9_]{2,}\b/g, " ");
        sites.push({
          rel,
          line: src.slice(0, m.index).split("\n").length,
          constant,
          expected,
          subject: classifySubject(window),
          text: lineText.trim(),
        });
      }
    }
  }
  return sites;
}

/**
 * Constants whose NAME the subject scan depends on. The legacy width is here
 * even though it is exempt from the class check: aliasing it would still hide a
 * use site from every count, including the anti-vacuity floors.
 */
const ALIAS_TRACKED = [
  ...Object.keys(CLASS_OF_CONSTANT),
  "ED25519_LEGACY_SEED_AND_PUBKEY_BYTES",
];

/**
 * Aliased imports/re-exports of a tracked constant.
 *
 * Scoped to import and export STATEMENTS so a TypeScript cast (`X as number`)
 * elsewhere in a file cannot false-positive. Refusing is deliberately cheaper
 * than resolving: an alias resolver would have to track per-file rename maps
 * for a pattern that appears zero times in this codebase.
 */
function aliasedTrackedImports(
  sources: ReadonlyArray<{ rel: string; text: string }>,
): string[] {
  const found: string[] = [];
  for (const { rel, text } of sources) {
    const src = stripComments(text);
    const stmts = src.matchAll(
      /^(?:import|export)\b[\s\S]*?from\s+["'][^"']+["'];/gm,
    );
    for (const stmt of stmts) {
      for (const constant of ALIAS_TRACKED) {
        const alias = new RegExp(`\\b${constant}\\s+as\\s+([A-Za-z_$][\\w$]*)`).exec(
          stmt[0],
        );
        if (alias) {
          const line = src.slice(0, stmt.index! + alias.index).split("\n").length;
          found.push(`${rel}:${line} imports ${constant} as ${alias[1]}`);
        }
      }
    }
  }
  return found;
}

function serverSrcSources(): Array<{ rel: string; text: string }> {
  return tsFilesUnder(SERVER_SRC).map((abs) => ({
    rel: abs.slice(SERVER_SRC.length + 1),
    text: readFileSync(abs, "utf8"),
  }));
}

// ── The bare-literal scanner ────────────────────────────────────────────

/**
 * A comparison of some *.length against a bare 32 or 64, narrowed to subjects
 * whose names look like Ed25519 material so the many legitimate 32s (symmetric
 * keys, digests, nonces) do not red.
 */
const BARE_ED25519_LENGTH =
  /\b(?:[A-Za-z_$][\w$]*)?(?:[Pp]ub(?:lic)?[Kk]ey|[Pp]ubkey|[Pp]rivate[Kk]ey|[Ss]ignature|[Ss]ig|[Ss]eed)\w*\.length\s*(?:!==|===|!=|==)\s*(?:32|64)\b/;

/**
 * The files PR-4 converted. Listed explicitly rather than globbed: a glob would
 * silently start or stop covering files as the tree moves, and the point of
 * this list is that it is a reviewed decision. Note this list bounds part 3
 * ONLY; part 2 scans all of `server/src`.
 */
const CONVERTED_FILES = [
  "agent-contract/identity-bind.ts",
  "broker-mcp/producer-signature.ts",
  "castle-wall/runtime/helper-signer.ts",
  "castle-wall/runtime/linux-activation-gate.ts",
  "castle-wall/runtime/macos-daemon.ts",
  "castle-wall/runtime/manifest-publisher.ts",
  "castle-wall/runtime/producer-signature.ts",
  "cli/castle-wall-observe.ts",
  "cli/castle-wall.ts",
  "cli/custody-unlock.ts",
  "cli/federation-operator-signing.ts",
  "cli/fleet.ts",
  "cli/transparency.ts",
  "entitlement/activation.ts",
  "entitlement/compliance-attestation.ts",
  "entitlement/token.ts",
  "mesh/federation-joiner-trust-root-store.ts",
  "mesh/federation-rotate-root.ts",
  "mesh/federation-trust-root-store.ts",
  "mesh/guardian/guardian-roster.ts",
  "mesh/libp2p-transport/peer-id.ts",
  "mesh/lifecycle/node-key-binding.ts",
  "mesh/trust-root-hybrid.ts",
  "recognition/did-web.ts",
  "release-manifest.ts",
  "transparency/emitter.ts",
  "transparency/signer.ts",
  "v1/federation-policy-bundle.ts",
  "v1/federation-revocation.ts",
  "v1/federation-sync-envelope.ts",
  "v1/federation.ts",
  "v1/operator-attestation.ts",
  "v1/session-service.ts",
  "workload-lifecycle/host-attestation.ts",
  "workload-lifecycle/undeclared-finding.ts",
];

/**
 * The standalone offline verifier subset: these three files import only each
 * other, `@noble/*`, and `node:` builtins, so a third party can compile and run
 * them without a Sanctuary server. This is NOT a property of `transparency/` at
 * large: `against-log.ts`, `checkpoint.ts`, `emitter.ts`, and `signer.ts` all
 * import server modules. Scoping this list correctly matters because the
 * "cannot import" claim is what justifies their bare literals.
 */
const STANDALONE_VERIFIER_SUBSET = [
  "transparency/verify.ts",
  "transparency/anchor-verify.ts",
  "transparency/offline-cli.ts",
];

describe("Ed25519 byte-width constants", () => {
  const registry = read("core/crypto-suite-registry.ts");

  it("declares the Ed25519 widths the rest of the tree imports", () => {
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_PRIVATE_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
    expect(declaredInt(registry, "ML_DSA_65_PUBLIC_KEY_BYTES")).toBe(1952);
    expect(declaredInt(registry, "ML_DSA_65_SECRET_KEY_BYTES")).toBe(4032);
    expect(declaredInt(registry, "ML_DSA_65_SIGNATURE_BYTES")).toBe(3309);
  });

  it("derives the legacy seed||pubkey width instead of hardcoding 64", () => {
    // The declaration must be an expression over the two named widths, not the
    // literal 64: writing 64 here is what makes it look like a signature length.
    expect(registry).toContain(
      "export const ED25519_LEGACY_SEED_AND_PUBKEY_BYTES =\n" +
        "  ED25519_PRIVATE_KEY_BYTES + ED25519_PUBLIC_KEY_BYTES;",
    );
  });

  it("keeps core/identity.ts's un-importable copy equal to the registry", () => {
    // identity.ts CANNOT import the registry: crypto-suite-registry.ts imports
    // `sign`/`verify` from identity.ts, so the reverse edge would close a
    // dependency cycle. The literal is pinned by comment; this is its teeth.
    const identity = read("core/identity.ts");
    expect(declaredInt(identity, "ED25519_PUBLIC_KEY_LENGTH")).toBe(
      declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES"),
    );
  });

  it("proves core/identity.ts still cannot import the registry", () => {
    // If this ever stops being true the pin above should become a real import.
    // Reading the ACTUAL import list rather than trusting a header comment is
    // deliberate: a "this module imports nothing from X" claim that contradicts
    // the imports is a defect class this repo has hit repeatedly.
    expect(registry).toMatch(/^import .*from "\.\/identity\.js";$/m);
  });

  it("keeps the legacy frozen serializers' literals equal to the registry", () => {
    // `pqc-slice1-additive.test.ts` forbids these two modules from so much as
    // naming the suite registry, so that frozen v1 signatures stay byte-stable.
    // They therefore keep bare literals; this is the reconciliation that makes
    // those literals safe. Verified against that gate's real file list, so the
    // two guards cannot drift into contradicting each other.
    const pqcGate = readFileSync(
      join(SERVER_DIR, "test", "structure", "pqc-slice1-additive.test.ts"),
      "utf8",
    );
    expect(pqcGate).toContain('"server/src/transparency/checkpoint.ts"');
    expect(pqcGate).toContain('"server/src/v1/operator-signed.ts"');

    expect(read("transparency/checkpoint.ts")).toContain(
      "if (keyBytes.length !== 32) return false;",
    );
    expect(read("v1/operator-signed.ts")).toContain(
      "if (signature.length !== 64) return false;",
    );
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
  });

  it("keeps the standalone verifier SUBSET self-contained and equal to the registry", () => {
    // Derived from the real import list of each file, never from header prose.
    // The subset's closure may reach only itself, @noble, and node: builtins.
    for (const rel of STANDALONE_VERIFIER_SUBSET) {
      const specs = [
        ...read(rel).matchAll(/^import[\s\S]*?from\s+["']([^"']+)["'];/gm),
      ].map((m) => m[1]!);
      for (const spec of specs) {
        if (spec.startsWith(".")) {
          const resolved = `transparency/${spec
            .replace(/^\.\//, "")
            .replace(/\.js$/, ".ts")}`;
          expect(
            STANDALONE_VERIFIER_SUBSET,
            `${rel} imports ${spec}, which is outside the standalone subset`,
          ).toContain(resolved);
        } else {
          expect(
            spec.startsWith("@noble/") || spec.startsWith("node:"),
            `${rel} imports ${spec}, which is neither @noble nor a node: builtin`,
          ).toBe(true);
        }
      }
    }

    // ...and the claim is scoped: the rest of transparency/ is NOT standalone,
    // so a future edit cannot widen the wording and stay green.
    expect(read("transparency/against-log.ts")).toMatch(
      /^import .*from "\.\.\/audit\/chain\.js";$/m,
    );

    expect(read("transparency/verify.ts")).toContain(
      "if (key.length !== 32) return false;",
    );
    expect(read("transparency/verify.ts")).toContain(
      "if (sig.length !== 64) return false;",
    );
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
  });
});

describe("no Ed25519 width constant used against the wrong key class", () => {
  const sites = scanUseSites(serverSrcSources());

  it("fires on the exact shape that shipped past the previous guard (self-check)", () => {
    // The real instances found in mesh/federation-trust-root-store.ts,
    // reproduced verbatim, including the nested-call form that a closing-paren
    // boundary would have hidden.
    const knownBad = [
      {
        rel: "fixture-a.ts",
        text: [
          "assertExactLength(",
          "  keys.ed25519.private_key,",
          "  ED25519_PUBLIC_KEY_BYTES,",
          '  "hybrid ed25519 private_key",',
          ");",
        ].join("\n"),
      },
      {
        rel: "fixture-b.ts",
        text: [
          "ed25519PrivateKey = decodeKeyExact(",
          '  readString(ed, "private_key"),',
          "  ED25519_PUBLIC_KEY_BYTES,",
          "  `${where}.ed25519.private_key`,",
          ");",
        ].join("\n"),
      },
      {
        rel: "fixture-c.ts",
        text: "if (params.signer.publicKey.length !== ED25519_SIGNATURE_BYTES) {",
      },
      {
        rel: "fixture-d.ts",
        text: "if (signature.length !== ED25519_PUBLIC_KEY_BYTES) return false;",
      },
    ];
    const caught = scanUseSites(knownBad).filter(
      (s) => s.subject !== null && s.subject !== s.expected,
    );
    expect(caught.map((s) => s.rel).sort()).toEqual([
      "fixture-a.ts",
      "fixture-b.ts",
      "fixture-c.ts",
      "fixture-d.ts",
    ]);
  });

  it("stays quiet on correct pairings (self-check)", () => {
    const knownGood = [
      {
        rel: "ok-a.ts",
        text: [
          "assertExactLength(",
          "  keys.ed25519.private_key,",
          "  ED25519_PRIVATE_KEY_BYTES,",
          ");",
        ].join("\n"),
      },
      {
        rel: "ok-b.ts",
        text:
          "if (nodePubkey.length !== ED25519_PUBLIC_KEY_BYTES || signature.length !== ED25519_SIGNATURE_BYTES) {",
      },
      {
        rel: "ok-c.ts",
        text: "if (seed.length !== ED25519_PRIVATE_KEY_BYTES) {",
      },
      {
        rel: "ok-d.ts",
        // The legacy layout is exempt by construction: its own name is stripped
        // before classification and it is not in CLASS_OF_CONSTANT.
        text: "if (privateKey.length === ED25519_LEGACY_SEED_AND_PUBKEY_BYTES) {",
      },
    ];
    const caught = scanUseSites(knownGood).filter(
      (s) => s.subject !== null && s.subject !== s.expected,
    );
    expect(caught).toEqual([]);
  });

  it("refuses an aliased import of a tracked constant (self-check)", () => {
    // The scan matches by name, so an alias would hide a use site from it AND
    // from the floors below. Refusing is the cheap correct answer.
    const aliased = [
      {
        rel: "aliased.ts",
        text: [
          'import { ED25519_PUBLIC_KEY_BYTES as __PK } from "../core/crypto-suite-registry.js";',
          "return private_key.length === __PK;",
        ].join("\n"),
      },
      {
        rel: "reexported.ts",
        text: 'export { ED25519_SIGNATURE_BYTES as SIG_LEN } from "./crypto-suite-registry.js";',
      },
    ];
    expect(aliasedTrackedImports(aliased)).toEqual([
      "aliased.ts:1 imports ED25519_PUBLIC_KEY_BYTES as __PK",
      "reexported.ts:1 imports ED25519_SIGNATURE_BYTES as SIG_LEN",
    ]);

    // ...and a plain import, or a cast that merely reads like an alias, is fine.
    expect(
      aliasedTrackedImports([
        {
          rel: "plain.ts",
          text: [
            'import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";',
            "const n = ED25519_PUBLIC_KEY_BYTES as number;",
          ].join("\n"),
        },
      ]),
    ).toEqual([]);
  });

  it("has no aliased import of a tracked constant anywhere in server/src", () => {
    // If this reds, do not build a resolver: import the constant under its own
    // name. The scan's whole subject-pairing model assumes the name is intact.
    expect(aliasedTrackedImports(serverSrcSources())).toEqual([]);
  });

  it("still reaches the tree (anti-vacuity floor)", () => {
    // A zero-violation result means nothing if the scan went blind. These floors
    // are what make the green in the next test positive evidence rather than
    // absence of evidence. Raise them when the tree grows; never lower them to
    // silence a red.
    expect(sites.length).toBeGreaterThanOrEqual(90);
    expect(sites.filter((s) => s.subject !== null).length).toBeGreaterThanOrEqual(60);
  });

  it("pairs every classifiable use site with the matching key class", () => {
    const violations = sites
      .filter((s) => s.subject !== null && s.subject !== s.expected)
      .map(
        (s) =>
          `${s.rel}:${s.line} subject=${s.subject} constant=${s.constant} :: ${s.text}`,
      );
    expect(violations).toEqual([]);
  });
});

describe("no bare Ed25519 length literals in the converted files", () => {
  it("the scan pattern actually matches a bare literal (self-check)", () => {
    expect(BARE_ED25519_LENGTH.test("if (publicKey.length !== 32) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (signature.length !== 64) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (nodePubkey.length !== 32) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (seed.length !== 32) {")).toBe(true);
    // ...and does NOT match the symmetric/digest 32s that must stay literals.
    expect(BARE_ED25519_LENGTH.test("if (masterKey.length !== 32) {")).toBe(false);
    expect(BARE_ED25519_LENGTH.test("if (rootHash.length !== 32) return null;")).toBe(
      false,
    );
  });

  for (const rel of CONVERTED_FILES) {
    it(`${rel} names its Ed25519 widths`, () => {
      const offending = read(rel)
        .split("\n")
        .map((line, i) => ({ line, n: i + 1 }))
        // Comments are prose about the numbers, not enforcement; the derivation
        // notes PR-4 added deliberately mention 32 and 64.
        .filter(({ line }) => !/^\s*(\/\/|\*|\/\*)/.test(line))
        .filter(({ line }) => BARE_ED25519_LENGTH.test(line))
        .map(({ line, n }) => `${rel}:${n}: ${line.trim()}`);
      expect(offending).toEqual([]);
    });
  }
});
