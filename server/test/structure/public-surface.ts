/**
 * Shared PUBLIC-FACING SURFACE resolver for the structure guards.
 *
 * The no-CIMC attribution guard and the no-em-dash ratchet both enforce a
 * CLAUDE.md MANDATORY rule against the same "public-facing artifact" surface.
 * Originally each guard carried its own copy of the scope logic and the two had
 * DRIFTED: neither covered the public root docs ROADMAP.md /
 * SANCTUARY_ARCHITECTURE.md / sanctuary_framework.md, nor the public subtrees
 * announcements/ examples/ quickstart/ rfcs/. A real CIMC reference or a new
 * em-dash in any of those would have FALSE-GREENED. This module is the single
 * source of truth for "what counts as the public-facing surface," so the two
 * guards can never diverge again.
 *
 * TRACKED-ONLY: every file in the surface is enumerated from `git ls-files`, so
 * untracked local/CI scratch (a developer's notes, CI state like `.gnupg-ci`,
 * generated artifacts) is never scanned. The guards assert over the COMMITTED
 * tree, which is exactly the thing a reviewer is gating.
 *
 * THE SURFACE (per the DoE C-1 review, made complete):
 *   - public root docs: README*, CHANGELOG*, ROADMAP.md,
 *     SANCTUARY_ARCHITECTURE.md, sanctuary_framework.md, plus the
 *     community/governance/legal docs (CONTRIBUTING, CODE_OF_CONDUCT,
 *     GOVERNANCE, LICENSE, ASSURANCE_MATRIX)
 *   - the npm-shipped server README (server/package.json ships README.md)
 *   - public text subtrees: docs/, announcements/, examples/, quickstart/,
 *     rfcs/, plugin/, the product components (integrations/, menubar/,
 *     castle-wall-daemon|macos|vmm/), the served assets server/public/, and the
 *     shipped agent-template bundles server/src/templates/  (text-ish only)
 *   - root + server package.json (root/ has no public subtree of its own)
 *
 * Deliberately OUT of scope (documented so the omission is a decision, not a
 * gap): Archive/ (frozen historical record), CLAUDE.md and other internal
 * briefings (the attribution rule itself permits internal/biographical
 * mention), server/docs/design-refs/ (internal JSX/CSS mockups — carved out of
 * the otherwise-in-scope server/docs/ operator docs via EXCLUDED_SUBTREES),
 * the "Sanctuary Site/" working copy (the live marketing site lives in a
 * separate Pages repo), and test files. `server/src` is handled SEPARATELY by
 * each guard (see `serverSrcTrackedTs`) because the two rules treat code
 * comments differently: CIMC is forbidden everywhere incl. comments, whereas
 * the no-em-dash rule exempts internal code comments (see em-dash.test.ts /
 * no-em-dash-in-cli.test.ts).
 *
 * NON-DEPENDENCY MANIFEST SCOPE (see non-dependency.test.ts): the dependency
 * check covers the JS/TS package manifests (root, server, menubar, quickstart).
 * Cargo.toml / Package.swift are intentionally excluded: a Rust crate or Swift
 * package cannot take a hard dependency on the npm/PyPI Concordia/Verascore
 * package (different ecosystems), so there is no invariant to enforce there.
 */

import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/** Repo root: server/test/structure/<file> is four levels below it. */
export const REPO_ROOT = join(
  fileURLToPath(import.meta.url),
  "..",
  "..",
  "..",
  "..",
);

/** Text-ish extensions scanned inside the public subtrees. */
const TEXT_EXT: ReadonlySet<string> = new Set([
  "md",
  "markdown",
  "html",
  "htm",
  "css",
  "txt",
  "json",
  "yml",
  "yaml",
]);

/**
 * Public root documents (exact names or a leading-name regex). README* and
 * CHANGELOG* are matched by prefix (e.g. README.md, CHANGELOG.md); the rest are
 * exact filenames that genuinely render to users / readers.
 */
const ROOT_DOC_PREFIX = /^(README|CHANGELOG)/i;
const ROOT_DOC_EXACT: ReadonlySet<string> = new Set([
  "ROADMAP.md",
  "SANCTUARY_ARCHITECTURE.md",
  "sanctuary_framework.md",
  // community/governance/legal docs that render publicly (GitHub, npm)
  "CONTRIBUTING.md",
  "CODE_OF_CONDUCT.md",
  "GOVERNANCE.md",
  "LICENSE",
  "ASSURANCE_MATRIX.md",
  // the security policy GitHub renders on the Security tab — public-facing,
  // so the no-CIMC + no-em-dash guards must cover it too.
  "SECURITY.md",
]);

/**
 * Public subtrees scanned for text-ish files (repo-relative dir prefixes).
 * `plugin/` is in scope because the whole plugin (manifest, .mcp.json, README,
 * and the published skills SKILL.md docs) is host-rendered; the TEXT_EXT filter
 * keeps it to the text-ish files.
 */
const PUBLIC_SUBTREES: ReadonlyArray<string> = [
  "docs/",
  "announcements/",
  "examples/",
  "quickstart/",
  "rfcs/",
  "plugin/",
  // public product components shipped in this repo (READMEs + their docs):
  "integrations/",
  "menubar/",
  "castle-wall-daemon/",
  "castle-wall-macos/",
  "castle-wall-vmm/",
  // served console/attestation assets + shipped agent-template bundles:
  "server/public/",
  "server/src/templates/",
  "server/rfcs/", // public RFC documents under the server package
  // operator/protocol docs under the server package (DEPLOYMENT, federation
  // spec, runbooks, ...). The internal design-ref mockups are excluded below.
  "server/docs/",
  // public contributor-facing GitHub issue forms (NOT the internal workflows):
  ".github/ISSUE_TEMPLATE/",
];

/**
 * Subtrees carved OUT of an otherwise-in-scope PUBLIC_SUBTREES prefix. Today:
 * the internal design-ref mockups under server/docs/ (JSX/CSS prototypes +
 * sprint notes that legitimately carry an internal "No CIMC attribution" note).
 */
const EXCLUDED_SUBTREES: ReadonlyArray<string> = ["server/docs/design-refs/"];

/**
 * Explicit package-metadata files that are public-facing (npm registry
 * metadata) but do not live under a public subtree. `server/README.md` is added
 * because server/package.json ships it in the npm tarball (`files: [README.md]`)
 * — it is the page shown on the npm package listing.
 */
const PACKAGE_AND_MANIFEST: ReadonlyArray<string> = [
  "package.json",
  "server/package.json",
  "server/README.md",
  // server/package.json ships LICENSE in its `files`; it is on the npm listing.
  "server/LICENSE",
  // other tracked public-facing docs that are not under a public subtree:
  "server/src/README.md",
  "server/electron/README.md",
  ".github/RELEASING.md",
  // the Concordia sidecar README is especially in scope — the no-CIMC rule
  // names Concordia, and this is the most likely place a stray ref would land.
  "sidecars/concordia/README.md",
];

/**
 * Served-asset subtrees whose .js (and .css) are ALSO public-facing (they render
 * in the user's browser, so a UI string there is a public artifact). For these
 * we widen the extension set beyond TEXT_EXT to include served code.
 */
const SERVED_ASSET_SUBTREES: ReadonlyArray<string> = ["server/public/"];
const SERVED_ASSET_EXT: ReadonlySet<string> = new Set([...TEXT_EXT, "js"]);

function ext(p: string): string {
  const i = p.lastIndexOf(".");
  return i < 0 ? "" : p.slice(i + 1).toLowerCase();
}

/**
 * All repo-relative paths tracked by git, forward-slashed. Enumerating the
 * COMMITTED tree (not a raw readdir) is what makes the guards immune to
 * untracked local/CI noise.
 */
function trackedPaths(): string[] {
  const out = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return out
    .split("\0")
    .filter((p) => p.length > 0)
    .map((p) => p.replace(/\\/g, "/"));
}

function isTopLevel(rel: string): boolean {
  return !rel.includes("/");
}

/**
 * The public-facing DOC/TEXT/METADATA surface as repo-relative paths, sorted.
 * Used identically by the attribution and em-dash guards. Does NOT include
 * server/src (see `serverSrcTrackedTs`).
 */
export function publicFacingRelPaths(): string[] {
  const tracked = trackedPaths();
  const manifestSet = new Set(PACKAGE_AND_MANIFEST);
  const surface = new Set<string>();

  for (const rel of tracked) {
    // carve-outs (internal subtrees nested inside a public prefix) win first
    if (EXCLUDED_SUBTREES.some((d) => rel.startsWith(d))) continue;
    // public root docs
    if (isTopLevel(rel)) {
      const name = rel;
      if (ROOT_DOC_PREFIX.test(name) || ROOT_DOC_EXACT.has(name)) {
        surface.add(rel);
        continue;
      }
    }
    // served-asset subtrees: text-ish PLUS served .js (public UI strings)
    if (
      SERVED_ASSET_SUBTREES.some((d) => rel.startsWith(d)) &&
      SERVED_ASSET_EXT.has(ext(rel))
    ) {
      surface.add(rel);
      continue;
    }
    // public text subtrees (text-ish extensions only)
    if (PUBLIC_SUBTREES.some((d) => rel.startsWith(d)) && TEXT_EXT.has(ext(rel))) {
      surface.add(rel);
      continue;
    }
    // explicit package metadata + plugin manifest
    if (manifestSet.has(rel)) {
      surface.add(rel);
    }
  }

  return [...surface].sort();
}

/**
 * Public EXAMPLE/SCRIPT code (.py, .sh) under the public subtrees — e.g.
 * integrations/.../examples/*.py. These are public software artifacts: a CIMC
 * attribution in a published example is a rule violation. Used by the NO-CIMC
 * guard only (the no-em-dash ratchet deliberately does not pull these in — see
 * em-dash.test.ts on the typography scope line). No baseline, so a pure
 * substring scan adds them cheaply.
 */
const PUBLIC_EXAMPLE_CODE_EXT: ReadonlySet<string> = new Set(["py", "sh"]);
/** Extensionless Pages-site files (e.g. docs/CNAME) are public too. */
function isExtensionlessPagesFile(rel: string): boolean {
  return rel.startsWith("docs/") && ext(rel) === "" && !rel.endsWith("/");
}
export function publicExampleCodeFiles(): string[] {
  return trackedPaths()
    .filter(
      (rel) =>
        (PUBLIC_SUBTREES.some((d) => rel.startsWith(d)) &&
          PUBLIC_EXAMPLE_CODE_EXT.has(ext(rel))) ||
        isExtensionlessPagesFile(rel),
    )
    .sort();
}

/**
 * First-party NON-JS source: the Rust (castle-wall daemon, tauri) and Swift
 * (castle-wall macOS app) components shipped in this repo. Used by the NO-CIMC
 * guard only — a CIMC attribution in a shipped .rs/.swift file is a public
 * software-artifact violation. The no-em-dash ratchet deliberately does not
 * cover these (typography scope; see em-dash.test.ts). No baseline -> cheap
 * substring scan.
 */
const NON_JS_SOURCE_EXT: ReadonlySet<string> = new Set(["rs", "swift"]);
export function firstPartyNonJsSourceFiles(): string[] {
  return trackedPaths()
    .filter((rel) => NON_JS_SOURCE_EXT.has(ext(rel)))
    .sort();
}

/**
 * Absolute paths for the doc/text/metadata public surface. Convenience wrapper
 * around {@link publicFacingRelPaths} for guards that read files directly.
 */
export function publicFacingFiles(): string[] {
  return publicFacingRelPaths().map((rel) => join(REPO_ROOT, rel));
}

/**
 * Module-source extensions under server/src that guards scan. Covers every
 * JS/TS form a `import`/`require` (and CIMC-in-strings) could live in, so adding
 * a `.mjs`/`.cjs`/`.js`/`.tsx` file later cannot silently escape the guards.
 * (Today server/src is .ts-only, so this is count-neutral; it is future-proofing
 * against a real false-green.)
 */
const SERVER_SRC_CODE_EXT: ReadonlySet<string> = new Set([
  "ts",
  "tsx",
  "mts",
  "cts",
  "js",
  "jsx",
  "mjs",
  "cjs",
]);

/** True if a repo-relative path is a server/src JS/TS module-source file. */
export function isServerSrcCode(rel: string): boolean {
  return rel.startsWith("server/src/") && SERVER_SRC_CODE_EXT.has(ext(rel));
}

/**
 * First-party Sanctuary source roots (repo-relative dir prefixes) whose JS/TS
 * code the non-dependency guard scans for Concordia/Verascore imports. Beyond
 * the server package, these are the other first-party code trees that ship or
 * run: the quickstart CLI, the menubar app, and the build/dev scripts. A
 * relative import from any of them that escapes into a Concordia/Verascore tree
 * is just as much a hard-dependency break as one from server/src.
 */
export const FIRST_PARTY_SOURCE_ROOTS: ReadonlyArray<string> = [
  "server/src/",
  "server/scripts/",
  "server/examples/",
  "server/electron/",
  "quickstart/",
  "menubar/",
  "scripts/",
  ".github/scripts/",
];

/**
 * First-party JS/TS files NOT under a source root — the build/test/lint config
 * at the server package root, which `npm run build`/`test`/`lint` execute. A
 * Concordia import here is a real first-party dependency too. Matched by an
 * exact-suffix test so only the config files (not arbitrary server/*.ts) qualify.
 */
const FIRST_PARTY_CONFIG_SUFFIXES: ReadonlyArray<string> = [
  "server/tsup.config.ts",
  "server/vitest.config.ts",
  "server/playwright.config.ts",
  "server/eslint.config.js",
  "server/eslint.config.mjs",
  "server/eslint.config.cjs",
];

/** True if a repo-relative path is a first-party JS/TS module-source file. */
export function isFirstPartySourceCode(rel: string): boolean {
  if (
    SERVER_SRC_CODE_EXT.has(ext(rel)) &&
    FIRST_PARTY_SOURCE_ROOTS.some((root) => rel.startsWith(root))
  ) {
    return true;
  }
  return FIRST_PARTY_CONFIG_SUFFIXES.includes(rel);
}

/**
 * Every tracked first-party JS/TS module-source file (repo-relative, sorted),
 * across all FIRST_PARTY_SOURCE_ROOTS. Used by the non-dependency guard so a
 * Concordia/Verascore import outside server/src (e.g. from menubar/ or
 * quickstart/) is also caught.
 */
export function firstPartySourceFiles(): string[] {
  return trackedPaths().filter(isFirstPartySourceCode).sort();
}

/**
 * Every tracked JS/TS module-source file under server/src (repo-relative,
 * sorted). The attribution guard scans these whole (CIMC is forbidden in
 * comments too); the em-dash guard scans them comment-stripped (the no-em-dash
 * rule exempts code comments). Each guard decides; this just enumerates the
 * tracked set. Name kept (`...Ts`) for callers; the set is now all module exts.
 */
export function serverSrcTrackedTs(): string[] {
  return trackedPaths().filter(isServerSrcCode).sort();
}

/**
 * Strip JS/TS comments so a source file is scanned for em-dashes in EXECUTABLE
 * code / STRING LITERALS only (the no-em-dash rule exempts code comments but
 * NOT user-visible strings). Shared here so em-dash.test.ts and
 * gen-em-dash-baseline.ts always use the same strip (or they drift the
 * baseline).
 *
 * PARSER-BACKED, NOT SCANNER-BACKED (guard-integrity fix round 2, registry row
 * `sanctuary-structure-guard-stripcodecomments-desync`): a first attempt at
 * this function drove the raw TypeScript SCANNER token-by-token and tracked
 * template-interpolation brace depth by hand so it could tell a real
 * `CloseBraceToken` apart from the `}` that closes a `` ${...} `` interpolation.
 * That is unsound in general: whether a `/` starts a RegExpLiteral or a
 * division operator is a GRAMMAR fact (it depends on what kind of token can
 * legally precede it), not something a context-free scanner can always get
 * right by counting braces. A template interpolation containing a regex
 * literal with an unmatched brace --
 * `` const x = `a${/{/.test(s)} // tail—`; `` -- desynced the hand-rolled
 * brace counter: the scanner read the regex's `{` as an ordinary
 * `OpenBraceToken`, so the real interpolation-closing `}` looked like it still
 * had one more nested brace to close, and the template's tail (real STRING
 * content, including a genuine em-dash after what merely LOOKS like `//`) got
 * re-lexed as bare code and stripped as a comment. No amount of additional
 * brace-tracking closes this class of bug, because the scanner alone never
 * has enough context to disambiguate regex-vs-division; only a real parser
 * does.
 *
 * So this function now hands the source to `ts.createSourceFile` -- the same
 * parser TypeScript itself uses -- and asks it, via `node.getChildren()`,
 * which byte ranges are COMMENT TRIVIA. The parser resolves every regex vs.
 * division, template head/middle/tail, and nested-brace ambiguity correctly by
 * construction (that is its actual job), so a comment range this function
 * receives can never overlap a string, template, or regex literal: those are
 * each a single token in the parser's output, and a "comment range" is by
 * definition a span of TRIVIA the parser found strictly BETWEEN two tokens,
 * never inside one. Concretely, walking `getChildren()` down to every leaf
 * token and collecting `ts.getLeadingCommentRanges` at each token's full start
 * (`node.pos`, which includes leading trivia) plus `ts.getTrailingCommentRanges`
 * at each token's end covers every comment in the file exactly once (the two
 * calls overlap on same-line trailing comments; ranges are deduped by exact
 * [pos, end) so nothing is double-counted). Walking all the way to
 * `sourceFile.endOfFileToken` (also a real child token) catches a dangling
 * comment with no following statement. Only the identified comment ranges are
 * blanked -- same-length, newline-preserving, exactly as the prior
 * implementation did -- so line numbers survive and every character of every
 * string/template/regex literal is guaranteed to pass through untouched. If
 * this function ever under-collects a genuine comment (it should not, but if
 * some exotic trivia shape slips past both calls), the failure mode is a
 * harmless false positive -- a comment em-dash left in place -- never a
 * stripped string/template em-dash; the reverse (over-collecting, i.e. ever
 * treating literal content as a comment) is structurally impossible because
 * ranges come only from the parser's own trivia boundaries.
 *
 * `rel` (optional, repo-relative path) selects the parse `ScriptKind`: `.tsx`/
 * `.jsx` parse as `ts.ScriptKind.TSX` (JSX changes how `<` is tokenized), every
 * other in-scope extension (`.ts`, `.mts`, `.cts`, `.js`, `.mjs`, `.cjs`, and no
 * `rel` at all) parses as `ts.ScriptKind.TS`. Today's first-party source tree
 * has zero `.tsx`/`.jsx` files (verified against `firstPartySourceFiles()`),
 * so this is pure future-proofing against a file extension `isFirstPartySourceCode`
 * already accepts (see `SERVER_SRC_CODE_EXT` above) but no current file uses.
 */
function scriptKindFor(rel: string | undefined): ts.ScriptKind {
  const e = rel ? ext(rel) : "";
  return e === "tsx" || e === "jsx" ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
}

/**
 * Collect every comment's [pos, end) byte range in `sourceFile`, deduped and
 * sorted by position. See the `stripCodeComments` doc comment above for why
 * walking `getChildren()` to every leaf token and combining leading + trailing
 * comment ranges at each token cannot include a string/template/regex byte.
 */
function collectCommentRanges(
  sourceFile: ts.SourceFile,
): Array<{ pos: number; end: number }> {
  const text = sourceFile.text;
  const seen = new Set<string>();
  const ranges: Array<{ pos: number; end: number }> = [];

  function add(rs: ts.CommentRange[] | undefined): void {
    if (!rs) return;
    for (const r of rs) {
      const key = `${r.pos}:${r.end}`;
      if (!seen.has(key)) {
        seen.add(key);
        ranges.push({ pos: r.pos, end: r.end });
      }
    }
  }

  function visit(node: ts.Node): void {
    add(ts.getLeadingCommentRanges(text, node.pos));
    add(ts.getTrailingCommentRanges(text, node.end));
    node.getChildren(sourceFile).forEach(visit);
  }

  visit(sourceFile);
  return ranges.sort((a, b) => a.pos - b.pos);
}

export function stripCodeComments(source: string, rel?: string): string {
  const sourceFile = ts.createSourceFile(
    rel ?? "source.ts",
    source,
    ts.ScriptTarget.Latest,
    /*setParentNodes*/ true,
    scriptKindFor(rel),
  );
  const ranges = collectCommentRanges(sourceFile);

  let out = source;
  // Blank ranges back-to-front so earlier offsets stay valid as we splice.
  for (let i = ranges.length - 1; i >= 0; i--) {
    const { pos, end } = ranges[i];
    // Replace the comment with newlines only, so line structure (and any
    // error line numbers) is preserved without keeping comment-resident
    // em-dashes -- identical blanking behavior to the prior implementation.
    const blanked = source.slice(pos, end).replace(/[^\n]/g, "");
    out = out.slice(0, pos) + blanked + out.slice(end);
  }
  return out;
}
