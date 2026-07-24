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
 * NOT user-visible strings). Uses the TypeScript SCANNER, not a regex: a regex
 * stripper would wrongly delete `//` or `/* *\/` sequences that appear INSIDE a
 * string literal (e.g. `const m = "status // bad — visible"`), hiding a real
 * user-visible em-dash. The scanner tokenises correctly, so such a `//` is part
 * of the string token and is preserved. Shared here so em-dash.test.ts and
 * gen-em-dash-baseline.ts always use the same strip (or they drift the baseline).
 *
 * TEMPLATE-LITERAL CONTINUATION (guard-integrity fix, registry row
 * `sanctuary-structure-guard-stripcodecomments-desync`): the plain scanner
 * does NOT continue a template literal past an interpolation on its own. After
 * a `TemplateHead` (`` `...${ ``) `scan()` reads the interpolation expression's
 * tokens, but the `}` that closes it is returned as an ordinary
 * `CloseBraceToken` -- getting the `TemplateMiddle` (`` }...${ ``) or
 * `TemplateTail` (`` }...` ``) that actually follows requires calling
 * `scanner.reScanTemplateToken()` AT that `}`. Without it, everything after
 * the `}` is re-lexed as if it were ordinary code, so a `//` or `/* *\/`
 * sequence that is really user-visible STRING content in the template's tail
 * gets mis-tokenized as a comment and stripped (hiding a real em-dash or a
 * CIMC mention), and/or a later genuine comment can be missed entirely once
 * the scanner has drifted out of sync with the true token stream.
 *
 * `templateDepths` tracks, for each currently-open interpolation, how many
 * ordinary `{`/`}` pairs are nested inside its expression (a STACK, not a
 * single flag, because a template can nest inside its own interpolation, e.g.
 * `` `a${`b${c}d`}e` ``). On `TemplateHead` a new counter starts at 0. Inside
 * an interpolation, `{` increments the top counter and `}` decrements it --
 * that is a real nested brace (an object literal, a block, ...). Only when a
 * `}` would take the top counter BELOW 0 does it actually close the `${`; at
 * that point we call `reScanTemplateToken` instead of accepting the
 * `CloseBraceToken`, and keep its text verbatim (it is template string
 * content, never a comment, no matter what it looks like). A `TemplateTail`
 * result pops the counter (the template is fully closed); a `TemplateMiddle`
 * result means the same interpolation position reopens a new `${`, so the
 * counter resets to 0 rather than popping.
 */
export function stripCodeComments(source: string): string {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    /*skipTrivia*/ false,
    ts.LanguageVariant.Standard,
    source,
  );
  let out = "";
  // One entry per currently-open template interpolation (`${`); see the
  // doc comment above for what each counter tracks.
  const templateDepths: number[] = [];
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (
      token === ts.SyntaxKind.CloseBraceToken &&
      templateDepths.length > 0 &&
      templateDepths[templateDepths.length - 1] === 0
    ) {
      // This `}` closes a template interpolation, not an ordinary brace --
      // re-read from here as the TemplateMiddle/TemplateTail that follows.
      token = scanner.reScanTemplateToken(/*isTaggedTemplate*/ false);
      out += scanner.getTokenText();
      if (token === ts.SyntaxKind.TemplateTail) {
        templateDepths.pop();
      } else {
        // TemplateMiddle: this interpolation is done, but its `${` reopens
        // a fresh one at the same stack position.
        templateDepths[templateDepths.length - 1] = 0;
      }
      token = scanner.scan();
      continue;
    }

    if (
      token !== ts.SyntaxKind.SingleLineCommentTrivia &&
      token !== ts.SyntaxKind.MultiLineCommentTrivia
    ) {
      // keep the raw text of every non-comment token (incl. whitespace/strings)
      out += scanner.getTokenText();
    } else {
      // replace the comment with newlines so line structure (and any error
      // line numbers) is preserved without keeping comment-resident em-dashes.
      out += scanner.getTokenText().replace(/[^\n]/g, "");
    }

    if (token === ts.SyntaxKind.TemplateHead) {
      templateDepths.push(0);
    } else if (
      token === ts.SyntaxKind.OpenBraceToken &&
      templateDepths.length > 0
    ) {
      templateDepths[templateDepths.length - 1]++;
    } else if (
      token === ts.SyntaxKind.CloseBraceToken &&
      templateDepths.length > 0
    ) {
      templateDepths[templateDepths.length - 1]--;
    }

    token = scanner.scan();
  }
  return out;
}
