/**
 * Generates `src/dashboard/design-fonts.ts` (the `CONSOLE_FONT_FACE_CSS`
 * constant) from the subsetted woff2 files in `assets/fonts/`.
 *
 *   node scripts/build-design-fonts.mjs           write the module
 *   node scripts/build-design-fonts.mjs --check   exit 1 if the committed module
 *                                                 or any font file has drifted
 *
 *   Re-cutting a subset (only when UNICODE_RANGE or a pinned source changes),
 *   in a scratch virtualenv with fonttools 4.55.3 and brotli 1.2.0 (brotli is
 *   the woff2 encoder, so its version decides the output bytes; Python 3.9.6):
 *
 *   pyftsubset <source>.ttf --unicodes="<UNICODE_RANGE>" --flavor=woff2 \
 *     --no-hinting --desubroutinize --layout-features+=tnum,case \
 *     --name-IDs=0,1,2,3,4,5,6,13,14 --output-file=assets/fonts/<file>
 *
 *   then update that face's subsetSha256 below and run this script. With
 *   those versions the command reproduces every committed subset byte for
 *   byte (checked 2026-10-12 against all three subsetSha256 pins). Failure
 *   mode: a different brotli can write a valid but different woff2, so the
 *   sha256 moves with no visible change; the subset hash below, not the
 *   command, is the authority for what ships.
 *
 * Why generated: the console is a single HTML document served by the local
 * server, and it must never fetch a face from a third-party origin, so each
 * face rides inline as a base64 data URI. Hand-pasting the base64 is how a
 * truncated or mismatched face ships; this script is the only writer, and
 * `test/structure/console-design-fonts.test.ts` re-derives the module from
 * the committed woff2 files on every run.
 *
 * Size. Per PAGE: 105,928 bytes of base64 (the three subsets total 79,440
 * bytes; base64 writes 4 bytes per 3, per face), 107,059 bytes of @font-face
 * CSS in every page that interpolates the constant. Per PACKAGE: tsup builds
 * with splitting off, so each bundle that reaches the dashboard carries its
 * own copy. Measured on the 2026-10-12 build: `dist/cli.js`, `dist/cli.cjs`,
 * `dist/index.js` and `dist/index.cjs` each embed it once, and each of their
 * four source maps carries it again in sourcesContent, so the npm package
 * holds eight copies, 847,424 bytes of base64 in all (unpacked size).
 *
 * Provenance. Each face was fetched from its upstream repository at the pinned
 * ref below into an empty scratch directory (nothing was executed from it), its
 * sha256 checked against its sourceSha256, then subset offline with the command
 * in the usage block above.
 *
 * Cross-file pin: `build-design-fonts.d.mts` declares the type surface of this
 * file's exports (UNICODE_RANGE, FACES and renderModule) for the structure
 * test; an export added, removed or reshaped here must be changed there too.
 *
 * The wght axis is kept whole (variable faces), so every weight a template asks
 * for resolves without a second file. Name IDs 0, 13 and 14 keep the copyright
 * and license notice inside each subset, as the SIL Open Font License asks of a
 * modified version. The license text for each face sits beside its woff2 in
 * `assets/fonts/` and is reproduced in THIRD_PARTY_NOTICES.md, which ships in
 * the npm package.
 *
 * Failure mode: a woff2 replaced without re-running this script leaves the
 * module embedding the old bytes; `--check` and the structural test both fail
 * on the sha256 mismatch. A subset that drops a glyph the console uses does not
 * fail anything: the browser falls back to the system stack for that one
 * character, so add the code point to UNICODE_RANGE and re-subset.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const FONT_DIR = join(SERVER_DIR, "assets", "fonts");
const OUT_FILE = join(SERVER_DIR, "src", "dashboard", "design-fonts.ts");

/**
 * Latin (U+0000-00FF plus the typographic punctuation block U+2000-206F and
 * Google's latin extras), the arrows U+2190-2193, and the shapes U+25B6,
 * U+25BC, U+25C6, U+25C7, U+25CF. Manrope and Space Grotesk carry the arrows;
 * Roboto Mono does not. None of the three faces carries any of those shapes,
 * nor the four status-pill glyphs in STATUS_PILL_CSS (U+25B2, U+2B22, U+25CB,
 * U+25CC; checked against each pinned source's cmap on 2026-10-12), so every
 * shape renders from the system stack. Adding a code point no face carries
 * changes no subset byte, which is why the status glyphs are not listed. A
 * code point a face lacks falls back per character, never per word:
 * unicode-range only narrows which characters a face is considered for, and
 * the cmap still decides, so a listed shape no face carries draws from the
 * system stack exactly as it would unlisted (confirmed by render on
 * 2026-10-12: the committed CSS and the same CSS with the shapes and arrows
 * trimmed from every range draw every shape identically, with no .notdef).
 * Which system face the browser picks for a shape can differ from the
 * no-web-font page (Chrome drew two diamonds from another fallback once a
 * web font was the primary face); that follows from bundling any face at
 * all, not from the range.
 * Must match the --unicodes argument used to cut the committed woff2 files.
 */
export const UNICODE_RANGE =
  "U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, " +
  "U+2000-206F, U+2074, U+20AC, U+2122, U+2190-2193, U+2212, U+2215, " +
  "U+25B6, U+25BC, U+25C6, U+25C7, U+25CF, U+FEFF, U+FFFD";

export const FACES = [
  {
    family: "Manrope",
    file: "Manrope-wght.latin.woff2",
    license: "Manrope-OFL.txt",
    // The variable face's full wght axis (fvar 200..800).
    weight: "200 800",
    upstream: "https://github.com/googlefonts/manrope",
    // Upstream publishes no release tag; this is the commit Google Fonts
    // records as the source of its shipped Manrope[wght].ttf.
    ref: "6f81ebecdf65e4463b798cc07b16a4f8d5216917",
    sourcePath: "fonts/variable/Manrope[wght].ttf",
    sourceSha256: "d0639be45d0af36e798172419d7bd173c4bd4f29e2b76cbb69db1d11bf8b0a40",
    subsetSha256: "cd456782441247b5ea2648cbabea22a864dbf4bc179c2c136c643587114bc6bb",
  },
  {
    family: "Space Grotesk",
    file: "SpaceGrotesk-wght.latin.woff2",
    license: "SpaceGrotesk-OFL.txt",
    // fvar 300..700.
    weight: "300 700",
    upstream: "https://github.com/floriankarsten/space-grotesk",
    ref: "2.0.0",
    sourcePath: "fonts/ttf/SpaceGrotesk[wght].ttf",
    sourceSha256: "acad6de1fc93436f5c0f1f4137751ef04f1aea3063e7036535970ffcfbd79f72",
    subsetSha256: "6ecbae53c7a459eeb68880f39264e8bbc4daa5ac2e462933578661f8cdad4c7f",
  },
  {
    family: "Roboto Mono",
    file: "RobotoMono-wght.latin.woff2",
    license: "RobotoMono-OFL.txt",
    // fvar 100..700.
    weight: "100 700",
    upstream: "https://github.com/googlefonts/RobotoMono",
    ref: "v3.001",
    sourcePath: "fonts/variable/RobotoMono[wght].ttf",
    sourceSha256: "66a80e79d17e4c7cabd162e2916578a4cc08fd19eef6e2a643305eae9c567b2b",
    subsetSha256: "f8372c0e4704147a435cb078ca9af3e80ef90cdfe50f08673968a17ed6cda621",
  },
];

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export function renderModule() {
  const rules = [];
  for (const face of FACES) {
    const bytes = readFileSync(join(FONT_DIR, face.file));
    const actual = sha256(bytes);
    if (actual !== face.subsetSha256) {
      throw new Error(
        `${face.file}: sha256 ${actual} does not match the pinned ${face.subsetSha256}`,
      );
    }
    rules.push(
      [
        "@font-face {",
        `  font-family: "${face.family}";`,
        "  font-style: normal;",
        `  font-weight: ${face.weight};`,
        "  font-display: swap;",
        `  src: url("data:font/woff2;base64,${bytes.toString("base64")}") format("woff2");`,
        `  unicode-range: ${UNICODE_RANGE};`,
        "}",
      ].join("\n"),
    );
  }
  return `// GENERATED by scripts/build-design-fonts.mjs from assets/fonts/*.woff2. Do not edit by hand;
// edit the script or the font files and re-run it. Provenance (upstream, pinned ref, sha256 of the
// source and of each subset) is recorded in the script and in THIRD_PARTY_NOTICES.md.

/**
 * The three console faces as inline \`@font-face\` rules: Manrope (interface
 * text, \`--sans\`), Space Grotesk (headings and big numerals, \`--display\`,
 * which \`--serif\` aliases), and Roboto Mono (machine-produced values,
 * \`--mono\`). Each is a Latin subset of the upstream variable face, embedded
 * as a base64 woff2 data URI. All three are licensed under the SIL Open Font
 * License 1.1; the notices are in THIRD_PARTY_NOTICES.md.
 *
 * Embedded, never fetched: the console is served by the local server and must
 * not reach a third-party font origin, which would both leak that the console
 * was opened and make its type depend on the network. A page that serves a
 * Content-Security-Policy must therefore allow \`data:\` fonts. The mobile
 * companion does, with \`font-src 'self' data:\` (MOBILE_COMPANION_CSP in
 * mobile.ts); its \`'self'\` source admits a same-origin font URL the page
 * never uses.
 *
 * Interpolated verbatim, next to \`PAPER_INK_ROOT_TOKENS_CSS\`, into the inline
 * \`<style>\` of every page that interpolates the tokens (the consumer list is in
 * design-tokens.ts). A page that omits it still renders: each token stack names
 * the system faces after the bundled one.
 */
export const CONSOLE_FONT_FACE_CSS = ${JSON.stringify(rules.join("\n"))};
`;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const rendered = renderModule();
  if (process.argv.includes("--check")) {
    const committed = readFileSync(OUT_FILE, "utf8");
    if (committed !== rendered) {
      console.error(
        "build-design-fonts: src/dashboard/design-fonts.ts is stale; run node scripts/build-design-fonts.mjs",
      );
      process.exit(1);
    }
    console.log("build-design-fonts: design-fonts.ts matches assets/fonts");
  } else {
    writeFileSync(OUT_FILE, rendered);
    console.log(`build-design-fonts: wrote ${OUT_FILE}`);
  }
}
