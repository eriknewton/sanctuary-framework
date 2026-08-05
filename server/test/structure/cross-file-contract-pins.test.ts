/**
 * Cross-file contract pin reconciliation guard.
 *
 * AGENTS.md ("Prose hygiene", adopted 2026-08-04) requires that wherever two
 * files must agree on a value, EACH side carries a "must match `<name>` in
 * `<file>`" comment. This file is the gate those comments describe, modeled on
 * hkdf-registry-reconciliation.test.ts and design-token-mirror-reconciliation
 * .test.ts: the mechanical scan is the authority; the prose is the index.
 *
 * WHY A TEST AND NOT JUST THE COMMENTS: the contracts covered here are
 * duplicated because one side cannot import the other without dragging in a
 * dependency it must not have (an offline verifier pulling the crypto runtime,
 * a type module tripping the cycle gate) or because the two sides are separate
 * language builds. Nothing makes the copies agree, and a drifted copy never
 * fails to compile. It fails LATER, as a signature mismatch on a valid chain
 * or an enforcer that refuses every frame, which reads as tampering or as a
 * broken install rather than as a stale mirror.
 *
 * FOUR KINDS OF ASSERTION, and the difference matters:
 *
 *   1. SOLE-DECLARATION. A frozen wire string that HAS a canonical exported
 *      constant must not be re-typed as a literal anywhere else in server/src.
 *      This scans EVERY .ts file under server/src, not a hand-listed set, with
 *      an explicit allowlist for the places a bare literal is legitimate
 *      (operator-visible help text). An unlisted occurrence fails.
 *   2. DECLARED-VALUE EQUALITY. For each mirrored pair, the test extracts the
 *      value from the NAMED declaration on each side and compares the parsed
 *      values, rather than asking whether a literal appears somewhere in the
 *      file. Presence-only checking would pass a one-sided change to a schema
 *      version while the string constants stayed put.
 *   3. DUPLICATED-FUNCTION EQUALITY. Where a whole function is hand-copied
 *      (`canonicalJson`), the two bodies are compared after whitespace
 *      normalization.
 *   4. PIN PRESENCE. Every duplicating site must NAME its counterpart.
 *
 * WHAT THIS SUITE DOES NOT COVER, stated so no comment elsewhere claims it
 * does: it does not compare the Rust or Swift enforcement LOGIC to the
 * TypeScript, only the declared constants; it does not verify that a mirrored
 * value is semantically correct, only that the copies agree; and it does not
 * cover `/^[0-9a-f]{64}$/`, which is an independent local validator in each of
 * the 10 files that declare it rather than a mirror of one declaration.
 *
 * FAIL-BEFORE (this file is not exempt, and must not be marked exempt).
 * Measured, not assumed, against the pre-PR tree; the counts are in the PR
 * body. The menubar producer/consumer group lives outside `server/src` and
 * therefore survives CI's revert-only-src method; it is kept in its own
 * `describe` block so that gap is legible rather than surprising.
 *
 * If this test fails, reconcile the value or restore the pin in the SAME PR
 * that broke it. Never relax an assertion to make it pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
// test/structure/<this file> -> test/ -> server/ -> repo root. Rust, Swift,
// and menubar sources hang off the repo root, so paths resolve from there.
const SERVER_DIR = join(HERE, "..", "..", "..");
const REPO_ROOT = join(SERVER_DIR, "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

/**
 * Strip line and block comments, so a literal MENTIONED in prose is never
 * counted as a declaration. Works for TypeScript, Rust (including `///` doc
 * comments, which begin with `//`), and Swift.
 *
 * Deliberately conservative: it does not respect string literals containing
 * "//", so a URL inside a string would truncate that line. No file scanned
 * here contains one. The failure direction is safe for the sole-declaration
 * scan, which looks for occurrences: over-stripping can only hide an
 * occurrence, never invent one.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** Every .ts file under server/src, repo-root-relative. */
function allServerSrcFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full, `${prefix}${entry}/`);
      } else if (entry.endsWith(".ts")) {
        out.push(`server/src/${prefix}${entry}`);
      }
    }
  };
  walk(join(SERVER_DIR, "src"), "");
  return out;
}

/**
 * Normalize a declared value so the same value written for three languages
 * compares equal: strips `as const`, `.to_string()`, Rust numeric underscore
 * separators, and surrounding quotes.
 */
function normalizeValue(raw: string): string {
  const value = raw
    .trim()
    .replace(/\s+as\s+const$/, "")
    .replace(/\.to_string\(\)$/, "")
    .trim();
  const quoted =
    /^"((?:[^"\\]|\\.)*)"$/.exec(value) ?? /^'((?:[^'\\]|\\.)*)'$/.exec(value);
  if (quoted) return quoted[1]!;
  if (/^-?[0-9_]+$/.test(value)) return value.replace(/_/g, "");
  return value;
}

/** Extract a TypeScript `const NAME = <value>;` declaration. */
function tsConst(source: string, name: string): string | null {
  const m = new RegExp(
    `(?:export\\s+)?const\\s+${name}(?:\\s*:\\s*[^=]+?)?\\s*=\\s*([^;]+);`
  ).exec(stripComments(source));
  return m ? normalizeValue(m[1]!) : null;
}

/**
 * Extract a Rust `const NAME: T = <value>;` declaration. The type pattern must
 * admit `&str` as well as `u32`/`u64`/`usize`; an extractor that silently
 * returns null for the reference types would make this whole suite pass by
 * comparing nothing, which is the exact failure mode it exists to catch.
 */
function rustConst(source: string, name: string): string | null {
  const m = new RegExp(
    `const\\s+${name}\\s*:\\s*&?\\s*[A-Za-z0-9_]+\\s*=\\s*([^;]+);`
  ).exec(stripComments(source));
  return m ? normalizeValue(m[1]!) : null;
}

/** Extract a Swift `static let name[: T] = <value>` declaration. */
function swiftConst(source: string, name: string): string | null {
  const m = new RegExp(
    `static\\s+let\\s+${name}(?:\\s*:\\s*[A-Za-z0-9_]+)?\\s*=\\s*(.+)`
  ).exec(stripComments(source));
  return m ? normalizeValue(m[1]!.split("\n")[0]!) : null;
}

describe("frozen wire strings have exactly one declaration in server/src", () => {
  /**
   * `allowedElsewhere` lists the files permitted to contain the bare literal
   * despite not declaring it, each with a stated reason. Anything NOT on the
   * list fails: a re-typed copy is how a `.v2` mint ships a half-migrated
   * stream that no error surfaces on either side.
   */
  const soleDeclarations = [
    {
      label: "ENFORCEMENT_EVENT_SCHEMA",
      literal: "sanctuary.enforcement-event.v1",
      declaredIn: "server/src/castle-wall/export/schema.ts",
      allowedElsewhere: {
        // Operator-visible `--help` text inside a template string. It DESCRIBES
        // the stream shape; nothing parses or emits it. A version bump must
        // update this copy in the same PR or the help text lies.
        "server/src/cli/cortex-export.ts": "operator --help text",
      } as Record<string, string>,
      mustReference: ["server/src/castle-wall/export/sink.ts"],
    },
    {
      label: "SIGNATURE_BUNDLE_VERSION",
      literal: "sanctuary.signature-bundle.v1",
      declaredIn: "server/src/core/crypto-suite-registry.ts",
      allowedElsewhere: {} as Record<string, string>,
      mustReference: ["server/src/v1/federation-revocation.ts"],
    },
  ] as const;

  for (const entry of soleDeclarations) {
    it(`${entry.label}: no unlisted file in server/src re-types the literal`, () => {
      const offenders: string[] = [];
      for (const file of allServerSrcFiles()) {
        if (file === entry.declaredIn) continue;
        if (file in entry.allowedElsewhere) continue;
        if (stripComments(read(file)).includes(entry.literal)) offenders.push(file);
      }
      expect(
        offenders,
        `these files re-type "${entry.literal}"; import ${entry.label} from ${entry.declaredIn} instead, or add an allowlist entry with a reason`
      ).toEqual([]);
    });

    it(`${entry.label} is declared exactly once in ${entry.declaredIn}`, () => {
      const declaring = stripComments(read(entry.declaredIn));
      expect(declaring.split(entry.literal).length - 1).toBe(1);
    });

    it(`${entry.label}: every allowlisted file still contains the literal`, () => {
      // An allowlist entry that no longer matches anything is stale and would
      // silently widen the scan's blind spot.
      for (const [file, reason] of Object.entries(entry.allowedElsewhere)) {
        expect(
          stripComments(read(file)).includes(entry.literal),
          `${file} is allowlisted (${reason}) but no longer contains the literal; drop the entry`
        ).toBe(true);
      }
    });

    for (const consumer of entry.mustReference) {
      it(`${consumer} references ${entry.label}`, () => {
        expect(read(consumer).includes(entry.label)).toBe(true);
      });
    }
  }
});

describe("audit chain constants are shared, not mirrored", () => {
  // The four audit-chain wire constants used to be hand-copied into the
  // standalone verifier. They now live in the zero-import module both sides
  // import, so drift is structurally impossible rather than merely watched.
  const SHAPE = "server/src/audit/checkpoint-shape.ts";
  const CHAIN = "server/src/audit/chain.ts";
  const VERIFIER = "server/src/cli/audit-chain-verify.ts";
  const NAMES = [
    "AUDIT_CHAIN_GENESIS",
    "AUDIT_CHAIN_SCHEMA_VERSION",
    "AUDIT_CHECKPOINT_DOMAIN",
    "AUDIT_CHECKPOINT_DOMAIN_PREFIX",
  ];

  it("the zero-import module declares all four", () => {
    const shape = read(SHAPE);
    for (const name of NAMES) {
      expect(new RegExp(`export const ${name}\\s*=`).test(shape), name).toBe(true);
    }
  });

  it("the zero-import module still has zero imports", () => {
    // The whole hoist depends on this. If it ever imports anything, the
    // standalone verifier silently inherits that dependency.
    expect(/^\s*import\s/m.test(stripComments(read(SHAPE)))).toBe(false);
  });

  it("neither chain.ts nor the verifier re-declares them", () => {
    for (const file of [CHAIN, VERIFIER]) {
      const source = stripComments(read(file));
      for (const name of NAMES) {
        expect(
          new RegExp(`const\\s+${name}\\s*=`).test(source),
          `${file} must import ${name}, not re-declare it`
        ).toBe(false);
      }
    }
  });

  it("the verifier imports them from the zero-import module", () => {
    expect(read(VERIFIER)).toContain("audit/checkpoint-shape.js");
  });

  it("the hand-copied canonicalJson bodies are identical", () => {
    // This one function is still duplicated: checkpointSigningBytes needs
    // core/encoding.ts and cannot move to the zero-import module, so
    // canonicalJson stays beside it. Compare the bodies, not just presence.
    const extract = (source: string): string => {
      const start = source.indexOf("function canonicalJson(");
      expect(start).toBeGreaterThan(-1);
      let depth = 0;
      let i = source.indexOf("{", start);
      const from = i;
      for (; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
          depth--;
          if (depth === 0) break;
        }
      }
      return source.slice(from, i + 1).replace(/\s+/g, " ").trim();
    };
    expect(extract(stripComments(read(VERIFIER)))).toBe(
      extract(stripComments(read(CHAIN)))
    );
  });
});

describe("mirrored declarations hold equal values and name their counterpart", () => {
  interface Pair {
    readonly canonicalName: string;
    readonly mirrorName: string;
    /** Override when one side builds its value from another constant. */
    readonly resolveCanonical?: (source: string) => string | null;
    /** Override when the mirror side is a bare literal, not a named const. */
    readonly resolveMirror?: (source: string) => string | null;
  }

  interface MirrorGroup {
    readonly label: string;
    readonly canonical: string;
    readonly mirrors: readonly string[];
    readonly pairs: readonly Pair[];
  }

  const literalPresence =
    (literal: string) =>
    (source: string): string | null =>
      stripComments(source).includes(literal) ? literal : null;

  const SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

  const groups: readonly MirrorGroup[] = [
    {
      label: "transparency checkpoint / offline verifier",
      canonical: "server/src/transparency/checkpoint.ts",
      mirrors: ["server/src/transparency/verify.ts"],
      pairs: [
        {
          canonicalName: "TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION",
          mirrorName: "TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION",
        },
        {
          canonicalName: "TRANSPARENCY_CHECKPOINT_GENESIS",
          mirrorName: "TRANSPARENCY_CHECKPOINT_GENESIS",
        },
        {
          canonicalName: "TRANSPARENCY_BUNDLE_FORMAT",
          mirrorName: "TRANSPARENCY_BUNDLE_FORMAT",
        },
        {
          // checkpoint.ts builds the prefix as `${DOMAIN}\n`; verify.ts spells
          // the whole thing. Resolve the template to compare like with like.
          canonicalName: "TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX",
          mirrorName: "TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX",
          resolveCanonical: (source) => {
            const domain = tsConst(source, "TRANSPARENCY_CHECKPOINT_DOMAIN");
            return domain === null ? null : `${domain}\\n`;
          },
        },
      ],
    },
    {
      label: "transparency anchor / offline anchor verifier",
      canonical: "server/src/transparency/anchor.ts",
      mirrors: ["server/src/transparency/anchor-verify.ts"],
      pairs: [
        {
          canonicalName: "TRANSPARENCY_ANCHOR_SCHEMA_VERSION",
          mirrorName: "ANCHOR_SCHEMA_VERSION",
        },
        {
          canonicalName: "TRANSPARENCY_ANCHOR_COMMITMENT_DOMAIN",
          mirrorName: "ANCHOR_COMMITMENT_DOMAIN",
        },
        {
          // anchor.ts inlines the SPKI prefix inside anchorPublicKeyPem, so
          // neither side can be read as a named const on the producer side.
          canonicalName: "SPKI_P256_PREFIX_HEX (inline in anchorPublicKeyPem)",
          mirrorName: "SPKI_P256_PREFIX_HEX",
          resolveCanonical: literalPresence(SPKI_PREFIX),
          resolveMirror: literalPresence(SPKI_PREFIX),
        },
      ],
    },
    {
      label: "service-account name charset",
      canonical: "server/src/castle-wall/provision/account.ts",
      mirrors: [
        "server/src/egress-gate/harness-daemon.ts",
        "server/src/egress-gate/gate-daemon.ts",
      ],
      pairs: [
        { canonicalName: "SAFE_SERVICE_ACCOUNT_RE", mirrorName: "SAFE_ACCOUNT_RE" },
      ],
    },
    {
      label: "mesh v2 hybrid certificate versions",
      canonical: "server/src/mesh/trust-root-hybrid.ts",
      mirrors: ["server/src/mesh/types.ts"],
      pairs: [
        {
          canonicalName: "FORTRESS_MASTER_KEY_VERSION_V2_HYBRID",
          mirrorName: "(literal type)",
          resolveMirror: literalPresence(
            "sanctuary.fortress-master.v2.hybrid-ed25519-ml-dsa-65"
          ),
        },
        {
          canonicalName: "PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID",
          mirrorName: "(literal type)",
          resolveMirror: literalPresence(
            "sanctuary.principal-cert.v2.hybrid-ed25519-ml-dsa-65"
          ),
        },
        {
          canonicalName: "NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID",
          mirrorName: "(literal type)",
          resolveMirror: literalPresence(
            "sanctuary.node-cert.v2.hybrid-ed25519-ml-dsa-65"
          ),
        },
      ],
    },
  ];

  for (const group of groups) {
    describe(group.label, () => {
      it("every mirrored declaration holds the canonical value", () => {
        const canonicalSource = read(group.canonical);
        for (const pair of group.pairs) {
          const expected = pair.resolveCanonical
            ? pair.resolveCanonical(canonicalSource)
            : tsConst(canonicalSource, pair.canonicalName);
          expect(
            expected,
            `${group.canonical} does not declare ${pair.canonicalName}`
          ).not.toBeNull();

          for (const mirror of group.mirrors) {
            const mirrorSource = read(mirror);
            const actual = pair.resolveMirror
              ? pair.resolveMirror(mirrorSource)
              : tsConst(mirrorSource, pair.mirrorName);
            expect(
              actual,
              `${mirror}: ${pair.mirrorName} should equal ${pair.canonicalName} in ${group.canonical}`
            ).toBe(expected);
          }
        }
      });

      it("each mirror names the canonical file in a comment", () => {
        // Pin comments spell sibling modules without the leading `server/src/`,
        // matching the convention used throughout server/src.
        const canonicalRef = group.canonical.replace(/^server\/src\//, "");
        for (const mirror of group.mirrors) {
          expect(
            read(mirror).includes(canonicalRef),
            `${mirror} must carry a comment naming ${canonicalRef}`
          ).toBe(true);
        }
      });

      it("the canonical file names its mirrors in a comment", () => {
        const canonicalSource = read(group.canonical);
        for (const mirror of group.mirrors) {
          const mirrorRef = mirror.replace(/^server\/src\//, "");
          expect(
            canonicalSource.includes(mirrorRef),
            `${group.canonical} must carry a comment naming ${mirrorRef}`
          ).toBe(true);
        }
      });
    });
  }
});

describe("castle-wall wire constants agree across TypeScript, Rust, and Swift", () => {
  const TS = "server/src/castle-wall/constants.ts";
  const RUST = "castle-wall-daemon/src/lib.rs";
  const SWIFT = "castle-wall-macos/Sources/CastleWallIPC/Constants.swift";

  /** Mirrored in all three languages. Numerics included deliberately. */
  const triLingual: ReadonlyArray<readonly [string, string, string]> = [
    ["CASTLE_WALL_SCHEMA_VERSION_V1", "SCHEMA_VERSION_V1", "schemaVersionV1"],
    ["CASTLE_WALL_AUDIT_LAYER", "AUDIT_LAYER", "auditLayer"],
    ["CASTLE_WALL_SIGNATURE_SCHEME_V1", "SIGNATURE_SCHEME_V1", "signatureSchemeV1"],
    [
      "CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER",
      "IPC_CONTENT_LENGTH_HEADER",
      "ipcContentLengthHeader",
    ],
    ["CASTLE_WALL_IPC_NAMESPACE", "IPC_NAMESPACE", "ipcNamespace"],
    [
      "CASTLE_WALL_REQUEST_ID_NONCE_BYTES",
      "REQUEST_ID_NONCE_BYTES",
      "requestIdNonceBytes",
    ],
  ];

  /** Mirrored in TypeScript and Rust only; Swift has no counterpart. */
  const tsAndRust: ReadonlyArray<readonly [string, string]> = [
    ["CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX", "PRODUCER_SIG_DOMAIN_PREFIX"],
    ["CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1", "PRODUCER_SIG_KEY_ID_V1"],
    ["CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS", "DEFAULT_PROMPT_TIMEOUT_SECONDS"],
    [
      "CASTLE_WALL_DEFAULT_NO_WALL_DURATION_SECONDS",
      "DEFAULT_NO_WALL_DURATION_SECONDS",
    ],
    ["CASTLE_WALL_DEFAULT_WAL_TTL_SECONDS", "DEFAULT_WAL_TTL_SECONDS"],
    ["CASTLE_WALL_DEFAULT_WAL_SIZE_CAP_BYTES", "DEFAULT_WAL_SIZE_CAP_BYTES"],
  ];

  it("every three-way constant holds the same value in all three languages", () => {
    const ts = read(TS);
    const rust = read(RUST);
    const swift = read(SWIFT);
    for (const [tsName, rustName, swiftName] of triLingual) {
      const expected = tsConst(ts, tsName);
      expect(expected, `${TS} does not declare ${tsName}`).not.toBeNull();
      expect(rustConst(rust, rustName), `${RUST}: ${rustName}`).toBe(expected);
      expect(swiftConst(swift, swiftName), `${SWIFT}: ${swiftName}`).toBe(expected);
    }
  });

  it("every TypeScript/Rust constant holds the same value on both sides", () => {
    const ts = read(TS);
    const rust = read(RUST);
    for (const [tsName, rustName] of tsAndRust) {
      const expected = tsConst(ts, tsName);
      expect(expected, `${TS} does not declare ${tsName}`).not.toBeNull();
      expect(rustConst(rust, rustName), `${RUST}: ${rustName}`).toBe(expected);
    }
  });

  it("all three files name the other language's file in a comment", () => {
    const ts = read(TS);
    expect(ts.includes("castle-wall-daemon/src/lib.rs")).toBe(true);
    expect(
      ts.includes("castle-wall-macos/Sources/CastleWallIPC/Constants.swift")
    ).toBe(true);
    expect(read(RUST).includes("server/src/castle-wall/constants.ts")).toBe(true);
    expect(read(SWIFT).includes("server/src/castle-wall/constants.ts")).toBe(true);
  });
});

describe("shared encoding vocabulary is spelled uniformly", () => {
  // Not a two-sided contract: several independently-versioned signed surfaces
  // each declare this encoding name. What must hold is that the SPELLING never
  // forks, because an external verifier reads the name and reconstructs the
  // signing bytes from it. See the note on
  // `AuditCheckpointRecord.payload_encoding` in audit/checkpoint-shape.ts.
  const ENCODING = "domain-separated-canonical-json-v1";
  const surfaces = [
    "server/src/audit/checkpoint-shape.ts",
    "server/src/operational/audit-log.ts",
    "server/src/transparency/checkpoint.ts",
    "server/src/transparency/emitter.ts",
    "server/src/transparency/verify.ts",
    "server/src/cognitive/tools.ts",
    "server/src/workload-lifecycle/host-attestation.ts",
    "server/src/workload-lifecycle/undeclared-finding.ts",
  ];

  it("the enumerated surfaces are exactly the ones that use the name", () => {
    // A surface added later without being listed would sit outside the note in
    // checkpoint-shape.ts, which claims to enumerate them.
    const actual = allServerSrcFiles().filter((file) =>
      stripComments(read(file)).includes(ENCODING)
    );
    expect(actual.sort()).toEqual([...surfaces].sort());
  });

  it("the enumerating note lives in audit/checkpoint-shape.ts", () => {
    const shape = read("server/src/audit/checkpoint-shape.ts");
    expect(shape).toContain("SHARED VOCABULARY");
    for (const file of surfaces) {
      if (file === "server/src/audit/checkpoint-shape.ts") continue;
      const ref = file.replace(/^server\/src\//, "");
      expect(shape.includes(ref), `checkpoint-shape.ts should name ${ref}`).toBe(true);
    }
  });
});

describe("menubar status classes: dynamic producer, static consumer", () => {
  // Lives outside server/src, so CI's fail-before revert (which reverts only
  // server/src) leaves these assertions passing. That is expected; the
  // server/src groups above carry the fail-before weight.
  const PRODUCER = "menubar/src/popover/popover.ts";
  const CSS = "menubar/src/styles/popover.css";
  const CLIENT = "menubar/src/api/client.ts";

  it("the CSS names its runtime producer", () => {
    const css = read(CSS);
    expect(css).toContain("menubar/src/popover/popover.ts");
    expect(css).toContain("menubar/src/api/client.ts");
  });

  it("the producer names the CSS it drives", () => {
    expect(read(PRODUCER)).toContain("menubar/src/styles/popover.css");
  });

  it("every non-connected union member has a CSS rule", () => {
    const union = /connection_status:\s*([^;]+);/.exec(read(CLIENT));
    expect(union, "connection_status union not found in client.ts").not.toBeNull();
    const members = [...union![1]!.matchAll(/'([a-z-]+)'/g)].map((m) => m[1]!);
    expect(members).toContain("connected");
    const css = read(CSS);
    for (const member of members) {
      if (member === "connected") continue; // base .status-dot colour IS connected
      expect(
        css.includes(`.status-${member} `),
        `${CSS} has no rule for .status-${member}, which the producer can emit`
      ).toBe(true);
    }
  });
});
