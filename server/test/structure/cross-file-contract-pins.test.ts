/**
 * Cross-file contract pin reconciliation guard.
 *
 * AGENTS.md ("Prose hygiene", adopted 2026-08-04) requires that wherever two
 * files must agree on a value, EACH side carries a "must match `<name>` in
 * `<file>`" comment. This file is the gate those comments describe, modeled on
 * hkdf-registry-reconciliation.test.ts and design-token-mirror-reconciliation
 * .test.ts: the mechanical scan is the authority; the prose is the index.
 *
 * WHY A TEST AND NOT JUST THE COMMENTS: every contract covered here is
 * duplicated on purpose, because one side of it is a module with a documented
 * no-imports property (an offline standalone verifier, a zero-dependency shape
 * module, a separate-language build). Nothing in the build makes the copies
 * agree, and a drifted copy never fails to compile. It fails LATER, as a
 * signature mismatch on a valid chain or an enforcer that refuses every frame,
 * which reads as tampering or as a broken install rather than as a stale
 * mirror.
 *
 * THREE KINDS OF ASSERTION HERE, and the difference matters:
 *
 *   1. SOLE-DECLARATION. A frozen wire string that HAS a canonical exported
 *      constant must not be re-typed as a literal anywhere else in server/src.
 *      Both of these failed against unmodified main (`sink.ts` re-typed the
 *      enforcement-event schema; `federation-revocation.ts` re-typed the
 *      signature-bundle version twice); this PR replaced those literals with
 *      the imported constant.
 *   2. VALUE PARITY. Where the duplication cannot be removed, every copy must
 *      spell the same value. This half describes an invariant that already
 *      held on main; it is the tripwire for the future.
 *   3. PIN PRESENCE. Every duplicating site must NAME its counterpart. This
 *      half failed against unmodified main for every group below.
 *
 * FAIL-BEFORE (this file is not exempt, and must not be marked exempt).
 * Measured, not assumed:
 *
 *   - 16 of 27 fail against a full `origin/main` archive.
 *   - 14 of 27 fail under CI's own method (`scripts/verify-fail-before.sh`,
 *     which reverts only `server/src`).
 *
 * The 2-test gap is the menubar producer/consumer pin: it lives outside
 * `server/src`, so the revert leaves it in place. It is kept in its own
 * `describe` block so that gap is legible rather than surprising. The
 * value-parity assertions account for most of the 11 that pass either way;
 * they describe an invariant that already held and are here as the tripwire
 * for the future.
 *
 * If this test fails, reconcile the value or restore the pin in the SAME PR
 * that broke it. Never relax an assertion to make it pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
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
 * Strip `//` line comments and block comments so a literal MENTIONED in prose
 * is never mistaken for a second declaration. Deliberately conservative: it
 * does not attempt to respect string literals containing "//", so a URL inside
 * a string would truncate that line. No file scanned here contains one, and a
 * false NEGATIVE (a missed occurrence) is the safe direction for this scan
 * anyway -- the sole-declaration assertions below count occurrences and a
 * missed one can only make the count smaller, never invent a violation.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

describe("frozen wire strings have exactly one declaration", () => {
  /**
   * Each entry: a frozen string, the file that declares it as a named export,
   * and the other server/src files that USE it (which must import the constant
   * rather than re-type the literal).
   */
  const soleDeclarations = [
    {
      label: "ENFORCEMENT_EVENT_SCHEMA",
      literal: "sanctuary.enforcement-event.v1",
      declaredIn: "server/src/castle-wall/export/schema.ts",
      importers: ["server/src/castle-wall/export/sink.ts"],
    },
    {
      label: "SIGNATURE_BUNDLE_VERSION",
      literal: "sanctuary.signature-bundle.v1",
      declaredIn: "server/src/core/crypto-suite-registry.ts",
      importers: ["server/src/v1/federation-revocation.ts"],
    },
  ] as const;

  for (const entry of soleDeclarations) {
    it(`${entry.label} is declared once, in ${entry.declaredIn}`, () => {
      const declaring = stripComments(read(entry.declaredIn));
      expect(
        countOccurrences(declaring, entry.literal),
        `${entry.declaredIn} should spell "${entry.literal}" exactly once (the declaration)`
      ).toBe(1);
    });

    for (const importer of entry.importers) {
      it(`${importer} imports ${entry.label} instead of re-typing the literal`, () => {
        const source = read(importer);
        expect(
          stripComments(source).includes(entry.literal),
          `${importer} must not re-type "${entry.literal}"; import ${entry.label} from ${entry.declaredIn}`
        ).toBe(false);
        expect(
          source.includes(entry.label),
          `${importer} must reference ${entry.label}`
        ).toBe(true);
      });
    }
  }
});

describe("duplicated constants keep identical values and name their counterpart", () => {
  /**
   * A mirror group: one canonical file and one or more files that re-declare
   * the same values because they cannot import them. `values` are checked for
   * literal presence in every member. `pinTargets` are the paths each
   * non-canonical member must name in a comment.
   */
  interface MirrorGroup {
    readonly label: string;
    readonly canonical: string;
    readonly mirrors: readonly string[];
    /** Literal text every member of the group must contain. */
    readonly values: readonly string[];
  }

  const groups: readonly MirrorGroup[] = [
    {
      label: "audit chain / standalone external verifier",
      canonical: "server/src/audit/chain.ts",
      mirrors: ["server/src/cli/audit-chain-verify.ts"],
      values: ['"GENESIS"', "sanctuary.audit-checkpoint.v1"],
    },
    {
      label: "transparency checkpoint / offline verifier",
      canonical: "server/src/transparency/checkpoint.ts",
      mirrors: ["server/src/transparency/verify.ts"],
      values: [
        "sanctuary.enforcement-checkpoint.v1",
        '"GENESIS"',
        "SANCTUARY_TRANSPARENCY_BUNDLE_V1",
      ],
    },
    {
      label: "transparency anchor / offline anchor verifier",
      canonical: "server/src/transparency/anchor.ts",
      mirrors: ["server/src/transparency/anchor-verify.ts"],
      values: [
        "sanctuary.transparency.anchor-commitment.v1",
        "3059301306072a8648ce3d020106082a8648ce3d030107034200",
      ],
    },
    {
      label: "service-account name charset",
      canonical: "server/src/castle-wall/provision/account.ts",
      mirrors: [
        "server/src/egress-gate/harness-daemon.ts",
        "server/src/egress-gate/gate-daemon.ts",
      ],
      values: ["/^[a-z_][a-z0-9._-]{0,63}$/"],
    },
    {
      label: "mesh v2 hybrid certificate versions",
      canonical: "server/src/mesh/trust-root-hybrid.ts",
      mirrors: ["server/src/mesh/types.ts"],
      values: [
        "sanctuary.fortress-master.v2.hybrid-ed25519-ml-dsa-65",
        "sanctuary.principal-cert.v2.hybrid-ed25519-ml-dsa-65",
        "sanctuary.node-cert.v2.hybrid-ed25519-ml-dsa-65",
      ],
    },
  ];

  for (const group of groups) {
    describe(group.label, () => {
      it("every member spells the same values", () => {
        for (const file of [group.canonical, ...group.mirrors]) {
          const source = stripComments(read(file));
          for (const value of group.values) {
            expect(
              source.includes(value),
              `${file} should contain ${value} (mirror group: ${group.label})`
            ).toBe(true);
          }
        }
      });

      it("each mirror names the canonical file in a comment", () => {
        // The canonical path is written into the pin comments without the
        // leading `server/`, matching how sibling modules are referenced
        // throughout server/src.
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

  /** Values mirrored in all three languages. */
  const triLingual = ["l1", "ed25519-v1", "Content-Length", "castle-wall"];

  /** Values mirrored in TypeScript and Rust only (no Swift counterpart). */
  const tsAndRustOnly = [
    "sanctuary.castle-wall.audit-producer.v1\\n",
    "cw-audit-producer-v1",
  ];

  it("the three-way values are present in all three files", () => {
    for (const value of triLingual) {
      for (const file of [TS, RUST, SWIFT]) {
        expect(
          stripComments(read(file)).includes(`"${value}"`),
          `${file} should declare "${value}"`
        ).toBe(true);
      }
    }
  });

  it("the producer-signature values are present in TypeScript and Rust", () => {
    for (const value of tsAndRustOnly) {
      for (const file of [TS, RUST]) {
        expect(
          stripComments(read(file)).includes(`"${value}"`),
          `${file} should declare "${value}"`
        ).toBe(true);
      }
    }
  });

  it("all three files name the other language's file in a comment", () => {
    const ts = read(TS);
    expect(ts.includes("castle-wall-daemon/src/lib.rs")).toBe(true);
    expect(ts.includes("castle-wall-macos/Sources/CastleWallIPC/Constants.swift")).toBe(
      true
    );
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
    "server/src/transparency/verify.ts",
    "server/src/cognitive/tools.ts",
    "server/src/workload-lifecycle/host-attestation.ts",
    "server/src/workload-lifecycle/undeclared-finding.ts",
  ];

  it("every signed surface uses the identical encoding name", () => {
    for (const file of surfaces) {
      expect(
        stripComments(read(file)).includes(`"${ENCODING}"`),
        `${file} should spell the encoding exactly "${ENCODING}"`
      ).toBe(true);
    }
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
    const union = read(CLIENT).match(
      /connection_status:\s*([^;]+);/
    );
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
