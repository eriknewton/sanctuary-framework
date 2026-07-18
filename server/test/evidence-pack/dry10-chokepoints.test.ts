/**
 * Sanctuary MCP Server - Evidence Pack: dry-bar round 10 chokepoint regressions
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Round 10 of the independent adversarial dry-bar sweep found three defects that
 * all lived OUTSIDE the #962 manifest-coverage chokepoint, plus one prose bug.
 * These tests pin the chokepoints that closed them.
 *
 * Every assertion here is on an ARTIFACT, never on prose alone. That is
 * deliberate and it is the lesson of rounds 7 through 9: a prose-level assertion
 * is what let this class survive three rounds, because the human-readable report
 * read correctly while the SIGNED manifest stayed dishonest. So:
 *
 *  - D10-1 asserts on the rendered counts AND the attested window TOGETHER, so a
 *    fix that corrects one surface while leaving the other stale fails here.
 *  - D10-2 asserts on the shipped directory contents as a SET.
 *  - D10-DISC-1 asserts on the manifest and report BYTES.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, readdir, rm, writeFile, readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  buildEvidencePack,
  ANCHOR_EVIDENCE_FILENAME,
  AUDIT_CHAIN_FILENAME,
  MANIFEST_FILENAME,
  PDF_FILENAME,
  REPORT_FILENAME,
  TRANSPARENCY_BUNDLE_FILENAME,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import { writePackDirectory } from "../../src/evidence-pack/cli.js";
import {
  describeReadFailureCause,
  populated,
  readFailed,
  sanitizeReason,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";
import { censusOverAttestedWindow } from "../../src/evidence-pack/aggregate.js";
import { quarterWindow } from "../../src/evidence-pack/quarter.js";
import type {
  EvidencePack,
  EvidencePackInput,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";

let masterKey: Uint8Array;
let signer: StoredIdentity;

beforeEach(async () => {
  masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("dry10-law", identityEncKey, "pw");
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

function entry(timestamp: string, operation: string): AuditEntry {
  return {
    timestamp,
    layer: "l2",
    operation,
    identity_id: "agent-a",
    result: "success",
  };
}

const Q3 = quarterWindow({ year: 2026, quarter: 3 });

function retention(over: Partial<RetentionFacts> = {}): RetentionFacts {
  return {
    max_entries: 100_000,
    retained_total: 1,
    max_total_size_bytes: 100 * 1024 * 1024,
    retained_total_size_bytes: 100,
    ever_pruned: false,
    earliest_retained_at: "2026-07-01T00:00:00.000Z",
    daemon_store: { status: "absent", included_entry_count: 0 },
    ...over,
  };
}

function input(over: Partial<EvidencePackInput> = {}): EvidencePackInput {
  return {
    firm_name: "Dry10 Test Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
    custody: populated({
      custody_mode: "passphrase",
      outbound_denied_by_default: populated(true),
    }),
    ...over,
  };
}

function deps(audit: ReadOutcome<AuditReadData>): BuildEvidencePackDeps {
  return { audit, signer, masterKey };
}

/** The signed Markdown report's bytes (the artifact the firm reads). */
function reportText(pack: EvidencePack): string {
  const report = pack.files.find((f) => f.filename === REPORT_FILENAME);
  if (!report) throw new Error("expected a report file");
  return report.content;
}

/** The SIGNED manifest's bytes, exactly as written to disk. */
function manifestText(pack: EvidencePack): string {
  return JSON.stringify(pack.manifest, null, 2);
}

/** The rendered "Total recorded audit operations" figure, parsed back out. */
function renderedTotal(pack: EvidencePack): number | null {
  const m = /Total recorded audit operations in the [a-z ]*?:\*\* (\d+)/.exec(
    reportText(pack)
  );
  return m ? Number(m[1]) : null;
}

/** Every count in the section-7 decision table, parsed back out. */
function renderedTableCounts(pack: EvidencePack): number[] {
  const text = reportText(pack);
  const start = text.indexOf("| Decision | Count |");
  if (start === -1) return [];
  const block = text.slice(start, text.indexOf("\n\n", start));
  return [...block.matchAll(/\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|/g)].map((m) =>
    Number(m[2])
  );
}

describe("D10-1: counts and the attested coverage window share one boundary", () => {
  // Codex round-10 case A, reproduced exactly. A future-dated in-quarter entry
  // (after the census cut) collapsed the attested window to zero width, and the
  // SIGNED report then said the window was empty, said "NONE of this quarter is
  // covered", said "the counts above are therefore zero for the attested
  // window", AND printed "Total recorded audit operations in the quarter: 1"
  // with a nonzero category table. All in one signed file.
  it("a future-dated entry past the census cut cannot produce a nonzero count beside an empty attested window", () => {
    const futureStamp = "2026-09-15T00:00:00.000Z";
    const pack = buildEvidencePack(
      input({ generated_at_override: "2026-08-01T00:00:00.000Z" }),
      deps(
        populated({
          entries: [entry(futureStamp, "gate_allow:state_read")],
          retention: retention({ earliest_retained_at: futureStamp }),
          census_taken_at: "2026-08-01T00:00:00.000Z",
        })
      )
    );

    // The attested window is empty, and the SIGNED manifest says so.
    const c = pack.manifest.coverage;
    if (!c.determinable) throw new Error("expected a determinable coverage span");
    expect(c.covered_from).toBe(c.covered_to_exclusive);
    expect(c.zero_of_quarter_covered).toBe(true);

    // THE REGRESSION: the counts must agree with that window, not with the
    // calendar quarter. Both the summary figure and every table row are zero.
    expect(renderedTotal(pack)).toBe(0);
    const table = renderedTableCounts(pack);
    expect(table.length).toBeGreaterThan(0);
    expect(table.every((n) => n === 0)).toBe(true);

    // And the aggregation the manifest was built from agrees.
    expect(pack.aggregation.status).toBe("populated");
    if (pack.aggregation.status === "populated") {
      expect(pack.aggregation.value.total_in_window).toBe(0);
    }
  });

  // Codex round-10 case B. The report appended "The last recorded audit entry
  // inside the covered window is X" whenever an entry existed, without checking
  // that X was actually inside the covered window. With an unparseable earliest
  // timestamp the covered window is empty, so no such entry can exist.
  it("never names a last-recorded entry that falls outside the covered window", () => {
    const pack = buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention({ earliest_retained_at: "not-a-date" }),
        })
      )
    );

    const c = pack.manifest.coverage;
    if (!c.determinable) throw new Error("expected a determinable coverage span");
    expect(c.covered_from).toBe(c.covered_to_exclusive);

    // If the sentence is rendered at all, the instant it names must be inside
    // the attested window. An empty window admits no instant, so it must be
    // absent entirely.
    const named = /last recorded (?:operator-store )?audit entry inside the covered window is ([^\s.]+)/.exec(
      reportText(pack)
    );
    expect(named).toBeNull();
    expect(renderedTotal(pack)).toBe(0);
  });

  // The same contradiction one surface over: when the covered window is NOT
  // DETERMINABLE the manifest correctly said `determinable: false` while the
  // report still printed definitive quarter-wide counts.
  it("asserts no definitive counts when the coverage window is not determinable", () => {
    const pack = buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
          census_taken_at: "not-a-parseable-instant",
        })
      )
    );

    expect(pack.manifest.coverage.determinable).toBe(false);
    // No definitive figure of any kind reaches the report.
    expect(renderedTotal(pack)).toBeNull();
    expect(renderedTableCounts(pack)).toEqual([]);
    expect(pack.aggregation.status).toBe("read_failed");
    expect(reportText(pack)).toContain("could NOT be computed");
  });

  // Guards against a vacuous pass: an ordinary healthy quarter must still render
  // real, definitive, CORRECT counts. If the fix had simply zeroed everything,
  // this test fails.
  it("still renders correct definitive counts for an ordinary covered quarter", () => {
    const pack = buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [
            entry("2026-07-05T00:00:00.000Z", "gate_allow:state_read"),
            entry("2026-08-05T00:00:00.000Z", "gate_allow:state_list"),
            entry("2026-09-05T00:00:00.000Z", "gate_deny:egress_post"),
            // Outside the quarter entirely: must not be counted.
            entry("2026-06-05T00:00:00.000Z", "gate_allow:x"),
          ],
          retention: retention({ retained_total: 4 }),
        })
      )
    );

    const c = pack.manifest.coverage;
    if (!c.determinable) throw new Error("expected a determinable coverage span");
    expect(c.zero_of_quarter_covered).toBeUndefined();
    expect(renderedTotal(pack)).toBe(3);
    expect(renderedTableCounts(pack).reduce((a, b) => a + b, 0)).toBe(3);
  });

  // The invariant itself, over a matrix: whatever the scenario, the rendered
  // total must equal the number of entries actually inside the attested window.
  // This is the property the chokepoint exists to guarantee.
  it("keeps the rendered total equal to the entries inside the attested window, across scenarios", () => {
    const entries = [
      entry("2026-06-30T23:59:59.000Z", "gate_allow:before"),
      entry("2026-07-15T00:00:00.000Z", "gate_allow:inside"),
      entry("2026-08-20T00:00:00.000Z", "gate_deny:inside"),
      entry("2026-09-30T00:00:00.000Z", "gate_allow:late"),
    ];
    const scenarios: Array<{ generatedAt: string; census?: string; earliest: string }> = [
      { generatedAt: "2026-10-02T00:00:00.000Z", earliest: "2026-07-01T00:00:00.000Z" },
      { generatedAt: "2026-09-01T00:00:00.000Z", earliest: "2026-07-01T00:00:00.000Z" },
      {
        generatedAt: "2026-09-01T00:00:00.000Z",
        census: "2026-08-01T00:00:00.000Z",
        earliest: "2026-07-01T00:00:00.000Z",
      },
      { generatedAt: "2026-08-01T00:00:00.000Z", earliest: "2026-09-15T00:00:00.000Z" },
    ];

    for (const s of scenarios) {
      const census = censusOverAttestedWindow(
        entries,
        retention({ earliest_retained_at: s.earliest, retained_total: entries.length }),
        Q3,
        { generatedAt: s.generatedAt, censusTakenAt: s.census }
      );
      if (census.aggregation.status !== "populated") continue;

      const from = new Date(census.coverage.covered_from).getTime();
      const to = new Date(census.coverage.covered_to_exclusive).getTime();
      const expected = entries.filter((e) => {
        const t = new Date(e.timestamp).getTime();
        return t >= from && t < to;
      }).length;

      expect(census.aggregation.value.total_in_window).toBe(expected);
      // And the tail it reports is genuinely inside that window.
      const last = census.aggregation.value.last_entry_at;
      if (last !== null) {
        const t = new Date(last).getTime();
        expect(t).toBeGreaterThanOrEqual(from);
        expect(t).toBeLessThan(to);
      }
    }
  });
});

describe("D10-2: the shipped directory is exactly the pack", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-dry10-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function packWithExports(over: {
    transparency: ReadOutcome<string>;
  }): EvidencePack {
    return buildEvidencePack(
      input({
        discrete_exports: {
          transparency: over.transparency,
          audit_chain: populated('{"kind":"entry","sequence":1}'),
          anchor: readFailed("no anchor evidence was gathered for this run."),
        },
      }),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );
  }

  /** The delivered directory contents, as a sorted set. */
  async function shipped(d: string): Promise<string[]> {
    return (await readdir(d)).filter((n) => !n.startsWith(".")).sort();
  }

  // The exact round-10 reproduction: run A gathers the transparency bundle; a
  // Castle Wall signing-key rotation flips that arm to read_failed; run B into
  // the SAME directory omits it. Run A's bundle must not survive.
  it("sweeps a stale conditional export when a later run into the same directory omits it", async () => {
    const runA = packWithExports({
      transparency: populated('{"format":"sanctuary-transparency-bundle","run":"A"}'),
    });
    await writePackDirectory(dir, runA);
    expect(await shipped(dir)).toContain(TRANSPARENCY_BUNDLE_FILENAME);

    const runB = packWithExports({
      transparency: readFailed("the checkpoints carry more than one signing key."),
    });
    await writePackDirectory(dir, runB);

    // THE REGRESSION: the shipped directory is run B's set, exactly.
    const expected = [
      MANIFEST_FILENAME,
      PDF_FILENAME,
      ...runB.files.map((f) => f.filename),
    ].sort();
    expect(await shipped(dir)).toEqual(expected);
    expect(await shipped(dir)).not.toContain(TRANSPARENCY_BUNDLE_FILENAME);
  });

  // The signed report's section-1 universal claim, checked against the artifact
  // the firm actually receives.
  it("delivers a directory in which every Markdown and export file is recorded in the manifest", async () => {
    const pack = packWithExports({
      transparency: populated('{"format":"sanctuary-transparency-bundle"}'),
    });
    await writePackDirectory(dir, pack);

    const listed = new Set(pack.files.map((f) => f.filename));
    for (const name of await shipped(dir)) {
      if (name === MANIFEST_FILENAME || name === PDF_FILENAME) continue;
      expect(listed.has(name)).toBe(true);
    }
    // And the claim the report makes is the claim we just verified.
    expect(reportText(pack)).toContain("`files` list is EXHAUSTIVE for this pack");
  });

  it("refuses to write beside a file it did not produce, rather than deleting it", async () => {
    const foreign = join(dir, "counsel-notes.md");
    await writeFile(foreign, "privileged working notes", "utf-8");

    const pack = packWithExports({ transparency: readFailed("not gathered.") });
    await expect(writePackDirectory(dir, pack)).rejects.toThrow(
      /counsel-notes\.md/
    );

    // The operator's file is untouched and no partial pack was written.
    expect(await readFile(foreign, "utf-8")).toBe("privileged working notes");
    expect(await shipped(dir)).toEqual(["counsel-notes.md"]);
  });

  it("tolerates dotfiles, which cannot falsify a claim about Markdown and export files", async () => {
    await writeFile(join(dir, ".DS_Store"), "junk", "utf-8");
    const pack = packWithExports({ transparency: readFailed("not gathered.") });
    await expect(writePackDirectory(dir, pack)).resolves.toBeUndefined();
    expect(await shipped(dir)).toEqual(
      [MANIFEST_FILENAME, PDF_FILENAME, ...pack.files.map((f) => f.filename)].sort()
    );
  });

  it("writes into a fresh directory that does not exist yet", async () => {
    const nested = join(dir, "q3", "pack");
    const pack = packWithExports({ transparency: readFailed("not gathered.") });
    await writePackDirectory(nested, pack);
    expect(await shipped(nested)).toContain(MANIFEST_FILENAME);
  });

  it("sweeps every conditional export name, not just the transparency bundle", async () => {
    // Plant all three canonical conditional export names from an earlier run.
    await mkdir(dir, { recursive: true });
    for (const name of [
      TRANSPARENCY_BUNDLE_FILENAME,
      AUDIT_CHAIN_FILENAME,
      ANCHOR_EVIDENCE_FILENAME,
    ]) {
      await writeFile(join(dir, name), "stale from a previous quarter", "utf-8");
    }

    const pack = buildEvidencePack(
      input({
        discrete_exports: {
          transparency: readFailed("not gathered."),
          audit_chain: readFailed("not gathered."),
          anchor: readFailed("not gathered."),
        },
      }),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );
    await writePackDirectory(dir, pack);

    expect(await shipped(dir)).toEqual(
      [MANIFEST_FILENAME, PDF_FILENAME, REPORT_FILENAME].sort()
    );
  });
});

describe("D10-DISC-1: host paths never reach a firm-facing artifact", () => {
  const FORTRESS_PATH =
    "/Users/someoperator/Code/Sanctuary/state/_audit/entry-0001.enc";

  it("scrubs absolute, home, and Windows paths plus uid/gid from any reason", () => {
    expect(sanitizeReason(`open '${FORTRESS_PATH}'`)).not.toContain("someoperator");
    expect(sanitizeReason(`open '${FORTRESS_PATH}'`)).not.toContain("/Users");
    expect(sanitizeReason("failed at ~/.sanctuary/state/x.enc")).not.toContain(
      ".sanctuary"
    );
    expect(sanitizeReason("at C:\\Users\\someone\\state")).not.toContain("someone");
    expect(sanitizeReason("denied for uid=501 gid=20")).not.toContain("501");
  });

  it("leaves ordinary prose and canonical filenames intact", () => {
    expect(sanitizeReason("the read/write check and/or the cap")).toBe(
      "the read/write check and/or the cap"
    );
    expect(sanitizeReason("see `transparency-bundle.json` for detail")).toBe(
      "see `transparency-bundle.json` for detail"
    );
  });

  it("never echoes an error's free-text message, only a closed-set category", () => {
    const e = Object.assign(new Error(`ENOENT: no such file, open '${FORTRESS_PATH}'`), {
      code: "ENOENT",
    });
    const described = describeReadFailureCause(e);
    expect(described).toContain("ENOENT");
    expect(described).toContain("was not present");
    expect(described).not.toContain("someoperator");
    expect(described).not.toContain("/Users");

    // An unrecognized cause collapses to the generic category; nothing from the
    // message survives, including an unknown errno code.
    const weird = Object.assign(new Error(`custody check failed for ${FORTRESS_PATH}`), {
      code: "ESOMETHINGNEW",
    });
    expect(describeReadFailureCause(weird)).not.toContain("someoperator");
    expect(describeReadFailureCause(weird)).not.toContain("ESOMETHINGNEW");
    expect(describeReadFailureCause("a bare string")).not.toContain("bare string");
  });

  // The leg the Claude lens could not stage empirically: a path-bearing audit
  // read failure reaching the SIGNED manifest's coverage.reason.
  it("keeps host paths out of the SIGNED manifest bytes on an audit read failure", () => {
    const pack = buildEvidencePack(
      input(),
      deps(readFailed(`the audit log could not be read: ENOENT, open '${FORTRESS_PATH}'`))
    );

    const manifest = manifestText(pack);
    expect(manifest).not.toContain("someoperator");
    expect(manifest).not.toContain("/Users");
    expect(manifest).not.toContain(".enc");
    // The manifest still discloses the failure honestly.
    expect(pack.manifest.coverage.determinable).toBe(false);
    if (!pack.manifest.coverage.determinable) {
      expect(pack.manifest.coverage.reason).toContain("could not be read");
    }
  });

  // A NEIGHBOURING surface found while fixing the reported one: the coverage
  // `explanation` interpolates the value that failed its usability check, and
  // that explanation is copied verbatim into the SIGNED manifest's
  // `coverage.reason` when the window is not determinable. It reaches the signed
  // artifact WITHOUT passing through `readFailed`, so the brand does not cover
  // it. The value is arbitrary text by definition on that path.
  it("keeps host paths out of the SIGNED manifest when an unusable census cut is quoted back", () => {
    const pack = buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
          census_taken_at: `corrupt ${FORTRESS_PATH}`,
        })
      )
    );

    expect(pack.manifest.coverage.determinable).toBe(false);
    const manifest = manifestText(pack);
    expect(manifest).not.toContain("someoperator");
    expect(manifest).not.toContain("/Users");
    expect(reportText(pack)).not.toContain("someoperator");
  });

  it("keeps an unusable earliest-retained value out of the signed report, and caps its length", () => {
    const blob = "x".repeat(5000) + FORTRESS_PATH;
    const pack = buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention({ earliest_retained_at: blob }),
        })
      )
    );

    const text = reportText(pack);
    expect(text).not.toContain("someoperator");
    expect(text).not.toContain("x".repeat(200));
  });

  it("keeps host paths out of the SIGNED report bytes on a discrete-export failure", () => {
    const pack = buildEvidencePack(
      input({
        discrete_exports: {
          transparency: readFailed(
            `the transparency bundle could not be gathered: File custody check failed for ${FORTRESS_PATH}: not a regular file`
          ),
          audit_chain: readFailed("the audit-chain export could not be gathered."),
          anchor: readFailed("the anchor evidence could not be gathered."),
        },
      }),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );

    const text = reportText(pack);
    expect(text).not.toContain("someoperator");
    expect(text).not.toContain("/Users");
    expect(text).toContain("could not be gathered");
  });
});

// ANTI-DRIFT GUARD, in the style of `op-exhaustiveness.test.ts`. The D10-1
// chokepoint works because `buildEvidencePack` derives the counts and the
// coverage statement from ONE call. `aggregateQuarter` and `detectShortfall`
// remain exported (they are the pure primitives the chokepoint is built from,
// and the aggregate tests drive them directly), so nothing at the type level
// stops a future edit from pairing them in the generator again and
// reintroducing the two-window drift. This reads the ACTUAL generator source
// and fails if that happens.
describe("D10-1 durability: the generator uses only the attested-window chokepoint", () => {
  it("never pairs the raw aggregation and shortfall primitives itself", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const generateTs = readFileSync(
      join(here, "..", "..", "src", "evidence-pack", "generate.ts"),
      "utf-8"
    );
    // Strip comments so the explanatory block comments (which name both
    // primitives on purpose) do not trip the guard.
    const code = generateTs
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");

    expect(code).toContain("censusOverAttestedWindow");
    expect(code).not.toContain("aggregateQuarter");
    expect(code).not.toContain("detectShortfall");
  });
});

describe("D10-3: section 10 does not print the failure clause twice", () => {
  it("renders the read-failed transparency reason exactly once", () => {
    const pack = buildEvidencePack(
      input({
        discrete_exports: {
          transparency: readFailed(
            "the transparency bundle could not be gathered: the checkpoints carry more than one signing key."
          ),
          audit_chain: readFailed("the audit-chain export could not be gathered."),
          anchor: readFailed("the anchor evidence could not be gathered."),
        },
      }),
      deps(
        populated({
          entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );

    const text = reportText(pack);
    const occurrences = text.split("the transparency bundle could not be gathered")
      .length - 1;
    expect(occurrences).toBe(1);
    expect(text).not.toContain(
      "could not be gathered. the transparency bundle could not be gathered"
    );
  });
});
