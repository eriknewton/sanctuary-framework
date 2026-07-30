/**
 * Sanctuary MCP Server - Evidence Pack: dry-bar round 11 chokepoint regressions
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Round 11's two independent lenses both returned NOT DRY. Every finding was
 * one shape: the pack asserted something it had not verified, or that its own
 * data contradicted. Not arithmetic errors -- unjustified claims. These tests
 * pin the chokepoints that made each class unrepresentable.
 *
 * Every assertion here is on an ARTIFACT -- the rendered Markdown the firm
 * reads, the extracted PDF text, the shipped directory as a set -- never on a
 * prose helper in isolation. Three prior rounds passed a prose-level check while
 * the SIGNED artifact stayed dishonest, so a helper-level assertion is not
 * evidence that the defect is closed.
 *
 * PDF NOTE: the round-11 lens's first PDF extraction produced a FALSE NEGATIVE,
 * because a line-wrapped phrase could not match across separate text-show runs.
 * {@link pdfText} joins runs with a space for exactly that reason, and
 * {@link expectPdfExtractionWorks} asserts a known-present phrase on every use
 * so a "phrase absent" result can never be a vacuous pass.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryStorage } from "../../src/storage/memory.js";
import { canonicalJson } from "../../src/audit/chain.js";
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
  REPORT_FILENAME,
  TRANSPARENCY_BUNDLE_FILENAME,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import { writePackDirectory } from "../../src/evidence-pack/cli.js";
import {
  emptyVerified,
  populated,
  readFailed,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";
import { diagnoseHistoryGap } from "../../src/evidence-pack/history-attribution.js";
import {
  APPLEDOUBLE_MAGIC,
  isPackRelevantEntry,
} from "../../src/evidence-pack/pack-files.js";
import { PACK_FILENAMES } from "../../src/evidence-pack/generate.js";
import {
  anchorCommitmentDigestHex,
  anchorCommitmentPreimage,
  anchorPublicKeyPem,
  buildHashedRekordProposal,
  deriveAnchorSigningKey,
  signAnchorPreimage,
} from "../../src/transparency/anchor.js";
import { rfc6962LeafHash } from "../../src/transparency/anchor-verify.js";
import {
  checkpointPayloadHash,
  type VerifierCheckpointRecord,
} from "../../src/transparency/verify.js";
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
  const { storedIdentity } = createIdentity("dry11-law", identityEncKey, "pw");
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

function retention(over: Partial<RetentionFacts> = {}): RetentionFacts {
  return {
    max_entries: 100_000,
    retained_total: 1,
    max_total_size_bytes: 100 * 1024 * 1024,
    retained_total_size_bytes: 100,
    ever_pruned: false,
    earliest_retained_at: "2026-04-02T10:00:00.000Z",
    daemon_store: { status: "absent", included_entry_count: 0 },
    ...over,
  };
}

function input(over: Partial<EvidencePackInput> = {}): EvidencePackInput {
  return {
    firm_name: "Dry11 Test Law LLP",
    quarter: { year: 2026, quarter: 1 },
    generated_at_override: "2026-07-19T00:00:00.000Z",
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

/**
 * Wrap-aware PDF text extraction: pull every `(...) Tj` show-text run and join
 * with a SPACE, so a phrase broken across two runs by line wrapping still
 * matches. Joining with no separator is what produced the round-11 lens's false
 * negative.
 */
function pdfText(pack: EvidencePack): string {
  const raw = Buffer.from(pack.pdf).toString("latin1");
  const runs = [...raw.matchAll(/\(((?:\\.|[^\\)])*)\)\s*Tj/g)].map((m) =>
    m[1]!.replace(/\\([()\\])/g, "$1")
  );
  return runs.join(" ");
}

/**
 * Guard against a vacuous pass: prove the extractor actually sees the document
 * before trusting any "phrase is absent" assertion made against it.
 */
function expectPdfExtractionWorks(text: string): void {
  expect(text.length).toBeGreaterThan(500);
  expect(text).toContain("Dry11 Test Law LLP");
}

// ── C-1 (HIGH): causal diagnoses route through the definitive discriminator ──

describe("D11 C-1: the pack never tells a firm entries were pruned from a log that never pruned", () => {
  /**
   * The reproduction. Fixture A's shape from the round-11 sweep: a fortress with
   * `ever_pruned: false` whose earliest entry post-dates the reporting quarter
   * entirely -- i.e. ANY pack for a quarter predating the install, which is the
   * ordinary backfill path and plausibly the first pack a firm ever sees.
   */
  function zeroCoveragePack(over: Partial<RetentionFacts> = {}): EvidencePack {
    return buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:state_read")],
          retention: retention(over),
        })
      )
    );
  }

  it("states genuine inactivity, not pruning, in the SIGNED report", () => {
    const text = reportText(zeroCoveragePack());

    // The false causal verdict, verbatim from the round-11 finding.
    expect(text).not.toContain("almost always means earlier entries were pruned");
    // And no affirmative pruning attribution reaches the reader by any wording.
    expect(text).not.toMatch(/\bentries were pruned by size\/count \(FIFO\)/);

    // The pack must still explain the gap -- silence would be its own defect.
    expect(text).toContain("never pruned entries");
    expect(text).toContain("not that entries were pruned");
  });

  it("states genuine inactivity, not pruning, in the rendered PDF", () => {
    const text = pdfText(zeroCoveragePack());
    expectPdfExtractionWorks(text);

    expect(text).not.toContain("almost always means earlier entries were pruned");
    expect(text).not.toMatch(/\bentries were pruned by size\/count \(FIFO\)/);
    expect(text).toContain("never pruned entries");
  });

  /**
   * The core of the finding was not the single false sentence: it was that two
   * packs from the SAME fortress state gave contradictory causal diagnoses of
   * the SAME timestamp. A fix that corrects the zero-coverage arm while leaving
   * the sibling arm free to diverge again has not closed the class.
   */
  it("the zero-coverage and partial-coverage arms agree about the same fortress", () => {
    const facts = retention();
    // Q1: the quarter predates every retained entry -> zero-coverage arm.
    const q1 = reportText(zeroCoveragePack());
    // Q2: the same fortress, a quarter its entries fall inside, whose earliest
    // entry is after the quarter start -> partial-coverage (sibling) arm.
    const q2 = reportText(
      buildEvidencePack(
        input({
          quarter: { year: 2026, quarter: 2 },
          generated_at_override: "2026-07-19T00:00:00.000Z",
        }),
        deps(
          populated({
            entries: [
              entry("2026-04-02T10:00:00.000Z", "gate_allow:state_read"),
            ],
            retention: facts,
          })
        )
      )
    );

    // Neither arm may assert pruning about a log that never pruned...
    for (const text of [q1, q2]) {
      expect(text).not.toMatch(/\bentries were pruned by size\/count \(FIFO\)/);
    }
    // ...and both must reach the SAME causal conclusion, since the fortress is
    // the same. This is the assertion that would have caught the finding.
    expect(q1).toContain("not that entries were pruned");
    expect(q2).toContain("not that entries were pruned");
  });

  it("a log that HAS pruned still gets the hedged register, never a definitive cause", () => {
    const text = reportText(zeroCoveragePack({ ever_pruned: true }));
    expect(text).toContain("has pruned entries at least once");
    // Pruning is a fact; that THIS gap is that pruning is not.
    expect(text).toContain("cannot be affirmed here");
    expect(text).not.toContain("almost always means earlier entries were pruned");
  });

  it("an UNREAD discriminator yields no definitive cause in either direction", () => {
    const text = reportText(zeroCoveragePack({ ever_pruned: null }));
    expect(text).toContain("cannot be determined from this report");
    expect(text).not.toContain("never pruned entries");
    expect(text).not.toContain("has pruned entries at least once");
  });

  it("the constructor refuses to build a diagnosis its own facts contradict", () => {
    // The fail-closed guard. A definitive attribution from an unread
    // discriminator must throw rather than reach an artifact.
    expect(() =>
      diagnoseHistoryGap({
        ever_pruned: null,
        at_cap_determinable: true,
        at_cap: false,
      })
    ).not.toThrow(); // null -> "undetermined", which is honest.

    expect(
      diagnoseHistoryGap({
        ever_pruned: null,
        at_cap_determinable: true,
        at_cap: false,
      }).attribution
    ).toBe("undetermined");

    // never_pruned requires the discriminator AND a determinable below-cap
    // position: an undeterminable cap position cannot prove below-cap.
    expect(
      diagnoseHistoryGap({
        ever_pruned: false,
        at_cap_determinable: false,
        at_cap: false,
      }).attribution
    ).toBe("undetermined");
  });

  /**
   * The structural half of the fix. The pruning vocabulary lives in exactly one
   * module; if another evidence-pack module reintroduces it, that module is
   * asserting a cause outside the one constructor -- which is the D11-1 defect
   * reappearing on a neighbouring surface, the class that survived ten rounds.
   */
  it("no other evidence-pack module constructs a pruning attribution", async () => {
    const dir = new URL("../../src/evidence-pack/", import.meta.url);
    const files = (await readdir(dir)).filter((f) => f.endsWith(".ts"));
    const offenders: string[] = [];
    for (const file of files) {
      if (file === "history-attribution.ts") continue;
      const src = await import("node:fs/promises").then((fs) =>
        fs.readFile(new URL(file, dir), "utf-8")
      );
      // Strip comments: the prohibition is on CONSTRUCTING the claim, and the
      // surrounding modules legitimately explain the rule in prose. Then FOLD
      // string concatenation (`"a " +\n  "b"` -> `"a b"`): without this the scan
      // is trivially defeated by splitting the phrase across two literals, which
      // is the ordinary way prose is written in this codebase and is exactly how
      // a line-oriented scanner produces a vacuous pass.
      const code = src
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "")
        .replace(/"\s*\+\s*"/g, "");
      // Any AFFIRMATIVE pruning attribution built outside the constructor is
      // the defect class, whatever the wording. The partial-coverage arm used
      // to compose its own "may have been pruned by size/count (FIFO)
      // retention" sentence, which is how a claim stays constructible outside
      // the chokepoint.
      for (const phrase of [
        "almost always means earlier entries were pruned",
        "pruned by size/count (FIFO) retention",
      ]) {
        if (code.includes(phrase)) offenders.push(`${file}: ${phrase}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * The guarantee that does not depend on scanning source at all. A source scan
   * can be defeated by splitting a phrase across two string literals; a rendered
   * artifact cannot lie about what it says. This walks EVERY combination of the
   * three facts that settle the attribution, against BOTH quarter shapes, and
   * asserts the invariant on the bytes the firm receives: a log that definitively
   * never pruned is never told its entries were pruned, on any path.
   */
  it("no (retention shape x quarter shape) combination affirms pruning from a never-pruned log", () => {
    const everPruned: (boolean | null)[] = [false, true, null];
    const capStates = [
      { at_cap_determinable: true, at_cap: false, retained_total: 1 },
      { at_cap_determinable: true, at_cap: true, retained_total: 100_000 },
      { at_cap_determinable: false, at_cap: false, retained_total: 1 },
    ];
    // Q1 predates every entry -> zero-coverage arm. Q2 contains them but starts
    // before the earliest -> partial-coverage arm.
    const quarters = [1, 2] as const;

    let checked = 0;
    for (const ep of everPruned) {
      for (const cap of capStates) {
        for (const q of quarters) {
          const facts = retention({
            ever_pruned: ep,
            retained_total: cap.retained_total,
            // An unknown size cap is what makes at-cap NOT determinable.
            max_total_size_bytes: cap.at_cap_determinable
              ? 100 * 1024 * 1024
              : 0,
          });
          const text = reportText(
            buildEvidencePack(
              input({ quarter: { year: 2026, quarter: q } }),
              deps(
                populated({
                  entries: [
                    entry("2026-04-02T10:00:00.000Z", "gate_allow:state_read"),
                  ],
                  retention: facts,
                })
              )
            )
          );
          checked++;

          // THE INVARIANT. Only a log that definitively never pruned earns the
          // reassurance; and such a log must never carry a pruning attribution.
          const definitivelyNeverPruned =
            ep === false && cap.at_cap_determinable && !cap.at_cap;
          if (definitivelyNeverPruned) {
            expect(text).not.toMatch(/entries were pruned by size\/count/);
            expect(text).not.toContain("almost always means earlier entries");
            expect(text).not.toContain("has pruned entries at least once");
          } else {
            // And the flattering reassurance must NOT fire without that proof.
            expect(text).not.toContain("never pruned entries");
          }
          // No arm may advise the unactionable remediation, ever.
          expect(text.toLowerCase()).not.toContain("raise the retention cap");
        }
      }
    }
    expect(checked).toBe(18);
  });
});

// ── C-3 (LOW): the pack does not advise an unactionable remediation ──────────

describe("D11 C-3: the pack never advises raising a cap the product cannot raise", () => {
  it("neither the zero-coverage nor the partial-coverage arm says 'raise the retention cap'", () => {
    const zeroCoverage = reportText(
      buildEvidencePack(
        input(),
        deps(
          populated({
            entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
            retention: retention({ ever_pruned: true }),
          })
        )
      )
    );
    const partial = reportText(
      buildEvidencePack(
        input({ quarter: { year: 2026, quarter: 2 } }),
        deps(
          populated({
            entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
            retention: retention({ ever_pruned: true }),
          })
        )
      )
    );

    for (const text of [zeroCoverage, partial]) {
      expect(text.toLowerCase()).not.toContain("raise the retention cap");
      // The actionable half survives, and names a command that actually ships.
      expect(text).toContain("sanctuary audit-chain export");
    }
  });
});

// ── X-1 (MED): hidden files cannot falsify the exhaustiveness claim ──────────

describe("D11 X-1: hidden pack-relevant files cannot ship unmanifested", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-dry11-hidden-"));
  });

  function simplePack(): EvidencePack {
    return buildEvidencePack(
      input(),
      deps(
        populated({
          entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );
  }

  it("refuses to write beside a hidden Markdown file the manifest cannot cover", async () => {
    await writeFile(join(dir, ".counsel-notes.md"), "# private\n", "utf-8");
    // The exact bypass the Codex lens drove: hidden, so the old dotfile
    // exemption dropped it before both the foreign check and the reconcile.
    await expect(writePackDirectory(dir, simplePack())).rejects.toThrow(
      /did not write/
    );
    // Fail-closed: nothing written, the operator's file untouched.
    const after = await readdir(dir);
    expect(after).toEqual([".counsel-notes.md"]);
    await rm(dir, { recursive: true, force: true });
  });

  it("refuses hidden JSON and JSONL exports too", async () => {
    for (const name of [".stale-export.json", ".old-chain.jsonl"]) {
      const d = await mkdtemp(join(tmpdir(), "sanctuary-dry11-hidden2-"));
      await writeFile(join(d, name), "{}", "utf-8");
      await expect(writePackDirectory(d, simplePack())).rejects.toThrow(
        /did not write/
      );
      await rm(d, { recursive: true, force: true });
    }
  });

  it("still tolerates inert OS metadata, so the tool stays usable", async () => {
    await writeFile(join(dir, ".DS_Store"), "\u0000binary", "utf-8");
    // F-3: a GENUINE AppleDouble fork of one of the pack's own files (correct
    // magic bytes). A `._*` file without the magic is no longer tolerated; see
    // the post-#969 sweep tests.
    await writeFile(
      join(dir, "._01_evidence_pack.md"),
      Buffer.from([...APPLEDOUBLE_MAGIC, 0x00, 0x02, 0x00, 0x00])
    );
    await expect(writePackDirectory(dir, simplePack())).resolves.toBeUndefined();
    const after = await readdir(dir);
    expect(after).toContain(".DS_Store");
    expect(after).toContain("00_pack_manifest.json");
    await rm(dir, { recursive: true, force: true });
  });

  it("the exemption predicate and the SIGNED prose describe the same set", () => {
    const text = reportText(simplePack());
    // Everything the writer ignores must be named in the signed recipe, or the
    // report tells the auditor to flag a file the generator deliberately left.
    for (const name of [".DS_Store", ".localized", "Thumbs.db", "desktop.ini"]) {
      expect(isPackRelevantEntry(name, PACK_FILENAMES)).toBe(false);
      expect(text).toContain(name);
    }
    // And the recipe tells the auditor to look for hidden files at all.
    expect(text).toContain("ls -a");
    expect(text).toContain("Any other file, hidden or not");
    // A hidden Markdown file is NOT exempt.
    expect(isPackRelevantEntry(".counsel-notes.md", PACK_FILENAMES)).toBe(true);
  });
});

// ── X-2 (MED): anchor confirmation is gated on what was actually read ────────

describe("D11 X-2: the anchor arm never claims confirmation the pack cannot support", () => {
  function hex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
  }

  function checkpointRecord(): VerifierCheckpointRecord {
    return {
      checkpoint_kind: "enforcement-checkpoint",
      schema_version: 1,
      counter: 1,
      previous_checkpoint_hash: "GENESIS",
      issued_at: "2026-04-02T10:00:00.000Z",
      fortress_id: "dry11-fortress",
      audit: {
        merkle_root: "01".repeat(32),
        lowest_sequence: 1,
        highest_sequence: 1,
        head_hash: "02".repeat(32),
        entry_count: 1,
      },
      policy: {
        rules_sha256: "03".repeat(32),
        rules_count: 1,
        manifest_sha256: null,
      },
      daemon: {
        version: "0.0.0-test",
        binary_sha256: "04".repeat(32),
      },
      enforcement: {
        total_allowed: 0,
        total_blocked: 1,
        rules: [{ rule_label: "05".repeat(32), allowed: 0, blocked: 1 }],
      },
      signer_kid: "castle-wall:test",
      signature: "test-signature",
      signature_algorithm: "Ed25519",
      payload_encoding: "domain-separated-canonical-json-v1",
      public_key: "test-public-key",
    };
  }

  function signedNote(rootHash: Uint8Array): string {
    const rootB64 = Buffer.from(rootHash).toString("base64");
    const fakeSignatureBlob = Buffer.from([0, 0, 0, 0, 1]).toString("base64");
    return (
      `rekor.fixture.test - 1066\n1\n${rootB64}\n\n` +
      `\u2014 rekor.fixture.test ${fakeSignatureBlob}\n`
    );
  }

  function anchorFixture(partial = false): {
    transparency: string;
    anchor: string;
  } {
    const record = checkpointRecord();
    const anchorKey = deriveAnchorSigningKey(generateRandomKey());
    const anchorPublicKey = anchorPublicKeyPem(anchorKey.publicKey);
    const salt = "11".repeat(32);
    const checkpointHash = checkpointPayloadHash(record);
    const preimage = anchorCommitmentPreimage({
      saltHex: salt,
      counter: record.counter,
      checkpointHash,
    });
    const commitment = anchorCommitmentDigestHex(preimage);
    const body = new TextEncoder().encode(
      canonicalJson(
        buildHashedRekordProposal({
          digestHex: commitment,
          signatureDer: signAnchorPreimage(anchorKey.privateKey, preimage),
          publicKeyPem: anchorPublicKey,
        })
      )
    );
    const leafHash = rfc6962LeafHash(body);
    const bodyB64 = Buffer.from(body).toString("base64");
    const receipt = {
      anchor_kind: "transparency-anchor-receipt",
      schema_version: 1,
      counter: record.counter,
      checkpoint_hash: checkpointHash,
      commitment_digest: commitment,
      rekor_url: "https://rekor.fixture.test",
      status: "anchored",
      anchored_at: "2026-04-02T10:00:01.000Z",
      rekor: {
        uuid: hex(leafHash),
        log_index: 0,
        log_id: "fixture-log",
        integrated_time: 1_760_000_000,
        ...(!partial ? { body_b64: bodyB64 } : {}),
        verification: {
          inclusionProof: {
            checkpoint: signedNote(leafHash),
            hashes: [],
            logIndex: 0,
            rootHash: hex(leafHash),
            treeSize: 1,
          },
        },
      },
    };
    return {
      transparency: JSON.stringify(
        {
          format: "SANCTUARY_TRANSPARENCY_BUNDLE_V1",
          exported_at: "2026-04-02T10:00:02.000Z",
          public_key: record.public_key,
          checkpoints: [record],
        },
        null,
        2
      ),
      anchor: JSON.stringify(
        {
          format: "SANCTUARY_TRANSPARENCY_ANCHORS_V1",
          exported_at: "2026-04-02T10:00:02.000Z",
          fortress_id: record.fortress_id,
          salt,
          anchor_public_key_pem: anchorPublicKey,
          rekor_url: "https://rekor.fixture.test",
          receipts: [receipt],
        },
        null,
        2
      ),
    };
  }

  function packWith(
    transparency: ReadOutcome<string>,
    anchor: ReadOutcome<string>
  ): EvidencePack {
    return buildEvidencePack(
      input({
        discrete_exports: {
          transparency,
          audit_chain: emptyVerified(),
          anchor,
        },
      }),
      deps(
        populated({
          entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );
  }

  it("declines the confirmation claim when the transparency bundle is absent", () => {
    // The Codex lens's real state: multi-key checkpoints make the bundle
    // ungatherable while anchor receipts still populate.
    const pack = packWith(
      readFailed(
        "the checkpoints carry more than one signing key; a single-key bundle could not be assembled."
      ),
      populated(JSON.stringify({ receipts: [{ counter: 2 }] }))
    );
    const text = reportText(pack);

    // The file IS shipped and IS signed -- that part was never the defect.
    expect(text).toContain(ANCHOR_EVIDENCE_FILENAME);
    // But the definitive confirmation claim must NOT be made.
    expect(text).not.toContain(
      "an auditor can confirm those checkpoints were publicly anchored"
    );
    expect(text).toContain("does NOT let an auditor confirm");
    expect(text).toContain("bundle is NOT included");
  });

  it("prints a caveat when the bundled receipt is internally consistent but lacks a pinned log key", () => {
    const fixture = anchorFixture();
    const pack = packWith(populated(fixture.transparency), populated(fixture.anchor));
    const text = reportText(pack);
    expect(text).not.toContain("can confirm those checkpoints were publicly anchored");
    expect(text).toContain("do NOT let an auditor confirm public anchoring offline");
    expect(text).toContain("0 log-key verified receipt(s), 1 internally consistent receipt(s)");
    expect(text).toContain("they do not support an offline public-anchoring confirmation");
  });

  it("prints a caveat when a bundled receipt is partial and unverified", () => {
    const fixture = anchorFixture(true);
    const pack = packWith(populated(fixture.transparency), populated(fixture.anchor));
    const text = reportText(pack);
    expect(text).not.toContain("can confirm those checkpoints were publicly anchored");
    expect(text).toContain("do NOT let an auditor confirm public anchoring offline");
    expect(text).toContain("1 unverified receipt");
    expect(text).toContain("receipt entry bodies and inclusion proofs");
  });

  it("the PDF carries the same gated claim as the Markdown", () => {
    const pack = packWith(
      readFailed("the checkpoints carry more than one signing key."),
      populated(JSON.stringify({ receipts: [{ counter: 2 }] }))
    );
    const text = pdfText(pack);
    expectPdfExtractionWorks(text);
    expect(text).not.toContain(
      "an auditor can confirm those checkpoints were publicly anchored"
    );
    expect(text).toContain("does NOT let an auditor confirm");
  });
});

// ── C-2 (MED): every out-of-quarter artifact declares its scope ──────────────

describe("D11 C-2: artifacts whose scope differs from the quarter declare it", () => {
  function packWithExports(): EvidencePack {
    return buildEvidencePack(
      input({
        discrete_exports: {
          transparency: populated(JSON.stringify({ checkpoints: [] })),
          audit_chain: populated('{"seq":1}\n'),
          anchor: populated(JSON.stringify({ receipts: [] })),
        },
      }),
      deps(
        populated({
          entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
          retention: retention(),
        })
      )
    );
  }

  it("the audit-chain export declares that it spans the whole retained log", () => {
    // The sharpest observed case: a signed "0 operations in the quarter" beside
    // a signed export holding 17 out-of-quarter records, with no disclosure.
    const text = reportText(packWithExports());
    expect(text).toContain(AUDIT_CHAIN_FILENAME);
    expect(text).toContain("NOT limited to 2026-Q1");
    expect(text).toContain("ENTIRE retained history across all quarters");
    // And it names why, so the reader understands rather than merely worries.
    expect(text).toContain("hash chain must be contiguous");
    // And warns off the exact wrong inference a reader would otherwise draw.
    expect(text).toContain("NOT comparable with the in-quarter");
  });

  it("the transparency bundle and anchor evidence declare their scope too", () => {
    const text = reportText(packWithExports());
    const declarations = [
      ...text.matchAll(/SCOPE: this file is NOT limited to 2026-Q1/g),
    ];
    // All three whole-history exports, not just the one the lens demonstrated.
    expect(declarations.length).toBe(3);
    expect(text).toContain(TRANSPARENCY_BUNDLE_FILENAME);
    expect(text).toContain(ANCHOR_EVIDENCE_FILENAME);
  });

  it("the tool inventory declares it is a generation-time snapshot", () => {
    const text = reportText(packWithExports());
    // The exec-summary bullet a reader actually reads, not just the section.
    expect(text).toMatch(/AI tools inventoried:[\s\S]{0,600}?SCOPE: this reflects/);
    expect(text).toContain("NOT as of 2026-Q1");
    expect(text).toContain("2026-07-19T00:00:00.000Z");
  });

  it("the scope declarations survive into the PDF", () => {
    const text = pdfText(packWithExports());
    expectPdfExtractionWorks(text);
    expect(text).toContain("NOT limited to 2026-Q1");
    expect(text).toContain("NOT as of 2026-Q1");
  });
});
