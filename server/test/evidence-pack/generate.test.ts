/**
 * Sanctuary MCP Server - Evidence Pack generator tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hermetic end-to-end tests for the pack generator: PDF renders without
 * throwing, every emitted file signature and the manifest signature verify
 * offline, the quarter aggregation is correct, and the covered-window shortfall
 * is disclosed honestly. Every read-dependent claim flows through a typed
 * ReadOutcome. Uses an in-memory storage backend + a real fortress identity;
 * never touches `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  buildEvidencePack,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import { canonicalJSON } from "../../src/evidence-pack/signer.js";
import { emptyInventorySnapshot } from "../../src/evidence-pack/inventory.js";
import {
  populated,
  emptyVerified,
  readFailed,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";
import type {
  EvidencePack,
  EvidencePackInput,
  QuarterAggregation,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";

let masterKey: Uint8Array;
let signer: StoredIdentity;

beforeEach(async () => {
  masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("acme-law", identityEncKey, "pw");
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

function entry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success",
  details?: Record<string, unknown>
): AuditEntry {
  return { timestamp, layer: "l2", operation, identity_id: "agent-a", result, details };
}

/** A gate entry marked as a HUMAN control-point decision (decided_by human). */
function humanEntry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success"
): AuditEntry {
  return entry(timestamp, operation, result, { decided_by: "human" });
}

const FULL_COVERAGE: RetentionFacts = {
  max_entries: 100_000,
  retained_total: 3,
  max_total_size_bytes: 100 * 1024 * 1024,
  retained_total_size_bytes: 0,
  ever_pruned: false,
  earliest_retained_at: "2026-06-01T00:00:00.000Z",
};

/** Deps with a populated audit read. */
function deps(
  entries: AuditEntry[],
  retention: RetentionFacts = FULL_COVERAGE
): BuildEvidencePackDeps {
  const audit: ReadOutcome<AuditReadData> = populated({ entries, retention });
  return { audit, signer, masterKey };
}

function baseInput(): EvidencePackInput {
  return {
    firm_name: "Acme Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
    custody: populated({
      custody_mode: "passphrase",
      outbound_denied_by_default: populated(true),
    }),
  };
}

function agg(pack: EvidencePack): QuarterAggregation {
  if (pack.aggregation.status !== "populated") {
    throw new Error("expected populated aggregation");
  }
  return pack.aggregation.value;
}

function coverage(pack: EvidencePack) {
  const c = pack.manifest.coverage;
  if (!c.determinable) throw new Error("expected determinable coverage");
  return c;
}

describe("buildEvidencePack", () => {
  it("renders a PDF that begins with the PDF header and ends with %%EOF", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf.startsWith("%PDF-1.4")).toBe(true);
    expect(pdf.includes("%%EOF")).toBe(true);
    expect(pack.pdf.length).toBeGreaterThan(1000);
  });

  it("signs every file and the manifest so a third party can verify offline", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const signerPub = fromBase64url(pack.manifest.signer.public_key_base64url);
    for (const file of pack.files) {
      const digest = hash(stringToBytes(file.content));
      expect(verify(digest, fromBase64url(file.signature), signerPub)).toBe(true);
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    const { manifest_signature, ...body } = pack.manifest;
    const manifestDigest = hash(stringToBytes(canonicalJSON(body)));
    expect(verify(manifestDigest, fromBase64url(manifest_signature), signerPub)).toBe(true);
  });

  it("counts quarter decisions correctly, ignoring out-of-window entries", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-06-30T00:00:00.000Z", "gate_allow:before"), // out
        entry("2026-08-01T00:00:00.000Z", "gate_allow:a"),
        entry("2026-08-02T00:00:00.000Z", "gate_deny:b"),
        entry("2026-08-03T00:00:00.000Z", "gate_approval_proof:c"),
        entry("2026-10-01T00:00:00.000Z", "gate_allow:after"), // out (end excl)
      ])
    );
    expect(agg(pack).total_in_window).toBe(3);
    expect(agg(pack).by_category.allowed).toBe(1);
    expect(agg(pack).by_category.denied).toBe(1);
    expect(agg(pack).by_category.human_approved).toBe(1);
  });

  it("discloses a covered-window shortfall in the manifest and the report", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        max_entries: 100,
        retained_total: 100, // at cap -> pruning likely
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: true,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
      })
    );
    expect(coverage(pack).shortfall).toBe(true);
    expect(coverage(pack).retention_at_cap).toBe(true);
    expect(pack.files[0]!.content).toContain("COVERAGE NOTICE");
  });

  it("N2: an all-post-quarter completed quarter cover banner says NONE covered, not the generic 'does not reach the start'", () => {
    const pack = buildEvidencePack(
      baseInput(), // generated_at 2026-10-02 (Q3 complete)
      deps([], {
        max_entries: 100_000,
        retained_total: 5,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: true,
        earliest_retained_at: "2026-11-01T00:00:00.000Z", // entirely after Q3
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("NONE of this quarter is covered");
    expect(report).not.toContain("does NOT reach the quarter start");
  });

  it("prints the honest coverage-basis and scope-and-limits language", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Coverage basis");
    expect(report).toContain("INVISIBLE to this inventory");
    expect(report).toContain("Scope and limits");
    expect(report).toContain("do not claim per-rule per-flow");
  });

  it("renders each section title into the PDF", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf).toContain("Executive summary");
    expect(pdf).toContain("AI tool inventory");
    expect(pdf).toContain("Scope and limits");
  });

  it("N1: counts human approvals AND human denials by decided_by; automated denials stay 'by policy'", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        humanEntry("2026-08-01T00:00:00.000Z", "gate_approve:tool_a"),
        humanEntry("2026-08-02T00:00:00.000Z", "gate_approve:tool_b"),
        humanEntry("2026-08-03T00:00:00.000Z", "gate_deny:tool_c", "failure"), // human denial
        entry("2026-08-04T00:00:00.000Z", "gate_deny:tool_e", "failure"), // automated denial
        entry("2026-08-05T00:00:00.000Z", "gate_allow:tool_d"),
      ])
    );
    expect(agg(pack).by_category.human_approved).toBe(2);
    expect(agg(pack).by_category.human_denied).toBe(1); // N1: real, not always 0
    expect(agg(pack).by_category.denied).toBe(1); // the automated one only
    const report = pack.files[0]!.content;
    expect(report).toContain("| Human-approved | 2 |");
    expect(report).toContain("| Human-denied | 1 |");
    expect(report).toContain("Denied by automated policy (no human) | 1");
    expect(report).not.toContain("Denied by policy |"); // old wrong wording
  });

  it("renders no phantom Escalated row", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    expect(pack.files[0]!.content).not.toContain("Escalated");
  });

  it("an in-progress quarter is stamped PARTIAL, shortfall:true, covered_to capped at generation time", () => {
    const pack = buildEvidencePack(
      {
        firm_name: "Acme Law LLP",
        quarter: { year: 2026, quarter: 3 },
        generated_at_override: "2026-08-15T12:00:00.000Z", // mid-Q3
        custody: populated({
          custody_mode: "passphrase",
          outbound_denied_by_default: populated(true),
        }),
      },
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        max_entries: 100_000,
        retained_total: 3,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: false,
        earliest_retained_at: "2026-06-01T00:00:00.000Z",
      })
    );
    expect(coverage(pack).in_progress_quarter).toBe(true);
    expect(coverage(pack).shortfall).toBe(true);
    expect(coverage(pack).covered_to_exclusive).toBe("2026-08-15T12:00:00.000Z");
    expect(coverage(pack).covered_to_exclusive).not.toBe("2026-10-01T00:00:00.000Z");
    expect(pack.files[0]!.content).toContain("PARTIAL QUARTER");
  });

  it("a POPULATED inventory still prints the coverage-basis + never-complete language", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: populated([
            {
              agent_id: "coding-bot",
              harness: "claude_code",
              model_vendor: "anthropic",
              model_id: "claude-opus-4",
              wrapped_at: "2026-07-15T00:00:00.000Z",
              status: "active",
            },
          ]),
          mcp_servers: populated([{ name: "filesystem", transport: "stdio", enabled: true }]),
          observed_destinations: populated([
            { host: "api.openai.com", port: 443, protocol: "tcp", times_seen: 3, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("coding-bot");
    expect(report).toContain("filesystem");
    expect(report).toContain("api.openai.com");
    expect(report).toContain("Coverage basis");
    expect(report).toContain("INVISIBLE to this inventory");
    expect(report).toContain("never be read as an exhaustive list");
    expect(report).toContain("What is NOT in this inventory");
    expect(report).toContain("NOT a complete census");
    expect(report).toContain("since decommissioned");
  });

  it("HIGH-1 (sample-render): the egress table cannot be read as a breach admission", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "paste.example-exfil.ru", port: 443, protocol: "tcp", times_seen: 2, exfil_risk: true },
            { host: "api.anthropic.com", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The bare, misreadable jargon is gone.
    expect(report).not.toContain("Exfil risk");
    expect(report).not.toMatch(/paste\.example-exfil\.ru.*\| yes \|/);
    // Replaced by a classification column + values that read as a category.
    expect(report).toContain("Destination risk class");
    expect(report).toContain("elevated (review)");
    expect(report).toContain("standard");
    // And an unmissable legend defining it as NOT a finding of exfiltration.
    expect(report).toContain("NOT a finding that any data left the firm");
    expect(report).toContain("NOT a confirmed exfiltration");
  });

  it("F1 (round-2 sweep): the egress table discloses its deny-only row basis", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.telegram.org", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: true },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The legend must state, adjacent to the table, that rows are BLOCKED
    // observations (not contacts) and that allowed egress is structurally
    // absent - closing both the self-incriminating and the flattering read.
    expect(report).toContain("BLOCKED flow observations only");
    expect(report).toContain("a destination the wall DENIED");
    expect(report).toContain("a count of those denied attempts");
    expect(report).toContain("This table never lists allowed egress");
    expect(report).toContain("Allowed egress is not inventoried");
    expect(report).toContain("not a census of where the machines' traffic actually went");
    // R3-1 re-truing (final, post two-family-gate engine hardening): the
    // legend claims the engine's VERIFIED-suppression semantics -- rows are
    // suppressed/cleared only for flows the engine can positively verify
    // the signed policy permits for the attempting agent (exact host/IP
    // allows, the promote workflow's shape) -- and explicitly discloses
    // that a row may remain listed when permission cannot be verified that
    // exactly. No falsifiable "permitted destinations never appear"
    // absolute survives.
    expect(report).toContain("positively verify the current");
    expect(report).toContain("for the agent that attempted it");
    expect(report).toContain("as of its most recent refresh");
    expect(report).toContain("clears any pending candidate");
    expect(report).toContain("may remain listed while its permission cannot be verified");
    expect(report).toContain("never that data was exchanged");
    expect(report).not.toContain("do NOT appear here");
  });

  it("OPEN-MED-1 + F2: the egress 'Seen' legend states its true basis (candidate-record lifetime, not quarter-scoped)", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.anthropic.com", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The legend must state the count's true basis adjacent to the table: the
    // current candidate record (discard/promote resets the count - F2), and
    // never quarter-scoped (OPEN-MED-1).
    expect(report).toContain("Legend - Seen:");
    expect(report).toContain("current candidate record was created");
    expect(report).toContain("later observed again restarts its count");
    expect(report).toContain(
      "NOT a count scoped to the reporting quarter"
    );
    expect(report).toContain(
      "may not have been seen within the reporting quarter"
    );
    // The falsifiable-under-reset absolute basis claim is gone.
    expect(report).not.toContain("since observation began on this install");
  });

  it("MED-1 (sample-render): the tool count carries an active/recorded denominator", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: populated([
            { agent_id: "live-bot", harness: "claude_code", status: "active" },
            { agent_id: "old-bot", harness: "generic_mcp", status: "retired" },
          ]),
          mcp_servers: populated([
            { name: "filesystem", transport: "stdio", enabled: true },
            { name: "legacy", transport: "stdio", enabled: false },
          ]),
          observed_destinations: emptyVerified(),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // 4 recorded (2 agents + 2 servers), 2 active (one agent active, one server enabled).
    expect(report).toContain("AI tools inventoried:** 4 recorded, of which 2 active");
    expect(report).toContain("NOT a count of live tools");
    // The bare "inventoried: 4 (" form is gone.
    expect(report).not.toMatch(/AI tools inventoried:\*\* 4 \(/);
  });

  it("an MCP read FAILURE renders incomplete-with-reason, never an affirmative 'none configured'", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: readFailed(
            "the sovereignty profile could not be read: decrypt failed"
          ),
          observed_destinations: emptyVerified(),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).not.toContain("No MCP tool servers are configured on this fortress.");
    expect(report).toContain("could not be read for this period, so this section is INCOMPLETE");
    expect(report).toContain("NOT a statement that none exist");
    expect(report).toContain("decrypt failed");
    // A genuinely-empty (empty_verified) source DOES get the affirmative census line.
    expect(report).toContain("No wrapped AI harnesses are recorded");
    // The exec summary flags the incomplete read (MCP source failed).
    expect(report).toContain("could not be fully determined this period");
  });

  it("the executive summary says 'configured', never 'connected', for MCP servers", () => {
    // R3-5: the definitive census wording requires an explicitly COLLECTED
    // (verified-empty) inventory; an absent inventory renders hedged
    // not-collected language with no census sentence at all.
    const pack = buildEvidencePack(
      { ...baseInput(), inventory: emptyInventorySnapshot() },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("configured AI tool servers");
    expect(report).not.toContain("connected AI tool servers");
  });

  it("MED-1: a failed inventory read never prints 'AI tools inventoried: 0' (routed through the gate)", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: readFailed("registry read failed"),
          mcp_servers: readFailed("profile read failed"),
          observed_destinations: readFailed("observe read failed"),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // No bare definitive zero for a failed read, in any form.
    expect(report).not.toContain("AI tools inventoried:** 0");
    expect(report).not.toContain("AI tools inventoried: 0");
    // Instead: "could not be fully determined", explicitly NOT a zero.
    expect(report).toContain("could not be fully determined this period");
    expect(report).toContain("This is NOT a count of zero.");
  });

  it("MED-1: an all-empty_verified inventory DOES print the definitive gated 0", () => {
    const pack = buildEvidencePack(
      // R3-5: the definitive 0 now requires an EXPLICIT verified-empty
      // inventory (every source actually read, each empty) -- it is no longer
      // the default for an input that supplied no inventory at all.
      { ...baseInput(), inventory: emptyInventorySnapshot() },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("AI tools inventoried:** 0");
    expect(report).toContain("NOT a claim that the firm uses no AI tools");
  });

  it("R3-5: an input with NO inventory renders hedged not-collected language, never a definitive census minted from nothing", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    // No definitive zero census from an inventory nobody collected.
    expect(report).not.toContain("AI tools inventoried:** 0");
    expect(report).not.toContain("No wrapped AI harnesses are recorded");
    expect(report).not.toContain("No MCP tool servers are configured");
    // Hedged instead: could-not-be-determined with the not-collected reason.
    expect(report).toContain("could not be fully determined this period");
    expect(report).toContain("This is NOT a count of zero.");
    expect(report).toContain("not collected");
  });

  it("R3-2: the covered-window line and Scope-and-limits disclose retention-span vs recording-liveness", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    // The section-7 covered-window sentence carries the liveness clause: the
    // window reflects what the retained log SPANS, and does not by itself
    // prove the stack was recording throughout it.
    expect(report).toContain("reflects what the retained audit log spans");
    expect(report).toContain(
      "does not by itself prove the enforcement stack was running and recording"
    );
    // And the mandatory Scope-and-limits page names the class directly.
    expect(report).toContain(
      "A covered window proves retention span, not recording liveness."
    );
    expect(report).toContain(
      "zero recorded decisions in a period does not mean zero AI"
    );
  });

  it("LOW-1: the total bullet is labeled 'audit operations' and splits out non-decision 'other'", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-08-01T00:00:00.000Z", "gate_allow:x"),
        entry("2026-08-02T00:00:00.000Z", "identity_create"), // 'other'
      ])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Total recorded audit operations in the quarter");
    expect(report).not.toContain("Total recorded control-point decisions in the quarter");
    // Splits 2 total into 1 control-point decision + 1 other.
    expect(report).toContain("1 control-point decisions + 1 other recorded operations");
  });

  it("CHOKEPOINT: a read_failed audit source never renders a definitive negative", () => {
    const pack = buildEvidencePack(baseInput(), {
      audit: readFailed("the audit log could not be read: decrypt failed"),
      signer,
      masterKey,
    });
    const report = pack.files[0]!.content;
    // Aggregation + shortfall are read_failed.
    expect(pack.aggregation.status).toBe("read_failed");
    expect(pack.shortfall.status).toBe("read_failed");
    // The manifest coverage is non-determinable - NOT a false "shortfall: false".
    expect(pack.manifest.coverage.determinable).toBe(false);
    // The report asserts NO decision counts and NO full-quarter coverage.
    expect(report).toContain("could NOT be computed");
    expect(report).toContain("decrypt failed");
    expect(report).toContain("COVERAGE UNAVAILABLE");
    // It never claims zero denials or full coverage.
    expect(report).not.toContain("Denied by automated policy (no human) | 0");
    expect(report).not.toMatch(/Covered window attested for this quarter/);
  });

  it("CHOKEPOINT: a custody read_failed renders incomplete, not a definitive fact table", () => {
    const pack = buildEvidencePack(
      { ...baseInput(), custody: readFailed("custody probe failed") },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("The per-install custody facts could not be read");
    expect(report).toContain("custody probe failed");
    // The definitive custody fact table is omitted.
    expect(report).not.toContain("| Master-key custody |");
  });

  it("surfaces an UNCATEGORIZED gate op honestly, never folded into a flattering total", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-08-01T00:00:00.000Z", "gate_allow:x"),
        entry("2026-08-02T00:00:00.000Z", "gate_frobnicate:y"), // unknown gate op
      ])
    );
    expect(agg(pack).by_category.uncategorized).toBe(1);
    expect(agg(pack).by_category.allowed).toBe(1);
    expect(agg(pack).by_category.other).toBe(0);
    const report = pack.files[0]!.content;
    expect(report).toContain("Uncategorized control-point operations");
  });

  it("HIGH-2: an un-probed outbound posture renders 'not determinable', NEVER a hardcoded 'yes'", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        custody: populated({
          custody_mode: "unknown",
          outbound_denied_by_default: readFailed("not probed by this build"),
        }),
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("not determinable for this install");
    // The custody row must not assert a definitive "denied by default | yes".
    expect(report).not.toMatch(/outbound denied by default \| yes/i);
  });

  it("HIGH-2: a probed outbound=true scopes the claim to Sanctuary's gateway, not machine-level", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        custody: populated({
          custody_mode: "passphrase",
          outbound_denied_by_default: populated(true),
        }),
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Sanctuary-gateway outbound denied by default");
    expect(report).toContain("does NOT deny egress from other applications");
  });

  it("HIGH-3: the incident line is 'not assessed', NEVER a flattering 'none surfaced'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).not.toContain("Unresolved incidents:** none");
    expect(report).not.toContain("none surfaced");
    expect(report).toContain("Incidents:** not assessed in this build");
  });

  it("HIGH-4: the cover uses evidence-toward framing, not 'answers, one for one' + 'without trusting the vendor'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).not.toContain("answers, one for one, the five questions");
    expect(report).not.toContain("verify the underlying evidence without trusting");
    expect(report).toContain("organized around the five questions");
    // Placeholder sections are named on the cover.
    expect(report).toContain("governance-policy, training, and incident-response sections are placeholders");
  });

  it("HIGH-4: placeholder CNA subtitles say 'Maps to' + 'NOT included', not 'Answers'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).toContain("Maps to CNA Question 2");
    expect(report).toContain("Maps to CNA Question 5");
    expect(report).not.toContain("Answers CNA Question 2");
    expect(report).not.toContain("Answers CNA Question 5");
  });

  it("round-2 wording: 'vendor-independent' (not 'firm-independent'); data-export is an architecture property", () => {
    const pack = buildEvidencePack(baseInput(), deps([])); // no discrete exports
    const report = pack.files[0]!.content;
    expect(report).not.toContain("firm-independent");
    expect(report).toContain("vendor-independent");
    // Data-export is labeled a product property, not a per-install table value.
    expect(report).toContain("a product property, not a per-install read");
    expect(report).not.toContain("| Data export | requires human (Tier 1) approval |");
  });
});
