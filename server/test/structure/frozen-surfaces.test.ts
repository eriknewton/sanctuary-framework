/**
 * Frozen-surface guard (the Q1 "frozen-token tripwire").
 *
 * The single highest-severity risk in the pending l1-l4 -> named-layer rename:
 * the `l1`..`l4` tokens are doing TWO unrelated jobs that look identical to a
 * find-replace. As DIRECTORY/IMPORT-PATH strings they are safe to rename; as
 * WIRE / CRYPTO / AT-REST / EXPORT / DISPLAY literals they must survive
 * byte-for-byte, or existing fortress data stops decrypting and external
 * consumers break. A careless `s/l2/operational/` sweep would silently corrupt
 * the second kind, and it fails SILENTLY (fresh-install tests still pass).
 *
 * This gate asserts every frozen literal below still EXISTS verbatim in
 * server/src. It is a millisecond-fast tripwire that fires the instant a
 * rename/reorg removes one — long before (and cheaper than) the Phase-0 decrypt
 * fixtures. It is presence-only: it proves a frozen surface was not deleted/
 * renamed, not that its every byte is correct (the fixtures do that).
 *
 * PROVENANCE: the list was curated + verified by a multi-agent workflow
 * (extract from the module map / surface manifest / HKDF registry / a code
 * scan -> verify each occurs verbatim on main -> adversarial completeness
 * critic), 2026-06-14. Each entry was confirmed present at curation time.
 *
 * MAINTENANCE: if an INTENTIONAL change renames/removes one of these (e.g. a
 * deliberate API migration), the gate reds — that is the point. Update this
 * list in that same PR, as a conscious, reviewed decision. Never delete an
 * entry to make a red test pass without confirming the surface really moved.
 *
 * Deliberately EXCLUDED (false-safety as a substring presence-check, per the
 * curation's own "dropped" analysis): bare `L1`..`L4` and `1.0` (match prose/
 * type names everywhere); `audit-log` and `sovereignty-profile` (match the
 * UN-renamed filenames audit-log.ts / sovereignty-profile.ts, so the check can
 * never detect the crypto-purpose string changing); `!` and `.enc` (match
 * `!==` / `.encode` etc.); the `"l1" | "l2" | ...` union-type declarations
 * (whitespace-sensitive). The l-number-EMBEDDING labels below are kept: post-
 * rename their only match is the frozen label, so the guard activates exactly
 * when the rename happens.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

// Frozen literals that must exist verbatim in server/src, grouped by category.
const FROZEN_SURFACES: ReadonlyArray<string> = [
  // --- wire: MCP tool names + basename-dispatched bin aliases ---
  "l2_hardening_status",
  "l2_verify_isolation",
  "reputation_publish",
  "compliance_eu_ai_act_annex_iii_classify",
  "broker/request_token",
  "sanctuary_distress",
  "sovereignty_audit",
  "audit_export_siem",
  "shr_generate",
  "shr_verify",
  "shr_gateway_export",
  "verify-transparency",
  "verify-exit-bundle",
  "import-exit-bundle",

  // --- wire: field values / JSON keys / server names parsed by consumers ---
  "l1_cognitive",
  "l2_operational",
  "l3_selective_disclosure",
  "l4_reputation",
  "l3_disclosure",
  "sanctuary-broker",
  "application/did+json; charset=utf-8",
  "identity.sanctuaryprotocol.ai",
  "privacy-filter-tier-2",

  // --- public TS export symbols (root index.ts surface) ---
  "L1Status",
  "L2Status",
  "L3Status",
  "L4Status",
  "HOSTED_DID_PATH_RE",
  "STATE_ENVELOPE_SCHEMA_VERSION",

  // --- user-visible display / help strings ---
  "Cognitive Sovereignty",
  "Operational Isolation",
  "Selective Disclosure",
  "Verifiable Reputation",
  "Your agent is protected.",
  "hero-copy",

  // --- HKDF / crypto domain-separation labels (the at-rest decryption trap) ---
  // l-number-embedding labels (a layer rename must NOT touch these):
  "l2-context-gate",
  "l3-policies",
  "l3-commitments",
  "l4-reputation",
  "l2-recognition-hosted-did-web-v1",
  "l2-auto-trigger-rules-v1",
  "l2-anomaly-classifier-state-v1",
  "l2-english-policy-activation-v1",
  "l2-approval-aggregator-v1",
  "l2-approval-aggregator-payload-v1",
  "l2-query-anonymity-tier-b-v1",
  "l2-privacy-policies-v1",
  "l2-privacy-placeholders",
  "l2-privacy-placeholder-lookup",
  "l2-honeypot-trap-v1",
  "l2-sentinel-finding-v1",
  "key-17:x402-signer:v1",
  "key-17:erc8004-identity:v1",
  "key-17:ap2-mandate:v1",
  // cross-cutting crypto labels + signing domains:
  "intelligence-substrate-config",
  "sanctuary-fed-v0.1-transport",
  "cw-audit-producer-v1",
  "sanctuary.enforcement-checkpoint.v1",
  "sanctuary.audit-checkpoint.v1",
  "sanctuary.state-envelope.v1",
  "sanctuary.v1.operator-signed",
  "audit-head-anchor",
  "audit-rotation-anchor",
  "identity-encryption",
  "bridge-commitments",
  "federation-trust-root",
  "custody-envelope-mac",
  "custody-sentinel",
  "state-meta-mac",
  "principal-baseline",
  "transparency-counter-floor",
  "distress-inbox",
  "sanctuary-composition-v1",
  "sdw-catalog-v1",
  "sdw-document-corpus-v1",
  "sdw-working-state-v1",
  "sdw-query-history-v1",
  "sdw-vector-memory-v1",
  "sdw-replay-anchors-v1",
  "sdw-source-ref-v1",
  "sdw-memory-passage-content-v1",
  "sdw-replay-anchor-mac",
  "sanctuary.audit.v1",
  "sanctuary.receipt.v1",
  "sanctuary.transparency.anchor-commitment.v1",
  "sanctuary.meta-record-mac.v1",
  "sanctuary-fortress-mode-v1",
  "operator-chat-store-v1",
  "concierge-memory-store-v1",
  "principal-policy-unified-inbox-v1",
  "principal-policy-unified-inbox-operator-prefs-v1",
  "principal-policy-unified-inbox-retention-policy-v1",

  // --- persisted at-rest keys / namespaces (renaming orphans on-disk state) ---
  "SANCTUARY_EXIT_BUNDLE_V1",
  "_composition",
  "_intelligence",
  "_bridge",
  "_chat",
  "_recognition_hosted_did_web",
  "_sdw_catalog",
  "_sdw_document_corpus",
  "__custody_epoch_keys",
  "__head_anchor",
  "state-envelope-public-keys-v1",
  "_reputation",
  "_meta",
  "_query_anonymity_tier_b",
  "_query_anonymity_reverse_map",
  "_facade/hidden",

  // --- frozen versioned HTTP / served route paths ---
  "/v1/agents/protect",
  "/api/sentinels",
  "/v1.1",
  "/v1/status",
  "/api/console",
  "/api/distress",
];

/** All .ts source under server/src, concatenated once. */
function readServerSrcCorpus(): string {
  const parts: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) {
        parts.push(readFileSync(full, "utf-8"));
      }
    }
  };
  walk(SERVER_SRC);
  return parts.join("\n");
}

describe("frozen-surface guard", () => {
  it("every frozen wire/crypto/at-rest/export/display literal still exists verbatim in server/src", () => {
    const corpus = readServerSrcCorpus();
    // sanity: the walk actually read the tree
    expect(corpus.length).toBeGreaterThan(100_000);

    const missing = FROZEN_SURFACES.filter((literal) => !corpus.includes(literal));

    expect(
      missing,
      "Frozen surface(s) no longer present verbatim in server/src — a reorg or " +
        "layer rename may have changed a wire/crypto/at-rest/export/display literal " +
        "that must survive byte-for-byte (this would silently break decryption of " +
        "existing data or break external consumers). If the change was INTENTIONAL " +
        "(a deliberate API migration), update FROZEN_SURFACES in this same PR as a " +
        "reviewed decision:\n  " + missing.join("\n  "),
    ).toEqual([]);
  });

  it("the frozen-surface list has no duplicates", () => {
    const dupes = FROZEN_SURFACES.filter(
      (v, i) => FROZEN_SURFACES.indexOf(v) !== i,
    );
    expect(dupes, `duplicate entries: ${dupes.join(", ")}`).toEqual([]);
  });
});
