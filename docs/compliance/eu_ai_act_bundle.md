---
title: EU AI Act Compliance Artifact Generator
description: Generate signed Annex IV / Article 12-26 compliance artifacts from your Sanctuary agent runtime
---

# EU AI Act Compliance Artifact Generator

**Status:** available from Sanctuary Framework v0.8.0
**License:** Apache-2.0
**Author:** Erik Newton
**Regulation alignment:** Regulation (EU) 2024/1689, as of 2026-04-10

**This tool produces technical compliance artifacts; it is NOT legal advice and does not constitute a legal interpretation of Regulation (EU) 2024/1689. Consult qualified legal counsel before filing or relying on the generated bundle for any regulatory submission.**

---

## What it does

The EU AI Act Compliance Artifact Generator is a Sanctuary MCP tool (and matching CLI subcommand) that translates your agent's Sanctuary runtime state into a bundle of eight compliance documents (plus an optional ninth when delta mode is enabled):

| File | Regulatory anchor |
|---|---|
| `00_bundle_manifest.json` | Signed index with coverage matrix, file digests, and Ed25519 signatures |
| `01_annex_iv_technical_documentation.md` | Annex IV technical documentation per Article 11 |
| `02_article_26_deployer_log.md` | Deployer obligations per Article 26 |
| `03_article_12_automatic_logs.md` | Automatic record-keeping per Article 12 + retention per Article 19(1) |
| `04_risk_management_summary.md` | Risk management per Article 9 + Annex IV §5 |
| `05_human_oversight_statement.md` | Human oversight per Article 14 + Annex IV §2(e) |
| `06_cryptographic_attestations.md` | Bundle integrity summary |
| `07_annex_iii_classification.md` | Rule-based Annex III candidate classification (always included) |
| `08_delta.md` | *(conditional)* Delta report against a prior bundle, when `--delta-from` is supplied |
| `bundle.pdf` | *(conditional)* Hand-rolled PDF render of the Markdown bundle, when `--pdf` is supplied |

The generator does **not** invent evidence. Every piece of auto-filled content is pulled from the live Sanctuary instance (SHR, audit log, Principal Policy, context gating, identity manager) and every claim is traceable to a specific MCP tool call that an auditor can reproduce independently.

Fields that Sanctuary cannot know (the agent's intended purpose, the enterprise's legal name, the Annex III classification, training data lineage, operator training records, and so on) are left as explicit `[MANUAL INPUT REQUIRED: hint]` markers in the generated Markdown. The enterprise replaces these markers with their business facts before filing.

## Phase 2 additions: classification, delta, publish, PDF

Four optional capabilities extend the Phase 1 bundle generator. All four respect the non-dependency principle: none of them is required for bundle generation, and failure in any Phase 2 layer never prevents the core Markdown bundle from landing locally.

### Annex III classification helper

The generator ships with a rule-based Annex III classifier that reads the `deployment_context.intended_purpose` field and scores it against all eight Annex III high-risk categories (and their sub-points) of Regulation (EU) 2024/1689. Matching keywords come from a structured catalog in `server/src/compliance/eu_ai_act/annex_iii.ts` with coarse discrete weights (1.0 / 0.6 / 0.3), and candidates clearing a 0.4 minimum threshold are reported in document `07_annex_iii_classification.md` ordered by `rule_based_confidence` descending.

**The confidence field is deliberately named `rule_based_confidence`, not `confidence` or `probability`**, so downstream consumers cannot mistake it for a machine-learning model prediction. The classifier is keyword-weighted, fully auditable against the catalog, and makes no claims of statistical calibration. An empty result does **not** mean the agent is out of scope of the EU AI Act. It means the keyword catalog found no clear match and the deployer must perform manual review.

The classifier is also exposed as a standalone MCP tool:

```
Tool: compliance_eu_ai_act_annex_iii_classify
Input: { description: string }
Output: ClassificationResult
```

Useful when you want to score a candidate agent description without generating a full bundle.

### Delta mode

Supply `--delta-from <path>` on the CLI, or `delta_from_bundle_path` on the MCP tool, to compare the new bundle against a prior one on disk. The generator loads `{path}/00_bundle_manifest.json`, diffs the coverage rows, and emits `08_delta.md` summarising:

- Whether `regulation_version` bumped (external regulation text change)
- Whether `matrix_version` bumped (structural matrix change)
- Which rows were added, removed, or changed
- For changed rows: the specific `coverage` flag transition and `evidence_emitter[]` changes

**Delta problems never fail bundle generation.** If the prior bundle path is unreachable, the manifest is malformed, or the file is missing entirely, the delta is skipped silently (with a warning logged to the audit trail) and the bundle lands locally as usual. This lets you run delta mode unconditionally in a rolling-compliance cron job without building a dependency on prior-bundle availability.

### Verascore publish hook

Supply `--publish-to-verascore` on the CLI, or `publish_to_verascore: true` on the MCP tool, to POST the signed manifest to Verascore as a post-generation side effect. This publishes only the manifest: the document bodies never leave the local filesystem. The publish uses the same wire format and signing path as the existing `reputation_publish` tool: allow-listed Verascore hosts only (HTTPS, `verascore.ai` / `www.verascore.ai` / `api.verascore.ai`), canonical JSON of the manifest signed with the provider's primary Ed25519 identity via the existing `core/identity.js` sign primitive.

**Publish failure never fails bundle generation.** If the network is unreachable, Verascore returns a non-2xx status, or the URL fails SSRF validation, the publish outcome is captured in `publish_result` on the returned bundle and the bundle is returned in the same shape. Sanctuary never starts requiring Verascore to be online. This is the non-dependency principle applied to the publish layer.

### PDF render

Supply `--pdf` on the CLI to additionally render the Markdown bundle into a single `bundle.pdf` file in the output directory. The PDF is produced by a hand-rolled minimal PDF writer (zero new dependencies) using the Courier and Courier-Bold standard PDF Type1 fonts: no font embedding, no font metric tables, no Puppeteer/Chromium. The output is clean monospace typography with a cover page, per-document page breaks, and a footer on every page showing the manifest SHA-256 identifier prefix and page number.

**The PDF is NOT cryptographically signed.** Integrity verification remains with the Markdown files and the JSON manifest. The PDF is a human-readable render of those already-signed artifacts. See `examples/eu_ai_act_bundle_example/bundle.pdf` for a visual reference.

## Honest coverage posture

The coverage matrix classifies every row of the regulation into one of three flags:

| Flag | Count | Meaning |
|---|---|---|
| **Full** | 5 rows (11%) | Auto-emitted from Sanctuary tool output alone. Zero enterprise input required. Machine-verifiable against a live Sanctuary instance by running the listed `evidence_emitter` tools. |
| **Partial** | 24 rows (52%) | Sanctuary emits structured evidence (principal policy, audit summary, SHR capability report, etc.). Enterprise supplies business context via the `[MANUAL INPUT REQUIRED]` markers. |
| **Manual only** | 17 rows (37%) | Sanctuary has no visibility. The enterprise authors the section in full. |

**Total: 46 rows across Annex IV + Articles 12, 13, 14, 15, 19(1), and 26.**

The full row list, the core rows of the bundle, is:

1. Annex IV §2(h): Cybersecurity measures (description)
2. Article 12(1): Automatic logging of events over lifetime
3. Article 12(2)(a): Logs enable post-market monitoring per Article 72
4. Article 12(2)(b): Logs facilitate operation monitoring per Article 26(5)
5. Article 15(5) first subparagraph: Resilience against unauthorised third-party alteration

Every other row is either partial or manual-only. If you see a claim of "full coverage" that does not match this list, the coverage matrix has been modified and the claim needs re-verification.

See [`docs/compliance/eu_ai_act_coverage_matrix_v1.md`](./eu_ai_act_coverage_matrix_v1.md) for the complete row-by-row mapping.

## Usage

### CLI

```bash
sanctuary-mcp-server compliance eu-ai-act <agent-did> [flags]
```

Example (full Phase 1 + Phase 2 workflow):

```bash
sanctuary-mcp-server compliance eu-ai-act \
  did:sanctuary:my-hr-agent \
  --provider-name "Meridian Financial Holdings, Inc." \
  --provider-contact "ai-compliance@meridian.example.com" \
  --annex-iii-class "§4 employment, workers management, self-employment" \
  --intended-purpose "Automated CV screening and candidate shortlisting" \
  --vertical human_resources \
  --period-start 2026-04-01T00:00:00Z \
  --period-end 2026-04-30T23:59:59Z \
  --output ./april-compliance-bundle \
  --delta-from ./march-compliance-bundle \
  --publish-to-verascore \
  --pdf
```

The `--delta-from` flag points at the previous month's bundle directory to produce a rolling delta report; `--publish-to-verascore` posts the signed manifest to Verascore as an attestation of bundle existence; `--pdf` writes a monospace PDF render alongside the Markdown files. All three are optional and can be omitted independently.

The CLI will:

1. Start a Sanctuary server instance (stdio transport, no external ports opened).
2. Load the primary Ed25519 identity from the configured storage path.
3. Walk the audit log for the reporting period.
4. Render the six Markdown documents and sign each with the primary identity.
5. Build the manifest, sign it canonically, and write all seven files to the output directory.
6. Print a summary on stderr (output path on stdout for scripting pipelines).

**Required state before first run:**
- A Sanctuary instance with at least one identity (`identity_create` + `identity_set_primary`).
- A master key or passphrase reachable via `--passphrase` or `SANCTUARY_PASSPHRASE`.
- Audit log entries for the reporting period (otherwise the audit summary tables will be all zeros).

### MCP tool

The same functionality is exposed as an MCP tool for agent-initiated compliance generation:

```
Tool: compliance_generate_eu_ai_act_bundle

Input:
  agent_did:          string   : DID of the agent
  deployment_context: object   : enterprise-supplied facts
  period_start:       string   : ISO 8601
  period_end:         string   : ISO 8601

Output:
  bundle_version, matrix_version, regulation_version,
  generated_at, agent_did, period, signer,
  coverage_summary (5/24/17 + percentages),
  file_count, files[{filename, sha256, signature, content_length}],
  manifest_signature,
  _bundle_content.{manifest, files[{filename, content}]}
```

The tool is classified Tier 3 (auto-allow with audit logging) in the default Principal Policy: it is read-only and emits documents from existing state without modifying anything.

## Verifying a generated bundle

Every file in the bundle is SHA-256 hashed and Ed25519-signed. A verifier can independently check the bundle using any standard SHA-256 tool (no Sanctuary knowledge required):

```bash
# Recompute SHA-256 of each file and compare to the manifest
for f in 0[1-6]_*.md; do
  computed=$(shasum -a 256 "$f" | awk '{print $1}')
  recorded=$(jq -r ".files[] | select(.filename == \"$f\") | .sha256" 00_bundle_manifest.json)
  [[ "$computed" == "$recorded" ]] && echo "✓ $f" || echo "✗ $f (mismatch)"
done
```

See the example bundle at [`examples/eu_ai_act_bundle_example/verify.sh`](../../examples/eu_ai_act_bundle_example/verify.sh) for a working verification script.

To verify Ed25519 signatures, use any Ed25519 library with the `signer.public_key_base64url` field from the manifest.

## Known caveats (disclosed honestly)

These are specific to Sanctuary v0.7.0+ and are documented per-row in the coverage matrix:

1. **Audit log entries are not Ed25519-signed**: authenticated encryption (AES-256-GCM) provides integrity against third-party tampering but not non-repudiation against a compromised-master-key insider.

2. **Audit log persistence is fire-and-forget**: if disk write fails, the entry lives only in memory and is lost at process exit. Mitigation: run Sanctuary on reliable storage and monitor for write failures.

3. **Injection detector configuration state is not directly queryable**: the detector runs in the Principal Policy gate but has no MCP status tool in v0.7.0. Its activity is evidenced indirectly via `injection_detected:*` entries in the audit log.

4. **No TEE attestation**: Sanctuary self-reports its execution environment. The SHR degradation flag `NO_TEE` is set automatically. Mitigation: deploy on TEE-capable hardware where the deployment context demands it.

5. **Log retention is deployer-declared**: Sanctuary captures indefinitely by default; the deployer configures archival to meet the Article 19(1) six-month minimum.

The Article 12 document in every bundle discloses these caveats in a "Known Caveats and Residual Risk" section for audit transparency.

## How the coverage matrix stays honest

The coverage matrix is versioned (`v1`) and aligned to the OJ-published text of Regulation (EU) 2024/1689. Every row carries:

- `last_reviewed_date` and `last_reviewed_by` (per-row freshness)
- `review_notes` with the classification rationale (important for future maintainers)
- `evidence_emitter[]` listing the exact MCP tool names that emit the evidence, every name verified against the v0.7.0 registered tool set at matrix creation time

When the European Commission publishes implementing acts or delegated acts that modify the applicable requirements, the matrix must be re-reviewed. The `next_review_due` field at the top of the matrix forward-commits the review cadence. Bumping `REGULATION_VERSION` is the signal that the aligned regulation text has changed; the matrix `matrix_version` bumps only when the schema or row set changes structurally.

## Relationship to legal signatures

The cryptographic signatures in the bundle are **runtime authenticity attestations**, not legal signatures. They prove the bundle was emitted by the named Sanctuary instance and has not been altered since generation. The EU declaration of conformity under Article 47 requires a legal signature from the provider's legal representative: the Sanctuary signature is complementary, not a substitute.

A typical filing workflow:

1. Generate the bundle via the CLI or MCP tool.
2. Fill in every `[MANUAL INPUT REQUIRED]` marker with enterprise-supplied business context.
3. Have the completed documents reviewed by internal legal counsel.
4. Obtain the legal signature from the provider's legal representative.
5. Archive the Sanctuary-signed bundle alongside the legally-signed version for long-term retention.
6. Feed the SIEM-compatible audit exports (`audit_export_siem`) into the enterprise's Article 72 post-market monitoring pipeline.

---

## Related documents

- [`docs/compliance/eu_ai_act_coverage_matrix_v1.md`](./eu_ai_act_coverage_matrix_v1.md): complete row-by-row coverage mapping
- [`examples/eu_ai_act_bundle_example/`](../../examples/eu_ai_act_bundle_example/): fictional Fortune 2000 HR screening bundle
- [`examples/eu_ai_act_bundle_example/README.md`](../../examples/eu_ai_act_bundle_example/README.md): how to read the example
- [`examples/eu_ai_act_bundle_example/verify.sh`](../../examples/eu_ai_act_bundle_example/verify.sh): SHA-256 verification script

---

_NOT LEGAL ADVICE. This document describes a technical compliance artifact generator; it is not a legal interpretation of Regulation (EU) 2024/1689. Consult qualified legal counsel before regulatory submission._

_Sanctuary Framework · Author: Erik Newton · License: Apache-2.0_
