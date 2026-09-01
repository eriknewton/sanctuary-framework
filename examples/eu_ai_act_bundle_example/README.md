# EU AI Act Compliance Bundle: Example

This directory contains a fully generated EU AI Act compliance bundle
for a fictional Fortune 2000 enterprise (Meridian Financial Holdings, Inc.)
deploying a high-risk Annex III §4 HR screening agent.

**Everything in this directory is fictional.** No real entity, DID,
signature, or deployment is referenced.

## Purpose

This example shows what a Sanctuary-generated compliance bundle looks
like in its unfilled form, i.e., before the enterprise has replaced
the `[MANUAL INPUT REQUIRED: ...]` markers with their business
facts. An auditor, compliance lead, or evaluating enterprise can read
these files to understand:

- Which sections are fully auto-filled (the 5 `full` rows of the
  coverage matrix)
- Which sections are partially auto-filled (the 24 `partial` rows)
- Which sections require complete enterprise authoring (the 17
  `manual_only` rows)
- The format of the cryptographic attestations and manifest
- The honest voice of the generator: verbatim regulation quotes,
  explicit coverage flags, concrete evidence attribution per row

## Files

- `00_bundle_manifest.json`: signed JSON index with SHA-256 +
  Ed25519 signatures for every file, the 46-row coverage matrix
  summary, and the signer's public key
- `01_annex_iv_technical_documentation.md`: Annex IV per Article 11
- `02_article_26_deployer_log.md`: deployer obligations
- `03_article_12_automatic_logs.md`: automatic record-keeping
- `04_risk_management_summary.md`: Article 9 risk management
- `05_human_oversight_statement.md`: Article 14 human oversight
- `06_cryptographic_attestations.md`: bundle integrity summary

## Regenerating

```bash
cd server
GENERATE_EXAMPLE=1 npm test -- example-bundle
```

The fixture uses fixed master-key and identity-seed material so
regenerating this bundle produces byte-stable output (except for
differences introduced by matrix, template, or generator code
changes, which is exactly when regeneration is wanted).

## Not legal advice

The bundle format, verbatim regulation quotes, and coverage claims
in this example do not constitute legal advice. Consult qualified
legal counsel before filing any real compliance artifact with a
regulator.

_Author: Erik Newton · License: Apache-2.0_
