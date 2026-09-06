# Third-party notices

## SPDX License List data 3.28.0

Sanctuary's inert SPDX lookup table is generated from a deterministic minimal
projection containing only identifier/deprecated-status pairs and the list
version/release date. The repository and npm package do not redistribute the
full JSON summaries published by the SPDX `license-list-data` project. A normal
offline build verifies the committed fact-only projection and generated table.

- project: SPDX License List
- repository: `https://github.com/spdx/license-list-data`
- annotated release tag: `v3.28.0`
- tag object: `779ef2e5dff6d4af389c53de5e97116ab0bb52e8`
- source commit: `c4a7237ec8f4654e867546f9f409749300f1bf4c`
- release date declared by both summaries: `2026-02-20T00:00:00Z`
- license summary source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/licenses.json`
- license summary raw SHA-256:
  `f728c534d8bd1044fc515a2ddb2292be99559021d830bfa3281be0bcd36302ee`
- license summary canonical-JSON SHA-256:
  `677f3480a6f3c26e7583e0ce41e9f486af91fcd3550de2eb6b8f4827e02589de`
- exception summary source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/exceptions.json`
- exception summary raw SHA-256:
  `bd145bb558f44432fcd6f0d7e956ed0124dff72af7641a7cfcb1b557dc390a5b`
- exception summary canonical-JSON SHA-256:
  `ce36f1adeeaf719982fa9d2ca5134872904febfb09308b3d588456764ce16a12`
- release README source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/README.md`
- release README raw SHA-256:
  `9d5e2eaa0daa05418074f90201d1e320fd3792018fe1a2ffdc3ebf69c9fffc44`
- committed fact-projection raw SHA-256:
  `a9517d7e516498a8adec3c07fa95cc6702c80c88e9d7381f1b667bfbf92c1c5e`
- generated identifier/deprecation table SHA-256:
  `57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1`

The pinned `license-list-data` tag contains no repository-level LICENSE file.
Its README states that the data is generated from SPDX's `license-list-XML`
repository and directs consumers to the source and publisher repositories for
licensing information. The corresponding official SPDX License List page
carries this notice: “© 2018 SPDX Workgroup a Linux Foundation Project. All
Rights Reserved.” Sanctuary therefore does not assert a broader upstream
license grant and does not commit or publish the full summaries. Its minimal
projection retains only standardized identifiers, deprecation flags, version,
and release date needed for deterministic validation. SPDX and Software
Package Data Exchange are registered trademarks of The Linux Foundation.

The raw and canonical JSON hashes above are the integrity roots for an
externally supplied refresh. The tag-object and source-commit ids are reviewed
provenance attestations; they are not computed from and do not independently
authenticate the downloaded bytes.

The generator verifies exact raw and canonical source hashes, exact source
shape and release metadata, unique identifiers and reference numbers, canonical
SPDX URLs, 727 license rows (32 deprecated), 84 exception rows (one deprecated),
and the independently pinned generated-table digest.

## Sanctuary-authored profile grammar

`dist/intelligence/catalog-v3/spdx/spdx-expression-3.0.1.abnf` is
Sanctuary-authored Apache-2.0 material. It documents Sanctuary SPDX expression
profile v1, a deliberately narrower grammar that uses SPDX 3.0.1 vocabulary.

## Reproducible refresh

1. Review a new immutable SPDX `license-list-data` annotated release tag; pin
   both the tag-object id and its dereferenced source commit.
2. Download only `json/licenses.json`, `json/exceptions.json`, and the release
   README from that tag into a temporary directory outside the repository. Pin
   all three URLs and raw hashes here; pin the two summary raw/canonical hashes
   in the generator. Never commit the full summaries.
3. Verify the exact release version/date, source shapes, canonical hashes, 727
   license rows/32 deprecated, 84 exception rows/one deprecated, case-folded
   uniqueness, reference-number uniqueness, URL bindings, and deprecation
   status before changing the independent generated-table digest.
4. Run `node scripts/copy-catalog-v3-assets.mjs --write --refresh-source-dir
   /absolute/path/to/downloads`, review the exact minimal-projection and
   generated-table diffs, and pin the projection raw hash, table-content digest,
   and generated-source raw hash in the generator. If schemas or the ABNF changed, regenerate every
   raw/JCS/source-asset digest and independently repin the manifest raw hash.
5. Reconfirm the mechanically measured 61 module directories and 53 barrels in
   `src/README.md`, `CONTRIBUTING.md`, and the package gate.
6. Run the independent Python parity verifier, focused schema/package tests,
   typecheck, lint, build, and packed ESM/CJS consumer tests. The normal
   `npm test` path also re-derives the table in `pretest` without network access.
