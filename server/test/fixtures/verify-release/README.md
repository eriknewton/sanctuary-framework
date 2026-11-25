# verify-release fixtures

Captured for the `sanctuary verify-release` tests. Tests read these files
offline; no test fetches anything.

| File | Source | Fetched (UTC) | sha256 |
|---|---|---|---|
| `attestations-1.8.4.json` | `https://registry.npmjs.org/-/npm/v1/attestations/@sanctuary-framework%2fmcp-server@1.8.4` | 2026-11-25 (coordinator capture) | `690c958ec44eafded87b952b452ab8883288351e56784d545448b7df31868092` |
| `version-1.8.4.json` | `https://registry.npmjs.org/@sanctuary-framework/mcp-server/1.8.4` | 2026-11-25T18:43:02Z | excerpt, see below |
| `release-manifest-1.8.4.json` | `https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/release-manifest.json` (one redirect to `release-assets.githubusercontent.com`) | 2026-11-25T18:43:02Z | `382443a04ab67cc936a522f05fec017fee063ac900b748dc07d55963bb2b1c1b` |
| `attestations-sigstore-verify-4.1.4.json` | `https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fverify@4.1.4` | 2026-11-25T18:43:13Z | `8ebac2405e4bc5c1eb3bc045d3e56735bb5831f34f5a9cc67561004750aac44a` |

- `attestations-1.8.4.json` holds npm's publish attestation and the SLSA
  provenance bundle for 1.8.4.
- `version-1.8.4.json` is an excerpt: the `name`, `version` and `dist` fields of
  the version document, byte-identical values, re-serialized with two-space
  indentation. Maintainer fields are left out. The full document's sha256 at
  capture was `8bd05b2a400dd2585a721a2dc1729c4f2f225904716211533fab06dc8c85a8a5`.
- `attestations-sigstore-verify-4.1.4.json` is the foreign package: provenance
  from another repository (`sigstore/sigstore-js`, workflow `release.yml`,
  trigger `push`). Its SLSA bundle passes the cryptographic check and is
  refused at the identity step.
- The Sigstore trusted root is not duplicated here. The tests read the
  committed production copy, `server/src/verify-release/trusted_root.json`,
  whose source and sha256 are in `server/src/verify-release/README.md`.
