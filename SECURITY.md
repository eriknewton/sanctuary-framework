# Security Policy

Sanctuary is sovereignty and security infrastructure for AI agents. We take
the security of the framework, and of the operators who run it, seriously.
This document describes how to report a vulnerability, what to expect when you
do, and the safe-harbor commitment we extend to good-faith researchers.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Public
disclosure before a fix is available puts operators at risk.

**Primary channel: GitHub Private Vulnerability Reporting.** Use the
**"Report a vulnerability"** button on the repository
[Security tab](https://github.com/eriknewton/sanctuary-framework/security/advisories/new).
This opens a private advisory visible only to you and the maintainer, keeps the
full disclosure thread in one place, and lets us collaborate on a fix and a
coordinated release without exposing details prematurely.

**Fallback channel.** If you cannot use Private Vulnerability Reporting (for
example, you do not have a GitHub account), email **eriknewton@gmail.com** with
the subject line prefix `[SANCTUARY-SECURITY]`. We will move the conversation
into a private advisory as soon as practical.

Please include, to the extent you can:

- the affected component and version (for example `@sanctuary-framework/mcp-server@1.8.4`, the Castle Wall daemon, or the macOS system extension),
- a description of the vulnerability and its impact,
- step-by-step reproduction instructions or a proof-of-concept,
- any relevant logs, configuration, or environment details, and
- your assessment of severity, if you have one.

## Response SLA

The same expedited SLA stated in [`GOVERNANCE.md`](GOVERNANCE.md) applies to
security reports:

| Stage | Target |
|---|---|
| **Initial acknowledgment** | within **24 hours** for a report assessed as Critical; within 72 hours otherwise |
| **Triage and severity assessment** | within 3 business days of acknowledgment |
| **Fix or mitigation plan** | communicated as soon as triage completes; timeline scales with severity |
| **Coordinated disclosure** | by mutual agreement, after a fix or mitigation is available |

Sanctuary is currently maintained by a single author (see
[`GOVERNANCE.md`](GOVERNANCE.md)). Critical reports are prioritized over all
other project work.

## Supported Versions

Security fixes are released against the current `latest` line on npm. Older
minor lines are not maintained; please upgrade to the supported version before
reporting an issue you cannot reproduce on it.

| Version | Supported |
|---|---|
| `1.8.x` (npm `latest`, currently `1.8.4`) | :white_check_mark: |
| `1.8.6-rc.*` (npm `next`, currently `1.8.6-rc.5`) | :warning: pre-release; a fix lands in the next `1.8.x` release, and no rc is patched in place |
| `< 1.8` | :x: |

The npm `latest` dist-tag is the authoritative pointer to the currently
supported release. Pre-release (`-rc`) and `next`-tagged builds are not covered
by this policy beyond the note above.

## What NOT To Do

- Do **not** open a public issue, pull request, or discussion that describes the
  vulnerability before a fix is released.
- Do **not** post details on social media or any other public channel before
  coordinated disclosure.
- Do **not** access, modify, or exfiltrate data that is not yours; do not run
  attacks against other operators' fortresses or any infrastructure you do not
  own; and do not degrade service for other users while testing.

## Safe Harbor

We will not pursue or support legal action against, and we consider authorized,
any security research that is conducted in good faith and in accordance with
this policy. Specifically, if you:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service degradation,
- test only against systems you own or are explicitly authorized to test,
- give us reasonable time to remediate before any public disclosure, and
- do not exploit a finding beyond the minimum necessary to demonstrate it,

then we will treat your research as authorized, will work with you to understand
and resolve the issue quickly, and will publicly acknowledge your contribution
if you wish. If legal action is initiated by a third party against you for
activity that complied with this policy, we will make this authorization known.

This safe harbor applies to the code and infrastructure in this repository.
It does not authorize testing against third-party services (for example a
reputation endpoint or an upstream MCP provider) that Sanctuary may compose
with; those are governed by their own policies.

## Verify Before You Trust

Each release of `@sanctuary-framework/mcp-server` can be checked before it is
installed, with no network beyond the npm registry and GitHub; the `curl` form
below needs no account, and `gh release download` needs a `gh auth login`.
The commands below are written against `1.8.4`; substitute the release you are
checking.

- **npm provenance.** `npm view @sanctuary-framework/mcp-server@1.8.4 dist.attestations`
  prints the SLSA v1 provenance attestation (`predicateType:
  https://slsa.dev/provenance/v1`). The package is published from
  [`.github/workflows/publish-on-tag.yml`](.github/workflows/publish-on-tag.yml)
  with `npm publish --provenance` through npm Trusted Publishing; no static
  publish token exists. `npm audit signatures` verifies registry signatures
  and provenance for every package installed in a project, so run it where the
  package is installed; an empty directory reports nothing to audit, which is
  not a pass.
- **Signed release manifest.** Every `1.8.x` release attaches
  `release-manifest.json` and the tarball to the GitHub release (earlier
  releases such as v1.7.0 carry neither), and the manifest is signed with a
  pinned Ed25519 key. From a clone of this repository at the tag, with the two
  assets fetched by `curl` (or by `gh release download v1.8.4 --pattern
  release-manifest.json --pattern sanctuary-framework-mcp-server-1.8.4.tgz`
  after `gh auth login`):

  ```bash
  curl -LO https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/release-manifest.json
  curl -LO https://github.com/eriknewton/sanctuary-framework/releases/download/v1.8.4/sanctuary-framework-mcp-server-1.8.4.tgz
  node scripts/verify-release-artifact.mjs --tarball sanctuary-framework-mcp-server-1.8.4.tgz --manifest release-manifest.json --version 1.8.4 --expected-public-key 61YBfiq_zlbTP5rl_r_msbPk40IXJL-_PuAxlpBVeF0
  ```

  The expected public key is `PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL` in
  [`server/src/release-manifest.ts`](server/src/release-manifest.ts); read it
  from the tag you are verifying if it ever differs from this page. Success
  prints `Verified sanctuary-framework-mcp-server-1.8.4.tgz for release 1.8.4.`
  and exits 0; any mismatch exits 1 with `Release verification refused:` and
  the reason. The private half of the key is held as a GitHub Actions secret
  of this repository (`RELEASE_SIGNING_KEY`, read only by
  `publish-on-tag.yml`); it is never in the tree.
- **macOS app.** `Sanctuary-CastleWall.app.zip` is Developer-ID-signed and
  notarized; compare `shasum -a 256 Sanctuary-CastleWall.app.zip` with the
  SHA-256 published in [`README.md`](README.md) under Release status for the
  release you downloaded.
- **Linux package.** Checksum only today. The
  [Castle Wall Linux 0.1.0-1](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1)
  pre-release ships a `.sha256` beside the `.deb`, with no signature and no apt
  repository, so `sha256sum -c sanctuary-castle-wall_0.1.0-1_amd64.deb.sha256`
  is the whole check.

## Static Analysis and Supply Chain

Several automated layers run alongside human review:

- **CodeQL static analysis** runs on this repository via GitHub
  [default setup](https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning).
  Because default setup is enabled, this repository deliberately does **not**
  ship a hand-written `codeql.yml` workflow, because a manual workflow would conflict
  with default setup. Code-scanning alerts are reviewed on the
  [Security tab](https://github.com/eriknewton/sanctuary-framework/security/code-scanning).
- **Software Bill of Materials (SBOM).** A CycloneDX SBOM is generated on every
  push to `main` and on every release by
  [`.github/workflows/sbom.yml`](.github/workflows/sbom.yml) and attached as a
  build artifact, so the dependency surface of a given build is auditable.
- **Dependency hygiene.** Dependabot tracks npm, pip, and GitHub Actions
  dependencies; the Python sidecar installs with `pip install --require-hashes`;
  and CI uses lockfile-pinned installs (`npm ci`).

## Crown-Jewel Files (for security reviewers)

If you are reviewing the framework for the first time, these are the
highest-value files to read:

- `server/src/core/key-derivation.ts`: Argon2id + HKDF key hierarchy.
- `server/src/core/master-custody.ts`: master-key custody, AEAD wraps, anti-rollback.
- `server/src/core/encryption.ts`: AES-256-GCM state encryption.
- `server/src/principal-policy/gate.ts`: the fail-closed approval gate every tool call passes through.
- `server/src/router.ts`: the routing layer that wraps every tool call in the gate.
- `castle-wall-daemon/` (Rust): the Linux OS-level egress enforcement daemon.
- [`ASSURANCE_MATRIX.md`](ASSURANCE_MATRIX.md): every trust claim mapped to evidence, known gaps, and the next proof needed.

## Disclosure History

Drill records and postmortems live under [`docs/audit/`](docs/audit/).
Findings from security reviews are tracked privately and are not published,
per the non-disclosure rule in [`AGENTS.md`](AGENTS.md); current trust claims
and their bounds are tracked in [`ASSURANCE_MATRIX.md`](ASSURANCE_MATRIX.md).
