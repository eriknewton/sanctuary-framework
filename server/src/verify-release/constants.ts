/**
 * Pins, URLs, caps and budgets for `sanctuary verify-release`.
 *
 * Every pin below names the ONE release path Sanctuary publishes through: the
 * `publish-on-tag.yml` workflow on `main` of `eriknewton/sanctuary-framework`,
 * dispatched by hand, on a GitHub-hosted runner. A provenance record that names
 * anything else describes some other build, so the verifier refuses it.
 *
 * Shared administration: the Sigstore provenance and the Ed25519 release
 * manifest use distinct keys, but both are produced by that one workflow. Whoever
 * can change and dispatch the workflow on `main` can exercise both checks, so
 * this command never claims they are independent roots.
 */

/** The package this verb verifies. */
export const PACKAGE_NAME = "@sanctuary-framework/mcp-server";

/** Registry path segment for the scoped name, `/` escaped as npm's attestations route expects. */
const PACKAGE_NAME_ESCAPED_SLASH = "@sanctuary-framework%2fmcp-server";

/** The unscoped file stem npm uses for the tarball of this package. */
const TARBALL_STEM = "mcp-server";

const REGISTRY_ORIGIN = "https://registry.npmjs.org";
const GITHUB_RELEASES_ORIGIN = "https://github.com/eriknewton/sanctuary-framework/releases/download";

/** The version document for one exact version. Never the packument's `latest`. */
export function versionDocumentUrl(version: string): string {
  return `${REGISTRY_ORIGIN}/${PACKAGE_NAME}/${version}`;
}

/** npm's attestations document for one exact version. */
export function attestationsUrl(version: string): string {
  return `${REGISTRY_ORIGIN}/-/npm/v1/attestations/${PACKAGE_NAME_ESCAPED_SLASH}@${version}`;
}

/**
 * The tarball URL. The tarball is fetched from this composed URL; the version
 * document's `dist.tarball` is only compared to it as a string, so a document
 * cannot point the fetch at another host or path.
 */
export function tarballUrl(version: string): string {
  return `${REGISTRY_ORIGIN}/${PACKAGE_NAME}/-/${TARBALL_STEM}-${version}.tgz`;
}

/** The signed release manifest on the GitHub release `v<version>`. Never `/releases/latest`. */
export function manifestUrl(version: string): string {
  return `${GITHUB_RELEASES_ORIGIN}/v${version}/release-manifest.json`;
}

/**
 * The one artifact name the release manifest must list. Must match the name the
 * release workflow uploads beside `release-manifest.json`
 * (`sanctuary-framework-mcp-server-<version>.tgz`).
 */
export function manifestArtifactName(version: string): string {
  return `sanctuary-framework-mcp-server-${version}.tgz`;
}

/** The provenance subject name for one version (purl, `@` percent-encoded). */
export function subjectName(version: string): string {
  return `pkg:npm/%40sanctuary-framework/${TARBALL_STEM}@${version}`;
}

/**
 * Strict semver, optional prerelease, no build metadata. Build metadata is
 * refused because npm ignores it while a tag would carry it, so the GitHub tag
 * `v<version>` and the registry version could name different builds.
 */
export const VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-(0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;

// ---------------------------------------------------------------------------
// Certificate identity pins (Fulcio). OIDs are from the Fulcio certificate
// specification, docs/oid-info.md in github.com/sigstore/fulcio:
//   1.3.6.1.4.1.57264.1.8   Issuer (V2)
//   1.3.6.1.4.1.57264.1.9   Build Signer URI
//   1.3.6.1.4.1.57264.1.11  Runner Environment
//   1.3.6.1.4.1.57264.1.12  Source Repository URI
//   1.3.6.1.4.1.57264.1.14  Source Repository Ref
//   1.3.6.1.4.1.57264.1.15  Source Repository Identifier
//   1.3.6.1.4.1.57264.1.17  Source Repository Owner Identifier
//   1.3.6.1.4.1.57264.1.18  Build Config URI
//   1.3.6.1.4.1.57264.1.20  Build Trigger
// The V2 extensions hold a DER UTF8String inside the extension OCTET STRING.
// The deprecated V1 extensions (1.1 to 1.6) are never read: their raw-string
// encoding is not self-describing.
// ---------------------------------------------------------------------------

/** GitHub Actions' OIDC issuer: the certificate was minted for a GitHub workflow token. */
export const PINNED_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * The workflow identity, the SAN URI Fulcio writes. Must match the workflow path
 * pinned by test/verify-release/workflow-pin.test.ts, which reads
 * `.github/workflows/publish-on-tag.yml`. The ref is `refs/heads/main` because
 * the workflow is dispatched from `main` and checks out an existing tag; that
 * is what releases record.
 */
export const PINNED_WORKFLOW_IDENTITY =
  "https://github.com/eriknewton/sanctuary-framework/.github/workflows/publish-on-tag.yml@refs/heads/main";

/** The source repository, as a URI. */
export const PINNED_REPOSITORY_URI = "https://github.com/eriknewton/sanctuary-framework";
/** Must match the workflow path in PINNED_WORKFLOW_IDENTITY and in the cross-file pin test. */
export const PINNED_WORKFLOW_PATH = ".github/workflows/publish-on-tag.yml";
export const PINNED_REF = "refs/heads/main";
/** GitHub's numeric repository id: survives a rename, so a re-created repository of the same name differs. */
export const PINNED_REPOSITORY_ID = "1188932575";
/** GitHub's numeric owner id: survives a rename of the owner account. */
export const PINNED_REPOSITORY_OWNER_ID = "38265121";
/** A self-hosted runner is outside GitHub's isolation, so only `github-hosted` builds are accepted. */
export const PINNED_RUNNER_ENVIRONMENT = "github-hosted";
/** The release workflow runs only on manual dispatch; any other trigger is another workflow path. */
export const PINNED_TRIGGER = "workflow_dispatch";

/** Fulcio OIDs read by the identity adapter. */
export const FULCIO_OID = {
  issuer: "1.3.6.1.4.1.57264.1.8",
  buildSignerUri: "1.3.6.1.4.1.57264.1.9",
  runnerEnvironment: "1.3.6.1.4.1.57264.1.11",
  sourceRepositoryUri: "1.3.6.1.4.1.57264.1.12",
  sourceRepositoryRef: "1.3.6.1.4.1.57264.1.14",
  sourceRepositoryId: "1.3.6.1.4.1.57264.1.15",
  sourceRepositoryOwnerId: "1.3.6.1.4.1.57264.1.17",
  buildConfigUri: "1.3.6.1.4.1.57264.1.18",
  buildTrigger: "1.3.6.1.4.1.57264.1.20",
} as const;

// ---------------------------------------------------------------------------
// Statement pins (SLSA provenance v1, as npm's GitHub Actions builder writes it).
// ---------------------------------------------------------------------------

export const DSSE_PAYLOAD_TYPE_IN_TOTO = "application/vnd.in-toto+json";
export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
export const PINNED_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1";
export const PINNED_BUILDER_ID = "https://github.com/actions/runner/github-hosted";

// ---------------------------------------------------------------------------
// Transport caps and budgets. Measured 1.8.4 values (2026-11-25):
// version document 7,322 bytes; attestations document 15,257 bytes; tarball
// 31,914,378 bytes; release manifest 297 bytes.
// ---------------------------------------------------------------------------

const KIB = 1024;
const MIB = 1024 * KIB;

/** 16 x 7,322 = 117,152, rounded up to 128 KiB. Text documents get 16x headroom. */
export const MAX_VERSION_DOCUMENT_BYTES = 128 * KIB;
/** 16 x 15,257 = 244,112, rounded up to 256 KiB. */
export const MAX_ATTESTATIONS_BYTES = 256 * KIB;
/** 4 x 31,914,378 = 127,657,512, rounded up to 122 MiB (127,926,272). */
export const MAX_TARBALL_BYTES = 122 * MIB;
/** 16 x 297 = 4,752, rounded up to 5 KiB. */
export const MAX_MANIFEST_BYTES = 5 * KIB;

/** The release-asset hosts GitHub redirects a download to. Confirmed live on 2026-11-25: release-assets.githubusercontent.com. */
export const GITHUB_ASSET_HOSTS: readonly string[] = ["objects.githubusercontent.com", "release-assets.githubusercontent.com"];
/** At most 3 redirect hops for the manifest; GitHub uses one. */
export const MAX_REDIRECT_HOPS = 3;

/**
 * Whole-run deadline. Derivation: a 32 MB tarball at 1 Mbit/s takes about 256 s
 * (31,914,378 x 8 / 1,000,000), plus headroom for the three small documents and
 * local hashing, so 300 s.
 */
export const RUN_DEADLINE_MS = 300_000;
/** Per-resource stall timeout: 30 s with no bytes arriving refuses that resource. */
export const STALL_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Archive caps. Measured 1.8.4 values: 132,452,876 bytes unpacked, 81 entries,
// largest file 23,448,089 bytes (dist/cli.cjs.map), longest path 74 characters.
// Byte caps get 4x headroom, counts and lengths 16x.
// ---------------------------------------------------------------------------

/** 4 x 132,452,876 = 529,811,504 gunzipped bytes. */
export const MAX_ARCHIVE_EXPANDED_BYTES = 4 * 132_452_876;
/** 16 x 81 = 1,296 entries. */
export const MAX_ARCHIVE_ENTRIES = 16 * 81;
/** 4 x 23,448,089 = 93,792,356 bytes for one file. */
export const MAX_ARCHIVE_FILE_BYTES = 4 * 23_448_089;
/** 16 x 74 = 1,184 characters for one entry path. */
export const MAX_ARCHIVE_PATH_LENGTH = 16 * 74;

/** The archive prefix npm packs every file under. Exactly one is removed. */
export const ARCHIVE_PREFIX = "package/";
