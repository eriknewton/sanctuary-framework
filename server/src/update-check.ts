/**
 * Sanctuary MCP Server: Update Check
 *
 * Non-blocking check against the npm registry for newer versions.
 * Prints a notice to stderr if an update is available.
 * Never throws; failures are silently ignored (network issues, offline, etc.).
 *
 * Respects SANCTUARY_NO_UPDATE_CHECK=1 to disable entirely.
 *
 * AUTHENTICITY: the bare version notice below trusts the registry for
 * transport only. For an advisory whose authenticity is independent of the
 * network, use `verifyAndAdviseUpdate`, which verifies an Ed25519-signed release
 * manifest against the PINNED release-signing key (see `release-manifest.ts`)
 * and fails closed on any unsigned/wrong-key/tampered manifest. The signed-
 * manifest verifier and its constants are re-exported from this module.
 */

import { get } from "node:https";
import {
  verifyReleaseManifest,
  type ManifestVerificationResult,
} from "./release-manifest.js";

export {
  verifyReleaseManifest,
  verifyReleaseManifestWithKey,
  buildReleaseManifestMessage,
  loadPinnedReleaseKey,
  PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL,
  RELEASE_MANIFEST_DOMAIN,
  type ReleaseManifestBody,
  type SignedReleaseManifest,
  type ManifestVerificationResult,
  type ManifestRefusalReason,
} from "./release-manifest.js";

/**
 * Minimal audit sink the update-gate writes to. Structurally compatible with
 * `AuditLog.append` (see `operational/audit-log.ts`) so the real audit log is
 * passed directly; kept narrow so this startup-path module does not pull in
 * the heavy audit module. `append` is best-effort by contract; losing a
 * telemetry entry must never change the (already fail-closed) trust decision.
 */
export interface UpdateAuditSink {
  append(
    layer: "l1" | "l2" | "l3" | "l4",
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result?: "success" | "failure",
  ): Promise<void> | void;
}

/** Audit operation names for the signed-update gate (stable wire strings). */
export const UPDATE_MANIFEST_VERIFIED_OP = "update.manifest.verified";
export const UPDATE_MANIFEST_REFUSED_OP = "update.manifest.refused";

/** npm registry endpoint for the package */
const REGISTRY_URL =
  "https://registry.npmjs.org/@sanctuary-framework/mcp-server/latest";

/**
 * GitHub Releases API endpoint for the latest release of the source repo.
 * The signed `release-manifest.json` is published as an asset on the release
 * for each `vX.Y.Z` tag. This is a DISTINCT channel from the npm registry, so
 * a registry compromise or MITM cannot forge a manifest that verifies against
 * the pinned key.
 */
const GITHUB_LATEST_RELEASE_URL =
  "https://api.github.com/repos/eriknewton/sanctuary-framework/releases/latest";

/** The asset filename the signed manifest is published under. */
const RELEASE_MANIFEST_ASSET_NAME = "release-manifest.json";

/** Request timeout in milliseconds */
const TIMEOUT_MS = 3000;

/** Max bytes we will read from any single update-related HTTP response. */
const MAX_RESPONSE_BYTES = 65536;

/**
 * Compare two semver version strings (major.minor.patch only).
 * Returns true if `latest` is newer than `current`.
 */
export function isNewerVersion(current: string, latest: string): boolean {
  const parse = (v: string): number[] =>
    v.replace(/^v/, "").split(".").map(Number);

  const [curMajor = 0, curMinor = 0, curPatch = 0] = parse(current);
  const [latMajor = 0, latMinor = 0, latPatch = 0] = parse(latest);

  if (latMajor !== curMajor) return latMajor > curMajor;
  if (latMinor !== curMinor) return latMinor > curMinor;
  return latPatch > curPatch;
}

/**
 * Format the update notification message.
 */
export function formatUpdateMessage(
  current: string,
  latest: string
): string {
  return `[Sanctuary] Update available: ${current} → ${latest}. Run: npx @sanctuary-framework/mcp-server@latest`;
}

/**
 * Check the npm registry for a newer version.
 * Returns the latest version string if newer, or null if current/error.
 */
export function fetchLatestVersion(
  currentVersion: string
): Promise<string | null> {
  return new Promise((resolve) => {
    const req = get(
      REGISTRY_URL,
      {
        headers: { Accept: "application/json" },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        // Only process 200 responses
        if (res.statusCode !== 200) {
          res.resume(); // drain
          resolve(null);
          return;
        }

        let data = "";
        res.setEncoding("utf-8");
        res.on("data", (chunk: string) => {
          data += chunk;
          // Safety: abort if response is unexpectedly large (> 32KB)
          if (data.length > 32768) {
            res.destroy();
            resolve(null);
          }
        });
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            const latest = json.version;
            if (
              typeof latest === "string" &&
              isNewerVersion(currentVersion, latest)
            ) {
              resolve(latest);
            } else {
              resolve(null);
            }
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Verify a signed release manifest against the pinned key and, ONLY on a
 * verified manifest, return the version to advise. Both the accepted and the
 * refused paths are audited.
 *
 * Fail-closed (AGENTS.md invariant #5): any manifest that does not verify
 * against the pinned key (unsigned, wrong-key, malformed, or tampered)
 * returns `{ advise: false }` and emits a refusal audit event. There is no
 * path where an unverified manifest produces an "update available" advisory.
 *
 * Never throws. Audit-sink failures are swallowed here (the sink's own
 * `flush()` re-raises a lost critical/telemetry write at the call site);
 * losing the telemetry entry must not flip the already-decided refusal.
 *
 * @param manifestValue - untrusted parsed manifest (e.g. fetched JSON)
 * @param audit - optional audit sink; when present, both paths are recorded
 * @param identityId - audit subject id (defaults to "system")
 */
export async function verifyAndAdviseUpdate(
  manifestValue: unknown,
  audit?: UpdateAuditSink,
  identityId = "system",
): Promise<
  | { advise: true; version: string }
  | { advise: false; reason: string }
> {
  const result: ManifestVerificationResult = verifyReleaseManifest(manifestValue);

  if (!result.ok) {
    if (audit) {
      try {
        await audit.append(
          "l1",
          UPDATE_MANIFEST_REFUSED_OP,
          identityId,
          { reason: result.reason },
          "failure",
        );
      } catch {
        // Audit best-effort; the refusal stands regardless.
      }
    }
    return { advise: false, reason: result.reason };
  }

  if (audit) {
    try {
      await audit.append(
        "l1",
        UPDATE_MANIFEST_VERIFIED_OP,
        identityId,
        { version: result.body.version },
        "success",
      );
    } catch {
      // Audit best-effort; the verified advisory stands regardless.
    }
  }
  return { advise: true, version: result.body.version };
}

/**
 * GET a URL and resolve to its UTF-8 body text, or null on any failure.
 * Bounded, timed, and non-throwing: any non-200 status, timeout, network
 * error, or oversized body resolves to null (offline / unreachable = silent).
 * A GitHub API call requires a User-Agent header or GitHub returns 403.
 */
function httpGetText(url: string): Promise<string | null> {
  return new Promise((resolve) => {
    const req = get(
      url,
      {
        headers: {
          Accept: "application/json",
          "User-Agent": "sanctuary-mcp-server-update-check",
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume(); // drain
          resolve(null);
          return;
        }
        let data = "";
        res.setEncoding("utf-8");
        res.on("data", (chunk: string) => {
          data += chunk;
          if (data.length > MAX_RESPONSE_BYTES) {
            res.destroy();
            resolve(null);
          }
        });
        res.on("end", () => resolve(data));
      },
    );

    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Fetch the latest release's signed `release-manifest.json` from the GitHub
 * Releases API and return its parsed (still-untrusted) JSON value, or null if
 * unavailable. This performs NO verification; the returned value MUST be routed
 * through `verifyAndAdviseUpdate` (which calls `verifyReleaseManifest`) before
 * any advisory is emitted. Never throws; offline / missing asset = null.
 */
export async function fetchLatestSignedManifest(): Promise<unknown | null> {
  const releaseJson = await httpGetText(GITHUB_LATEST_RELEASE_URL);
  if (releaseJson === null) return null;

  let release: unknown;
  try {
    release = JSON.parse(releaseJson);
  } catch {
    return null;
  }
  if (typeof release !== "object" || release === null) return null;

  const assets = (release as { assets?: unknown }).assets;
  if (!Array.isArray(assets)) return null;

  let assetUrl: string | null = null;
  for (const asset of assets) {
    if (typeof asset !== "object" || asset === null) continue;
    const a = asset as { name?: unknown; browser_download_url?: unknown };
    if (
      a.name === RELEASE_MANIFEST_ASSET_NAME &&
      typeof a.browser_download_url === "string"
    ) {
      assetUrl = a.browser_download_url;
      break;
    }
  }
  if (assetUrl === null) return null;

  const manifestText = await httpGetText(assetUrl);
  if (manifestText === null) return null;

  try {
    return JSON.parse(manifestText);
  } catch {
    return null;
  }
}

/**
 * Signed-update check: fetch the latest signed release manifest from the
 * GitHub Releases channel, verify it against the PINNED release-signing key,
 * and print an AUTHENTICATED update notice to stderr ONLY on `{ ok: true }`.
 *
 * Fail-closed (AGENTS.md invariant #5): on any refusal (unsigned, wrong-key,
 * malformed, tampered, or simply absent/unreachable) this stays SILENT: it
 * never falls through to a bare-npm advisory for the authenticated path. Both
 * the verified and refused outcomes are audited when an audit sink is supplied.
 *
 * Fire-and-forget: never throws, never blocks startup. Respects
 * SANCTUARY_NO_UPDATE_CHECK=1.
 *
 * With the pinned key still the all-zero placeholder, `verifyReleaseManifest`
 * refuses with `bad_pinned_key`, so this function is INERT (silent) until the
 * real key is activated. That inertness is intentional.
 *
 * @param currentVersion - the running version (advisory is suppressed unless
 *   the verified manifest attests a strictly newer version)
 * @param audit - optional audit sink; both paths are recorded when present
 */
export async function checkForSignedUpdate(
  currentVersion: string,
  audit?: UpdateAuditSink,
): Promise<void> {
  if (process.env.SANCTUARY_NO_UPDATE_CHECK === "1") {
    return;
  }

  try {
    const manifestValue = await fetchLatestSignedManifest();
    if (manifestValue === null) {
      // Absent / unreachable manifest is a silent refusal: never a false
      // advisory, and no fall-through to the bare npm notice.
      if (audit) {
        try {
          await audit.append(
            "l1",
            UPDATE_MANIFEST_REFUSED_OP,
            "system",
            { reason: "unavailable" },
            "failure",
          );
        } catch {
          // Audit best-effort; the silent refusal stands regardless.
        }
      }
      return;
    }

    const outcome = await verifyAndAdviseUpdate(manifestValue, audit);
    if (outcome.advise && isNewerVersion(currentVersion, outcome.version)) {
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this authenticated advisory.
      console.error(formatUpdateMessage(currentVersion, outcome.version));
    }
    // On refusal, or on a verified-but-not-newer manifest, stay silent.
  } catch {
    // Never fail the server over an update check.
  }
}

/**
 * Run the update check and print a notice to stderr if an update is available.
 * This function is fire-and-forget; it never throws or blocks the server.
 *
 * Set SANCTUARY_NO_UPDATE_CHECK=1 to disable.
 */
export async function checkForUpdate(currentVersion: string): Promise<void> {
  // Allow users to opt out
  if (process.env.SANCTUARY_NO_UPDATE_CHECK === "1") {
    return;
  }

  try {
    const latest = await fetchLatestVersion(currentVersion);
    if (latest) {
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
      console.error(formatUpdateMessage(currentVersion, latest));
    }
  } catch {
    // Never fail the server over an update check
  }
}
