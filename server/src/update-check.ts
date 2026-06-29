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

/** Request timeout in milliseconds */
const TIMEOUT_MS = 3000;

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
