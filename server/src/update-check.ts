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

import { get as httpsGet } from "node:https";
import { get as httpGet } from "node:http";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { resolveStoragePath } from "./paths.js";
import {
  verifyReleaseManifest,
  RELEASE_VERSION_SHAPE_RE,
  type ManifestVerificationResult,
} from "./release-manifest.js";

export {
  verifyReleaseManifest,
  verifyReleaseManifestWithKey,
  buildReleaseManifestMessage,
  loadPinnedReleaseKey,
  PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL,
  RELEASE_MANIFEST_DOMAIN,
  RELEASE_VERSION_SHAPE_RE,
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
 * Canonical wrap-meta pointer filename written into `<storage>/backup/` by
 * `sanctuary protect` (see `wrap/config-reader.ts`, which owns the write and
 * unwrap-read paths). Only the FILENAME is duplicated here, as a presence
 * probe; all reads of the file's CONTENT stay in the wrap module.
 */
const WRAP_META_POINTER_FILENAME = "wrap-meta.json";

/**
 * Minimal, independent presence check: was this install wrapped by
 * `sanctuary protect`? True when the canonical wrap-meta pointer file exists
 * under the instance's backup directory.
 *
 * Why not reuse `hasExistingWrapMeta` from `wrap/config-reader.ts`: that
 * module is the heavy, CLI-side wrap surface (custody reads, path-identity
 * verification); pulling it into this light startup-path module would couple
 * server boot to the wrap import graph for a one-bit answer. A stat of the
 * pointer file is enough here: the update notice only needs to know WHICH
 * upgrade advice to print, and a false negative safely degrades to the
 * unwrapped advice.
 *
 * Deliberate scope limits (honest, documented):
 * - The legacy pre-vocabulary-sweep pointer filename is NOT probed; its
 *   literal is confined to the wrap fallback-read module by the
 *   retired-vocabulary CI gate. Installs old enough to carry only the legacy
 *   pointer predate the version-pinned MCP entry (v1.6.1), so for them the
 *   unwrapped npx advice is exactly today's status-quo behavior.
 * - Tenant-path wraps by OLDER releases: a wrap run under
 *   SANCTUARY_STORAGE_PATH tenancy writes the pointer into the tenant
 *   directory, but wraps performed by releases from before
 *   `buildSanctuaryEnv` (wrap/cli.ts) persisted that var wrote a harness
 *   entry without it, so a harness that does not itself inherit the shell
 *   var spawns the pinned server on the DEFAULT storage path and this probe
 *   misses the tenant pointer (unwrapped advice; advisory-copy-only, like
 *   the other limits). Current wraps persist SANCTUARY_STORAGE_PATH (or the
 *   fortress var, which supersedes it) into the entry env, so the probe and
 *   the pointer agree.
 * - False POSITIVE on stale pointers: presence-only means an install that was
 *   wrapped and then unwrapped on a release BEFORE `removeWrapMeta` existed
 *   (which left the meta file in place after unwrap; see the stale-meta guard
 *   note in `wrap/config-reader.ts`) gets the wrapped advice despite being
 *   genuinely unwrapped today. Impact is advisory-copy-only (misleading
 *   upgrade wording; following it re-runs protect, i.e. wraps at the new
 *   version); no state or enforcement decision keys off this bit. All
 *   current-version unwrap paths delete the pointer via `removeWrapMeta`,
 *   so the mainline is clean.
 * - Never throws: any filesystem error resolves false (unwrapped advice).
 *
 * @param storagePath - instance storage root (tests inject a temp dir;
 *   production uses the same `resolveStoragePath()` the wrap surface uses)
 */
export async function detectWrappedInstall(
  storagePath: string = resolveStoragePath(),
): Promise<boolean> {
  try {
    const s = await stat(join(storagePath, "backup", WRAP_META_POINTER_FILENAME));
    return s.isFile();
  } catch {
    return false;
  }
}

/**
 * Format the update notification message.
 *
 * The suggested command pins the exact version the message announces
 * (v1.6.1 install-path hardening): the operator runs precisely what was
 * advertised, not whatever `latest` resolves to by the time they act.
 *
 * Wrapped installs (`wrapped = true`): a `sanctuary protect` wrap writes a
 * version-PINNED MCP entry into the harness config, so running the bare npx
 * command would only start a transient foreground server and rewrite nothing;
 * the harness would keep spawning the old pinned version while the operator
 * believes they upgraded. The wrapped advice therefore points at re-running
 * `protect` FROM the new version, which is the mechanism that rewrites the
 * pin (see `resolveSanctuaryCommand` in `wrap/cli.ts`).
 */
export function formatUpdateMessage(
  current: string,
  latest: string,
  wrapped = false
): string {
  if (wrapped) {
    return (
      `[Sanctuary] Update available: ${current} → ${latest}. ` +
      `This install is version-pinned by 'sanctuary protect'; running the server directly does not upgrade it. ` +
      `To upgrade the pin, re-run protect from the new version: ` +
      `npx @sanctuary-framework/mcp-server@${latest} protect --<your-harness>`
    );
  }
  return `[Sanctuary] Update available: ${current} → ${latest}. Run: npx @sanctuary-framework/mcp-server@${latest}`;
}

/**
 * Parse an npm-registry `.../latest` response body and return the advertised
 * version IFF it is acceptable to advise: a string, a clean semver shape, and
 * strictly newer than `currentVersion`. Anything else returns null.
 *
 * The semver-shape guard (`RELEASE_VERSION_SHAPE_RE`) is defense-in-depth
 * against a tampered registry / TLS-MITM response: the accepted string is
 * interpolated into a copy-paste command the operator is told to run, so a
 * shell-injection-shaped "version" must never be accepted, regardless of how
 * the version comparison happens to treat it.
 *
 * Extracted from the response handler so the acceptance rule is testable
 * without a network.
 */
export function extractNewerRegistryVersion(
  currentVersion: string,
  data: string
): string | null {
  try {
    const json: unknown = JSON.parse(data);
    if (typeof json !== "object" || json === null) return null;
    const latest = (json as { version?: unknown }).version;
    if (
      typeof latest === "string" &&
      RELEASE_VERSION_SHAPE_RE.test(latest) &&
      isNewerVersion(currentVersion, latest)
    ) {
      return latest;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Check the npm registry for a newer version.
 * Returns the latest version string if newer, or null if current/error.
 */
export function fetchLatestVersion(
  currentVersion: string
): Promise<string | null> {
  return new Promise((resolve) => {
    const req = httpsGet(
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
          resolve(extractNewerRegistryVersion(currentVersion, data));
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
 * Maximum number of redirect hops httpGetText will follow. GitHub's
 * release-asset download route (`browser_download_url` and the API
 * octet-stream asset route) returns a 302 to `*.githubusercontent.com`, so
 * following redirects is REQUIRED for the signed manifest to be fetchable.
 * Bounded at 2 so a redirect loop can never hang or amplify the request.
 */
const MAX_REDIRECT_HOPS = 2;

/**
 * SSRF guard: a redirect Location is followed ONLY if its host is one of these
 * (or a subdomain of `.githubusercontent.com`). This is the exact set GitHub
 * uses for the API + release-asset flow, so an attacker cannot redirect the
 * update fetch to an internal/metadata host. A host that does not match here
 * makes httpGetText resolve null (silent, never a false advisory).
 */
export function isAllowedRedirectHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === "github.com" ||
    host === "api.github.com" ||
    host === "githubusercontent.com" ||
    host.endsWith(".githubusercontent.com")
  );
}

/**
 * Predicate deciding whether a redirect target may be followed. Given the
 * parsed target URL, returns true only if it is safe to follow.
 */
export type RedirectPolicy = (next: URL) => boolean;

/**
 * The PRODUCTION redirect policy (the default): https-only AND an allowlisted
 * GitHub host. This is the SSRF-preserving policy; nothing in production
 * overrides it. Tests may pass a different policy to exercise the redirect-
 * follow MECHANISM against a local server, but the production fetch path
 * always uses this default.
 */
export const productionRedirectPolicy: RedirectPolicy = (next) =>
  next.protocol === "https:" && isAllowedRedirectHost(next.hostname);

/**
 * GET a URL and resolve to its UTF-8 body text, or null on any failure.
 * Bounded, timed, and non-throwing: any non-2xx (after bounded redirects),
 * timeout, network error, or oversized body resolves to null (offline /
 * unreachable = silent). A GitHub API call requires a User-Agent header or
 * GitHub returns 403.
 *
 * Redirects: a 3xx with a `Location` header is followed up to
 * MAX_REDIRECT_HOPS times, and ONLY to a target the redirect policy accepts.
 * The default `productionRedirectPolicy` is https-only + an allowlisted GitHub
 * host. This is required because GitHub release assets 302-redirect to
 * `*.githubusercontent.com`; the allowlist + https-only + hop cap keep the
 * SSRF guard intact. Every invariant (65536-byte cap, 3000ms timeout,
 * silent-on-any-error, never throws) is re-applied on each followed hop.
 *
 * `policy` is injectable ONLY so tests can drive the follow mechanism against
 * a local server; production callers never pass it, so the SSRF-preserving
 * default is always in force on the real fetch path.
 */
export function httpGetText(
  url: string,
  hopsRemaining = MAX_REDIRECT_HOPS,
  policy: RedirectPolicy = productionRedirectPolicy,
): Promise<string | null> {
  // Select the transport by scheme. Production always uses https (the GitHub
  // API + release-asset redirect targets are https, enforced by the redirect
  // policy). http support exists so the redirect-follow behavior is testable
  // against a local server without a TLS cert; it never weakens the production
  // path, which starts at an https API URL and uses the https-only default
  // policy.
  const client = url.startsWith("http://") ? httpGet : httpsGet;
  return new Promise((resolve) => {
    const req = client(
      url,
      {
        headers: {
          Accept: "application/json",
          "User-Agent": "sanctuary-mcp-server-update-check",
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        const status = res.statusCode ?? 0;

        // Redirect handling (bounded + policy-gated). A 3xx with a Location is
        // followed only to a policy-approved target, and only while hops
        // remain; anything else is a silent null.
        if (status >= 300 && status < 400) {
          res.resume(); // drain the redirect response body
          const location = res.headers.location;
          if (typeof location !== "string" || hopsRemaining <= 0) {
            resolve(null);
            return;
          }
          let next: URL;
          try {
            // Resolve relative Location against the current URL.
            next = new URL(location, url);
          } catch {
            resolve(null);
            return;
          }
          if (!policy(next)) {
            resolve(null);
            return;
          }
          resolve(httpGetText(next.toString(), hopsRemaining - 1, policy));
          return;
        }

        if (status !== 200) {
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
      // Wrapped installs get the protect-based upgrade advice (the bare npx
      // command would not rewrite the pinned MCP entry). Detection never
      // throws; a false negative degrades to the unwrapped advice.
      const wrapped = await detectWrappedInstall();
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this authenticated advisory.
      console.error(formatUpdateMessage(currentVersion, outcome.version, wrapped));
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
      // Wrapped installs get the protect-based upgrade advice (the bare npx
      // command would not rewrite the pinned MCP entry). Detection never
      // throws; a false negative degrades to the unwrapped advice.
      const wrapped = await detectWrappedInstall();
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
      console.error(formatUpdateMessage(currentVersion, latest, wrapped));
    }
  } catch {
    // Never fail the server over an update check
  }
}
