/**
 * Sanctuary MCP Server — Update Check
 *
 * Non-blocking check against the npm registry for newer versions.
 * Prints a notice to stderr if an update is available.
 * Never throws — failures are silently ignored (network issues, offline, etc.).
 *
 * Respects SANCTUARY_NO_UPDATE_CHECK=1 to disable entirely.
 */

import { get } from "node:https";

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
 * Run the update check and print a notice to stderr if an update is available.
 * This function is fire-and-forget — it never throws or blocks the server.
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
      console.error(formatUpdateMessage(currentVersion, latest));
    }
  } catch {
    // Never fail the server over an update check
  }
}
