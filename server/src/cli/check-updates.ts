/**
 * `sanctuary check-updates` — explicit, operator-requested update check.
 *
 * ZERO-OUTBOUND-BY-DEFAULT (2026-07-05): Sanctuary makes no unrequested
 * outbound connection. The startup update probes in `update-check.ts` are
 * gated by `outboundUpdateChecksEnabled()` and are OFF unless the operator
 * opts in with `SANCTUARY_UPDATE_CHECK=1`. This verb is the explicit-intent
 * bypass: running `sanctuary check-updates` is itself the operator's request,
 * so it ALWAYS performs both the bare npm-registry check and the signed
 * release-manifest check, regardless of the env-var default.
 *
 * Both checks stay advisory / never-block / no-credential; this verb always
 * exits 0 and prints a human-readable result, whether an update is available,
 * the install is up to date, or a check was unreachable. An available update
 * is informational, not an error, so it is never a non-zero exit signal.
 */

import { Writable } from "node:stream";
import {
  fetchLatestVersion,
  fetchLatestSignedManifest,
  verifyAndAdviseUpdate,
  isNewerVersion,
} from "../update-check.js";
import { getSanctuaryVersion } from "../version.js";

export interface CheckUpdatesCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  currentVersion?: string;
  /** Test seam: override the bare-version fetch. */
  fetchLatestVersionFn?: typeof fetchLatestVersion;
  /** Test seam: override the signed-manifest fetch. */
  fetchLatestSignedManifestFn?: typeof fetchLatestSignedManifest;
}

const HELP = `sanctuary check-updates. Explicitly check for a newer Sanctuary version.

Usage: sanctuary check-updates [--help]

Sanctuary makes no unrequested outbound connection by default. This command
is the explicit, operator-requested exception: it always checks npmjs.org and
the GitHub Releases signed-manifest channel, right now, regardless of the
SANCTUARY_UPDATE_CHECK / SANCTUARY_NO_UPDATE_CHECK environment defaults.

Exit codes:
  0  up to date, or an update is available (see printed result)
  1  invalid arguments
`;

export async function runCheckUpdatesCommand(
  args: CheckUpdatesCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  void err;

  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    out.write(HELP);
    return 0;
  }

  const currentVersion = args.currentVersion ?? getSanctuaryVersion();
  const fetchVersion = args.fetchLatestVersionFn ?? fetchLatestVersion;
  const fetchManifest =
    args.fetchLatestSignedManifestFn ?? fetchLatestSignedManifest;

  out.write(`Checking for updates (current: ${currentVersion})...\n`);

  // Bare npm-registry check.
  let bareResult: "up-to-date" | "update-available" | "unreachable";
  let bareLatest: string | null = null;
  try {
    bareLatest = await fetchVersion(currentVersion);
    bareResult = bareLatest ? "update-available" : "up-to-date";
  } catch {
    bareResult = "unreachable";
  }

  // Signed release-manifest check (authenticated channel).
  let signedResult: "up-to-date" | "update-available" | "unreachable" | "unverified";
  let signedLatest: string | null = null;
  try {
    const manifestValue = await fetchManifest();
    if (manifestValue === null) {
      signedResult = "unreachable";
    } else {
      const outcome = await verifyAndAdviseUpdate(manifestValue);
      if (!outcome.advise) {
        signedResult = "unverified";
      } else if (isNewerVersion(currentVersion, outcome.version)) {
        signedResult = "update-available";
        signedLatest = outcome.version;
      } else {
        signedResult = "up-to-date";
      }
    }
  } catch {
    signedResult = "unreachable";
  }

  if (bareResult === "update-available" && bareLatest) {
    out.write(
      `Update available: ${currentVersion} -> ${bareLatest}\n` +
        `Run: npx @sanctuary-framework/mcp-server@${bareLatest}\n`,
    );
  } else if (bareResult === "up-to-date") {
    out.write(`npm registry: up to date (${currentVersion} is the latest).\n`);
  } else {
    out.write(`npm registry: offline or unreachable, could not check.\n`);
  }

  if (signedResult === "update-available" && signedLatest) {
    out.write(
      `Signed release manifest: update available -> ${signedLatest} (authenticated).\n`,
    );
  } else if (signedResult === "up-to-date") {
    out.write(`Signed release manifest: up to date.\n`);
  } else if (signedResult === "unverified") {
    out.write(
      `Signed release manifest: not verifiable against the pinned release-signing key (ignored).\n`,
    );
  } else {
    out.write(`Signed release manifest: offline or unreachable, could not check.\n`);
  }

  return 0;
}
