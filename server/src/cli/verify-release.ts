/**
 * `sanctuary verify-release`: check an install of
 * `@sanctuary-framework/mcp-server` against the signed release record.
 *
 * ZERO-OUTBOUND-BY-DEFAULT: this verb makes network requests only because the
 * operator ran it, and only to the four fixed release resources. It never runs
 * in the background. A network failure is a refusal: without the records there
 * is nothing to compare against, so there is no "could not check, assume fine".
 */

import type { Writable } from "node:stream";
import { consumeFlagValue, FORTRESS_FLAG_USAGE_EXIT_CODE } from "./argv.js";
import { hermesPackageRootFromEntry } from "./hermes-memory.js";
import { verifyReleaseManifest } from "../release-manifest.js";
import { getSanctuaryVersion } from "../version.js";
import { SYSTEM_CLOCK } from "../verify-release/deadline.js";
import { escapePrintable } from "../verify-release/reasons.js";
import { PRODUCTION_PROVENANCE, runVerifyRelease, type RunReport, type VerifyReleaseDeps } from "../verify-release/run.js";
import { httpsRequester } from "../verify-release/transport.js";

export const VERIFY_RELEASE_VERIFIED_EXIT_CODE = 0;
export const VERIFY_RELEASE_INTERNAL_ERROR_EXIT_CODE = 1;
/** Usage errors share the CLI-wide usage code. */
export const VERIFY_RELEASE_USAGE_EXIT_CODE = FORTRESS_FLAG_USAGE_EXIT_CODE;
/** Every refusal, whatever its reason. */
export const VERIFY_RELEASE_REFUSED_EXIT_CODE = 3;

export const VERIFY_RELEASE_HELP = `sanctuary verify-release. Check an install against Sanctuary's signed release record.

Usage: sanctuary verify-release [--target <dir>] [--version <v>] [--json]

  --target <dir>   The install to check: a folder holding
                   @sanctuary-framework/mcp-server (for example
                   <prefix>/lib/node_modules/@sanctuary-framework/mcp-server).
                   Run this from a copy of Sanctuary you already trust.
  --version <v>    Optional. Must equal the version the target's package.json
                   names; the command never checks one version's files against
                   another version's records.
  --json           Print one JSON object on stdout.

Without --target the command checks its own install for later file drift.
That check is only as trustworthy as the copy running it: a modified copy can
report itself unmodified.

This command fetches four records for the version, from registry.npmjs.org
and from the GitHub release v<version>: the version document, the provenance
attestations, the package tarball and the signed release manifest. It makes no
other connection and never runs on its own. Any network failure is a refusal.

What it detects:
  - a package substituted at the registry, or by someone holding a stolen npm
    token;
  - provenance from another repository, another workflow, or a self-hosted
    runner;
  - a release manifest that is not signed by Sanctuary's pinned release key;
  - any added, removed or changed file in the checked install. It compares the
    contents and normalized names of regular files and directories, excluding
    exactly a top-level folder named node_modules and files named .DS_Store.
    Each excluded name must still be a real folder or a plain file, never a
    link. Any other spelling of those names, such as Node_Modules or
    .ds_store, is an extra entry and refuses.

What it does not detect:
  - a malicious change to the release workflow on main, or misuse of the
    signing secret by that workflow (both checks share GitHub workflow
    administration);
  - changes to dependencies under node_modules;
  - file modes, and the bin launchers npm writes outside the package;
  - a writer that changes files while the check runs.

Exit codes:
  0  verified
  1  internal error (no verdict)
  2  usage error
  3  refused (the reason is printed)

Refusals that are easy to misread:
  installed-file-unreadable  the file opened but could not be read, a storage
                             error; it does not say the bytes differ.
  installed-name-invalid     a name that is not UTF-8; the path shows its raw
                             bytes, escaped.
  installed-tree-oversize    the install holds more entries than the check
                             reads; it stops rather than list them all.
  sigstore-invalid           also what a release signed after a Sigstore key
                             rotation reports until Sanctuary's committed
                             trusted root is updated.
`;

export interface VerifyReleaseCommandArgs {
  argv: string[];
  /** The URL of cli.ts's own module; self mode resolves the package root from it. */
  entryModuleUrl: string;
  out?: Writable;
  err?: Writable;
  /** Test seam: injected objects replace production wiring. Never set in production. */
  deps?: Partial<VerifyReleaseDeps>;
}

type ParsedArgs = { ok: true; target?: string; version?: string; json: boolean } | { ok: false; message: string };

/** Each flag at most once; anything else is a usage error. */
export function parseVerifyReleaseArgs(argv: string[]): ParsedArgs {
  const target = consumeFlagValue(argv, "--target");
  if (target.error !== undefined) return { ok: false, message: target.error };
  const version = consumeFlagValue(target.argv, "--version");
  if (version.error !== undefined) return { ok: false, message: version.error };
  let json = false;
  for (const token of version.argv) {
    if (token === "--json") {
      if (json) return { ok: false, message: "--json may only be provided once" };
      json = true;
      continue;
    }
    // The token itself is never echoed: it could be a value meant for another flag.
    return { ok: false, message: "unrecognized argument; known flags are --target, --version and --json" };
  }
  return {
    ok: true,
    json,
    ...(target.value === undefined ? {} : { target: target.value }),
    ...(version.value === undefined ? {} : { version: version.value }),
  };
}

function humanReport(report: RunReport): string {
  const lines = [
    `target path: ${report.target === null ? "(not resolved)" : escapePrintable(report.target)}`,
    `version: ${report.version ?? "(not known)"}`,
    ...report.steps.map(({ step, result }) =>
      `${step}: ${result === "refused" ? `refused (${report.reason})` : result}`),
    report.verdict === "verified" ? "verdict: verified" : `verdict: refused (${report.reason})`,
  ];
  return `${lines.join("\n")}\n`;
}

function jsonReport(report: RunReport): string {
  return `${JSON.stringify({
    verdict: report.verdict,
    version: report.version,
    target: report.target === null ? null : escapePrintable(report.target),
    steps: report.steps,
    ...(report.reason === undefined ? {} : { reason: report.reason }),
  })}\n`;
}

export async function runVerifyReleaseCommand(args: VerifyReleaseCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    out.write(VERIFY_RELEASE_HELP);
    return VERIFY_RELEASE_VERIFIED_EXIT_CODE;
  }
  const parsed = parseVerifyReleaseArgs(args.argv);
  if (!parsed.ok) {
    // One stderr line and nothing on stdout, in both modes, so --json stdout is never a non-object.
    err.write(`sanctuary verify-release: ${parsed.message} (see sanctuary verify-release --help)\n`);
    return VERIFY_RELEASE_USAGE_EXIT_CODE;
  }
  try {
    const deps: VerifyReleaseDeps = {
      requester: httpsRequester,
      clock: SYSTEM_CLOCK,
      nodeVersion: process.versions.node,
      runningVersion: getSanctuaryVersion(),
      selfRoot: hermesPackageRootFromEntry(args.entryModuleUrl),
      verifyManifest: verifyReleaseManifest,
      provenance: PRODUCTION_PROVENANCE,
      ...args.deps,
    };
    const report = await runVerifyRelease(
      { ...(parsed.target === undefined ? {} : { target: parsed.target }), ...(parsed.version === undefined ? {} : { version: parsed.version }) },
      deps,
    );
    out.write(parsed.json ? jsonReport(report) : humanReport(report));
    return report.verdict === "verified" ? VERIFY_RELEASE_VERIFIED_EXIT_CODE : VERIFY_RELEASE_REFUSED_EXIT_CODE;
  } catch {
    // A fixed line: no stack, no message from the caught value, no bundle or certificate bytes.
    err.write("sanctuary verify-release: internal error; no verdict was produced\n");
    return VERIFY_RELEASE_INTERNAL_ERROR_EXIT_CODE;
  }
}
