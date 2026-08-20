/**
 * Read-only persisted-rule compatibility diagnostic.
 *
 * MANIFEST-RULEID-PATH-01: this command inventories an existing policy before
 * a consumer upgrade or producer filename-format switch. It never changes it.
 */

import { readFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";

import {
  preflightPersistedManifestRuleIdentities,
  type ManifestPreflightReport,
} from "../castle-wall/allowlist/manifest-preflight.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";

export interface ManifestPreflightCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  readFile?: (path: string) => Promise<Buffer>;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function resolveFortressArg(fortress: string | undefined, env: NodeJS.ProcessEnv): string {
  if (!fortress) return resolveStoragePath(env);
  return isAbsolute(fortress) ? fortress : resolve(process.cwd(), fortress);
}

/**
 * Run `sanctuary castle-wall manifest-preflight [--fortress <path>]`.
 *
 * A non-zero result means the persisted manifest cannot be used as a clean
 * compatibility witness. The report still contains every bounded finding.
 */
export async function runManifestPreflight(
  argv: string[] = [],
  ctx: ManifestPreflightCommandContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const parsed = consumeFlagValue(argv, "--fortress");
  if (parsed.error !== undefined || parsed.argv.length > 0) {
    write(
      err,
      `Usage: sanctuary castle-wall manifest-preflight [--fortress <path>]${
        parsed.error === undefined ? "" : `\nError: ${parsed.error}`
      }\n`,
    );
    return 2;
  }

  const fortressPath = resolveFortressArg(parsed.value, env);
  const egressDir = join(fortressPath, "policy", "egress");
  const read = ctx.readFile ?? readFile;
  let manifestBytes: Buffer;
  let pinnedPublicKey: Buffer;
  try {
    [manifestBytes, pinnedPublicKey] = await Promise.all([
      read(join(egressDir, "manifest.json")),
      read(join(fortressPath, CASTLE_PINNED_PUBKEY)),
    ]);
  } catch {
    write(
      out,
      JSON.stringify({
        status: "unavailable",
        signature: "not_checked",
        relation_preflight: "not_checked",
        rule_bodies_scanned: 0,
        issue_count: 1,
        omitted_issue_count: 0,
        issues: [
          {
            kind: "manifest_input",
            message: "persisted manifest or pinned key could not be read",
          },
        ],
      }) + "\n",
    );
    return 1;
  }
  if (pinnedPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    write(
      out,
      JSON.stringify({
        status: "incompatible",
        signature: "not_checked",
        relation_preflight: "not_checked",
        rule_bodies_scanned: 0,
        issue_count: 1,
        omitted_issue_count: 0,
        issues: [{ kind: "manifest_signature", message: "pinned public key has an invalid length" }],
      }) + "\n",
    );
    return 1;
  }

  let envelope: unknown;
  try {
    envelope = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    write(
      out,
      JSON.stringify({
        status: "incompatible",
        signature: "not_checked",
        relation_preflight: "not_checked",
        rule_bodies_scanned: 0,
        issue_count: 1,
        omitted_issue_count: 0,
        issues: [{ kind: "manifest_envelope", message: "manifest is not valid JSON" }],
      }) + "\n",
    );
    return 1;
  }

  let report: ManifestPreflightReport;
  try {
    report = await preflightPersistedManifestRuleIdentities(
      envelope,
      new Uint8Array(pinnedPublicKey),
      {
        readRuleBody: async (filename) => new Uint8Array(await read(join(egressDir, "rules", filename))),
      },
    );
  } catch {
    write(
      out,
      JSON.stringify({
        status: "incompatible",
        signature: "not_checked",
        relation_preflight: "not_checked",
        rule_bodies_scanned: 0,
        issue_count: 1,
        omitted_issue_count: 0,
        issues: [{ kind: "manifest_envelope", message: "manifest compatibility scan could not be completed" }],
      }) + "\n",
    );
    return 1;
  }
  const compatible =
    report.signature === "verified" &&
    report.relation_preflight === "passed" &&
    report.issue_count === 0;
  write(out, JSON.stringify({ status: compatible ? "compatible" : "incompatible", ...report }) + "\n");
  return compatible ? 0 : 1;
}
