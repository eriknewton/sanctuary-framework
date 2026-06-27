/**
 * `sanctuary plugin list | status | test` (plugin-host slice S5).
 *
 * Minimal operator surface over the bundled reference plugins. It is intentionally
 * read-only + liveness-only:
 *   - list    — every bundled plugin, its id/version/channel + declared hooks.
 *   - status  — integrity-verify the bundle against the first-party signer and print
 *               the descriptor summary (bundle hash, file count, entry).
 *   - test    — LIVENESS probe: spawn the plugin, send one host-generated randomized
 *               request through the real wire path, print the verdict. UX copy says
 *               this proves the plugin is ALIVE and answering the contract, NOT that
 *               its detection quality is good (RFC §11).
 *
 * There is no install/enable/disable/evict verb here — third-party install is
 * F1-gated (design D2) and the bundled reference plugin needs no install ceremony.
 * Lifecycle ceremonies are Tier-1 and live elsewhere.
 */

import { randomBytes, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Writable } from "node:stream";

import { SubstrateError } from "../substrate/errors.js";
import { parseGovernance } from "../substrate/governance.js";
import {
  loadBundledReferenceBlocklist,
  referenceBlocklistBundleDir,
  spawnReferencePlugin,
  type LoadedReferenceBundle,
} from "../substrate/reference-plugin/index.js";

const PLUGIN_HELP = `sanctuary plugin - bundled plugin inspection (read-only + liveness)

Usage:
  sanctuary plugin list              list bundled plugins and their declared hooks
  sanctuary plugin status [<id>]     integrity-verify a bundled plugin and print its descriptor
  sanctuary plugin test [<id>]       liveness probe: send a randomized request, print the verdict

Notes:
  - Only the first-party bundled reference plugin (ai.sanctuary.blocklist) is present.
    Third-party install is gated until the registry-integrity work lands.
  - "test" proves the plugin is ALIVE and answers the contract. It does NOT grade
    detection quality.
`;

interface BundledPluginRef {
  id: string;
  bundleDir: string;
  governanceText: Promise<string>;
}

function bundledPlugins(): BundledPluginRef[] {
  const blocklistDir = referenceBlocklistBundleDir();
  return [
    {
      id: "ai.sanctuary.blocklist",
      bundleDir: blocklistDir,
      governanceText: fs.readFile(path.join(blocklistDir, "governance.yaml"), "utf8"),
    },
  ];
}

/**
 * Integrity-verify a bundled plugin using its COMMITTED SIGNATURE.json and the
 * COMMITTED first-party signer pubkey. This proves the on-disk file set matches the
 * signed descriptor and that the Ed25519 signature verifies under the first-party
 * signer key shipped in the signed release (trust = release integrity; there is no
 * independent host-policy pin until the third-party signer registry lands, which is
 * F1-gated) — the production-honest path, no ephemeral keys.
 */
async function verifyBundledPlugin(ref: BundledPluginRef): Promise<{
  loaded: LoadedReferenceBundle;
  signerNote: string;
}> {
  const loaded = await loadBundledReferenceBlocklist(ref.bundleDir);
  return {
    loaded,
    signerNote:
      "integrity verified: on-disk file set matches the signed descriptor and the " +
      "Ed25519 signature verifies against the first-party signer key shipped in the " +
      "signed release (trust = release integrity; there is no independent host-policy " +
      "pin until the third-party signer registry lands, which is F1-gated).",
  };
}

async function runList(out: Writable): Promise<number> {
  const refs = bundledPlugins();
  const rows: Array<Record<string, unknown>> = [];
  for (const ref of refs) {
    const text = await ref.governanceText;
    const g = parseGovernance(text);
    rows.push({
      plugin_id: g.plugin_id,
      version: g.version,
      channel: g.channel,
      hooks: g.hooks.map((h) => h.hook_class),
      source: "first-party-bundled",
    });
  }
  out.write(`${JSON.stringify({ plugins: rows }, null, 2)}\n`);
  return 0;
}

async function runStatus(out: Writable, err: Writable, id?: string): Promise<number> {
  const refs = bundledPlugins().filter((r) => !id || r.id === id);
  if (refs.length === 0) {
    err.write(`sanctuary plugin status: no bundled plugin "${id}"\n`);
    return 1;
  }
  const rows: Array<Record<string, unknown>> = [];
  for (const ref of refs) {
    try {
      const { loaded, signerNote } = await verifyBundledPlugin(ref);
      rows.push({
        plugin_id: loaded.governance.plugin_id,
        version: loaded.governance.version,
        channel: loaded.governance.channel,
        entry: loaded.governance.entry,
        hooks: loaded.governance.hooks.map((h) => ({ hook_class: h.hook_class, fail_mode: h.fail_mode })),
        bundle_hash: loaded.bundleHash,
        file_count: loaded.descriptor.files.length,
        integrity: "verified",
        note: signerNote,
      });
    } catch (e) {
      const reason = e instanceof SubstrateError ? e.reason : "unknown";
      rows.push({ plugin_id: ref.id, integrity: "FAILED", reason, error: String(e) });
    }
  }
  out.write(`${JSON.stringify({ plugins: rows }, null, 2)}\n`);
  return rows.every((r) => r.integrity === "verified") ? 0 : 1;
}

async function runTest(out: Writable, err: Writable, id?: string): Promise<number> {
  const refs = bundledPlugins().filter((r) => !id || r.id === id);
  if (refs.length === 0) {
    err.write(`sanctuary plugin test: no bundled plugin "${id}"\n`);
    return 1;
  }
  const ref = refs[0]!;
  // First integrity-verify; never run a plugin whose bundle does not verify.
  let loaded: LoadedReferenceBundle;
  try {
    ({ loaded } = await verifyBundledPlugin(ref));
  } catch (e) {
    err.write(`sanctuary plugin test: integrity check failed: ${String(e)}\n`);
    return 1;
  }

  const spawned = spawnReferencePlugin(loaded.entryPath);
  try {
    const request_id = randomUUID();
    const nonce = randomBytes(16).toString("base64url");
    // Host-generated randomized liveness input on the production wire path.
    const host = `liveness-${randomBytes(4).toString("hex")}.example`;
    const verdict = await spawned.client.request(
      { request_id, nonce, hook_class: "egress_decision", host, port: 443 },
      { request_id, nonce, declaredSignalKeys: loaded.governance.signal_keys },
      500,
    );
    out.write(
      `${JSON.stringify(
        {
          plugin_id: loaded.governance.plugin_id,
          liveness: "alive",
          probe_host: host,
          verdict: verdict.decision,
          rationale: verdict.rationale,
          note: "liveness only: this proves the plugin answers the contract, not detection quality",
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (e) {
    err.write(
      `${JSON.stringify({ plugin_id: ref.id, liveness: "DEAD", error: String(e) }, null, 2)}\n`,
    );
    return 1;
  } finally {
    spawned.close();
  }
}

export async function runPluginCommand(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
}): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const sub = args.argv[0];
  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    out.write(PLUGIN_HELP);
    return 0;
  }
  if (sub === "list") return runList(out);
  if (sub === "status") return runStatus(out, err, args.argv[1]);
  if (sub === "test") return runTest(out, err, args.argv[1]);

  err.write(`sanctuary plugin: unknown subcommand "${sub}"\n\n${PLUGIN_HELP}`);
  return 1;
}
