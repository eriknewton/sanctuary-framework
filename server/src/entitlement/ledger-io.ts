/**
 * Thin persistence layer for the fleet license ledger (PR-1).
 *
 * Separated from `ledger.ts` (pure core) so the tamper-evidence logic stays
 * I/O-free and unit-testable. This layer only reads/writes the JSON document
 * under the fortress state dir; it resolves the path via the same config other
 * modules use (NEVER hardcodes `~/.sanctuary`), and it defers ALL trust
 * decisions to `verifyLedgerIntegrity`  -  a load NEVER silently trusts a ledger
 * that fails its integrity check.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { loadConfig } from "../config.js";
import { emptyLedger, type Ledger } from "./ledger.js";

/**
 * Resolve the on-disk path of the issuer's license ledger. Under the fortress
 * state dir (`<storage_path>/state/fleet-license-ledger.json`), NOT a hardcoded
 * home path  -  honors `SANCTUARY_STORAGE_PATH` / `--fortress` via loadConfig.
 */
export async function resolveLedgerPath(): Promise<string> {
  const config = await loadConfig();
  return join(config.storage_path, "state", "fleet-license-ledger.json");
}

/**
 * Load the ledger from `path`. A missing file yields a fresh empty ledger (an
 * issuer that has never issued anything). A present-but-unparseable file throws
 * (fail-closed: the CLI reports it rather than overwriting a corrupt/tampered
 * ledger). Integrity verification is the CALLER's responsibility via
 * `verifyLedgerIntegrity`  -  this only parses.
 */
export async function loadLedger(path: string): Promise<Ledger> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return emptyLedger();
    }
    throw err;
  }
  const parsed = JSON.parse(bytes.toString("utf-8")) as unknown;
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as Ledger).rows)
  ) {
    throw new Error(`fleet license ledger at ${path} is malformed`);
  }
  return parsed as Ledger;
}

/**
 * Persist the ledger to `path` atomically-ish (write a temp file then rename)
 * with owner-only permissions on the containing dir. The ledger holds no secret
 * material (signed tokens + public metadata only), but it is issuer state, so
 * it is written under the 0700 state dir.
 */
export async function saveLedger(path: string, ledger: Ledger): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}`;
  const json = JSON.stringify(ledger, null, 2) + "\n";
  await writeFile(tmp, json, { mode: 0o600 });
  const { rename } = await import("node:fs/promises");
  await rename(tmp, path);
}
