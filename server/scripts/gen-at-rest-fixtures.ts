#!/usr/bin/env node
/**
 * Phase-0 at-rest decrypt-fixture generator (run ONCE on pre-change origin/main).
 *
 * Writes deterministic TOY data through each decryptable store's REAL public
 * persist path, under a fixed SYNTHETIC master key, into a temp fortress, then
 * copies the produced `.enc` ciphertext into server/test/fixtures/at-rest/<label>/
 * as a committed, frozen artifact. The companion read-back test
 * (test/security/at-rest-decrypt-fixtures.test.ts) stages each fixture into a
 * temp fortress and reads it back through the same store, asserting the toy
 * payload survives byte-for-byte.
 *
 * WHY pre-change: a fixture generated AFTER a rename/reorg would "bless" whatever
 * the new code produces and hide a silently-changed HKDF label or storage
 * encoder. Generating on origin/main and only ever READING afterward is what
 * makes the fixture a real safety net for the l1-l4 -> named-layer rename (the
 * layer-token-embedding labels l2-context-gate / l3-policies / l3-commitments /
 * l4-reputation / l2-honeypot-trap-v1 are the canonical rename trap).
 *
 * PRIVACY (scoping §7 fixture-generation rule, invariants 2 + 6): every fixture
 * is generated from deterministic toy data + a synthetic test master key. No
 * operator data, no real keys, no opaque private material is ever written. The
 * synthetic key is a fixed all-constant 32-byte value, committed alongside the
 * fixtures so the read-back is reproducible.
 *
 * Re-running this script OVERWRITES the committed fixtures with fresh ciphertext
 * (AES-GCM uses a random IV, so the bytes differ each run) — only do that
 * intentionally on origin/main, never after a behavior change.
 *
 * Usage (from server/):  npx vite-node scripts/gen-at-rest-fixtures.ts
 *
 * Dependency-free beyond the server's own modules + Node built-ins.
 */

import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { FilesystemStorage } from "../src/storage/filesystem.js";
import {
  FIXTURE_MASTER_KEY,
  FIXTURE_STORES,
} from "../test/fixtures/at-rest/fixture-stores.js";

const SCRIPT_DIR = fileURLToPath(new URL(".", import.meta.url));
const SERVER_DIR = resolve(SCRIPT_DIR, "..");
const FIXTURE_ROOT = join(SERVER_DIR, "test", "fixtures", "at-rest");

/**
 * Write the toy payload for one store, then copy the produced namespace dir of
 * `.enc` files into the committed fixture location. Each store is given its own
 * fresh temp fortress so namespaces never collide.
 */
async function generateOne(spec: (typeof FIXTURE_STORES)[number]): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), `sanctuary-fixgen-${spec.label}-`));
  try {
    const storage = new FilesystemStorage(tmp);
    await spec.write(storage, FIXTURE_MASTER_KEY);

    // The store wrote under spec.namespace; copy that namespace dir verbatim.
    const producedNs = storage.namespacePath(spec.namespace);
    const destNs = join(FIXTURE_ROOT, spec.label, spec.namespace);
    // Clear any prior fixture for this label, then copy fresh.
    rmSync(join(FIXTURE_ROOT, spec.label), { recursive: true, force: true });
    mkdirSync(destNs, { recursive: true });
    cpSync(producedNs, destNs, { recursive: true });

    const files = readdirSync(destNs).filter((f) => f.endsWith(".enc"));
    process.stdout.write(
      `  ${spec.label.padEnd(28)} -> ${spec.namespace}/ (${files.length} .enc)\n`,
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  process.stdout.write(
    "Generating at-rest decrypt fixtures (pre-change, synthetic toy data)\n",
  );
  process.stdout.write(`  fixture root: ${FIXTURE_ROOT}\n\n`);
  for (const spec of FIXTURE_STORES) {
    await generateOne(spec);
  }
  process.stdout.write(
    `\nDone. ${FIXTURE_STORES.length} decryptable-store fixtures written.\n` +
      "Commit the .enc files; the read-back test reads them unchanged.\n",
  );
}

main().catch((err) => {
  process.stderr.write(String(err?.stack ?? err) + "\n");
  process.exitCode = 1;
});
