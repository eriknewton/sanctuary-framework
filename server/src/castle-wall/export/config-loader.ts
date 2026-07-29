/**
 * Operator config-file loader for the enforcement exporter.
 *
 * Mirrors the distress-lane loader (`server/src/distress/config.ts`): one
 * OPERATOR-owned file, in the operator-owned policy directory the agent cannot
 * write, read once and validated fail-closed. The pure validation lives in
 * `./config.ts` (no I/O there); this module is only the read + JSON-parse layer,
 * so the validator stays trivially hermetic.
 *
 * Location: `<fortress>/policy/egress/cortex-export.json` -- alongside
 * `distress.json`, `agent-origin.json`, and `operator-baseline.json`.
 *
 * FAIL-CLOSED (AGENTS.md must-never #5): a PRESENT but malformed file throws
 * `EnforcementExportConfigError` rather than silently degrading to a different
 * (for example local) lane. A MISSING file is the documented safe default: the
 * network-free `file` sink, no outbound push.
 *
 * NO SECRET IN THIS FILE (must-never #6): the pinned `destination_url` is
 * rejected if it embeds userinfo credentials (`validatePinnedUrl` in
 * `./config.ts`); collector auth is handled out of band. Because the file
 * therefore carries no secret, it needs no 0600 owner-only check (unlike
 * `distress.json`, which holds an HMAC secret).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  defaultExportConfig,
  EnforcementExportConfigError,
  validateExportConfig,
  type EnforcementExportConfig,
} from "./config.js";

/** The on-disk filename under `<fortress>/policy/egress/`. */
export const EXPORT_CONFIG_FILENAME = "cortex-export.json";

/**
 * Read `<fortressPath>/policy/egress/cortex-export.json`. Missing file -> the
 * safe default (file sink, no network). Present-but-invalid file -> throws
 * (fail closed).
 */
export async function readExportConfig(fortressPath: string): Promise<EnforcementExportConfig> {
  const filePath = join(fortressPath, "policy", "egress", EXPORT_CONFIG_FILENAME);
  let rawText: string;
  try {
    rawText = await readFile(filePath, "utf8");
  } catch (err) {
    const code =
      err instanceof Error && "code" in err ? (err as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return defaultExportConfig();
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new EnforcementExportConfigError("file is not valid JSON");
  }
  return validateExportConfig(parsed);
}
