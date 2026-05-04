/**
 * Castle Wall allowlist manifest parser and verifier.
 *
 * This module is the single trust boundary for "is this manifest legitimate?"
 * Subsequent PRs (PR 2, PR 3) consume Result values from these functions to
 * decide whether to load a new ruleset or keep the prior one.
 *
 * No filesystem I/O lives here. The verifier accepts in-memory rule-file bytes
 * indexed by relative path. The PR that adds the daemon (PR 2 Linux, PR 3
 * macOS) does the actual reading; this module is the pure validation core
 * so it can be unit-tested without touching disk.
 */

import { sha256 } from "@noble/hashes/sha256";
import { verify } from "../../core/identity.js";
import { fromBase64url, stringToBytes } from "../../core/encoding.js";
import { canonicalize } from "../../mesh/canonical-json.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../constants.js";
import type { AllowlistRule } from "./schema.js";
import { validateRule } from "./schema.js";
import type { SignedManifest } from "./manifest.js";

/** Result type returned by the verifier. */
export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string; issues?: ReadonlyArray<string> };

/** Bytes read from disk for one rule file, keyed by path relative to manifest. */
export type RuleFileBytes = ReadonlyMap<string, Uint8Array>;

/** Lowercase hex of a SHA-256 digest. */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Verify the Ed25519 signature on a SignedManifest. */
export function verifyManifestSignature(
  signed: SignedManifest,
  pinnedPublicKey: Uint8Array
): ParseResult<true> {
  if (signed.signature.signature_scheme !== CASTLE_WALL_SIGNATURE_SCHEME_V1) {
    return {
      ok: false,
      error: `unsupported signature_scheme: ${String(signed.signature.signature_scheme)}`,
    };
  }
  if (signed.manifest.schema_version !== CASTLE_WALL_SCHEMA_VERSION_V1) {
    return {
      ok: false,
      error: `unsupported manifest schema_version: ${String(signed.manifest.schema_version)}`,
    };
  }

  let payloadBytes: Uint8Array;
  try {
    payloadBytes = stringToBytes(canonicalize(signed.manifest));
  } catch (err) {
    return { ok: false, error: `manifest canonicalization failed: ${(err as Error).message}` };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64url(signed.signature.signature_b64url);
  } catch (err) {
    return { ok: false, error: `signature base64url decode failed: ${(err as Error).message}` };
  }

  const ok = verify(payloadBytes, signatureBytes, pinnedPublicKey);
  if (!ok) {
    return { ok: false, error: "manifest signature does not verify against pinned key" };
  }
  return { ok: true, value: true };
}

/**
 * Verify that every rule file in the manifest is present in the supplied
 * RuleFileBytes map and matches its recorded SHA-256 digest. Also validates
 * each parsed rule against the schema gate.
 *
 * The caller is responsible for verifying the manifest signature first via
 * verifyManifestSignature; this function only validates referenced bytes.
 */
export function verifyAndParseRules(
  signed: SignedManifest,
  ruleFiles: RuleFileBytes
): ParseResult<ReadonlyArray<AllowlistRule>> {
  const collected: AllowlistRule[] = [];
  const issues: string[] = [];

  for (const entry of signed.manifest.rules) {
    const bytes = ruleFiles.get(entry.file);
    if (!bytes) {
      issues.push(`rule file missing on disk: ${entry.file}`);
      continue;
    }
    const digest = toHex(sha256(bytes));
    if (digest !== entry.sha256.toLowerCase()) {
      issues.push(
        `rule file sha256 mismatch for ${entry.file} (manifest says ${entry.sha256}, found ${digest})`
      );
      continue;
    }
    let parsed: AllowlistRule;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes)) as AllowlistRule;
    } catch (err) {
      issues.push(`rule file ${entry.file} not valid JSON: ${(err as Error).message}`);
      continue;
    }
    if (parsed.id !== entry.rule_id) {
      issues.push(
        `rule file ${entry.file} declares id ${parsed.id}, manifest says ${entry.rule_id}`
      );
      continue;
    }
    const schemaIssues = validateRule(parsed);
    if (schemaIssues.length > 0) {
      for (const issue of schemaIssues) {
        issues.push(`rule ${entry.rule_id}: ${issue}`);
      }
      continue;
    }
    collected.push(parsed);
  }

  if (issues.length > 0) {
    return { ok: false, error: "rule validation failed", issues };
  }
  return { ok: true, value: collected };
}
