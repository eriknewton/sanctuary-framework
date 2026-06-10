/**
 * sanctuary verify-transparency — standalone offline verifier.
 *
 * Verifies a published enforcement-checkpoint chain (a transparency bundle,
 * a JSON array of checkpoint records, or a single record) with NOTHING but
 * the verifying public key:
 *
 *   1. Schema validation of every record
 *   2. Ed25519 signature verification against the pinned public key
 *   3. Strict counter continuity (+1 steps; gaps, duplicates, and
 *      rollbacks are findings)
 *   4. previous_checkpoint_hash linkage (a replaced or reordered
 *      checkpoint breaks the hash chain)
 *   5. Cross-record consistency (fortress_id, signing key)
 *
 * STANDALONE PROPERTY (mirrors cli/audit-chain-verify.ts): this module
 * imports only @noble/curves, @noble/hashes, and Node builtins. It does NOT
 * import any Sanctuary server module, so a third party can compile and run
 * it (or the published CLI) against a bundle with no fortress, no storage,
 * and no passphrase.
 *
 * HONESTY DISCIPLINE: the report never says "best effort passed". Verdicts
 * are PASS or FAIL; everything the verifier could NOT check is listed under
 * `not_checked`, and the signature basis (pinned key vs. embedded key) is
 * always stated.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

// ---- Minimal canonical JSON / encoding (no server imports) ----------------

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function fromBase64url(s: string): Uint8Array {
  const normalized = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const pad = (4 - (normalized.length % 4)) % 4;
  const std = (normalized + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function sha256Hex(input: string): string {
  return toHex(sha256(new TextEncoder().encode(input)));
}

// ---- Format constants (duplicated from checkpoint.ts for standalone use) ---

const TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION = 1;
const TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX =
  "sanctuary.enforcement-checkpoint.v1\n";
const TRANSPARENCY_CHECKPOINT_GENESIS = "GENESIS";
const TRANSPARENCY_BUNDLE_FORMAT = "SANCTUARY_TRANSPARENCY_BUNDLE_V1";
const HEX64 = /^[0-9a-f]{64}$/;

/** Checkpoint record shape (structural mirror of checkpoint.ts). */
export interface VerifierCheckpointRecord {
  checkpoint_kind: "enforcement-checkpoint";
  schema_version: number;
  counter: number;
  previous_checkpoint_hash: string;
  issued_at: string;
  fortress_id: string;
  audit: {
    merkle_root: string;
    lowest_sequence: number;
    highest_sequence: number;
    head_hash: string;
    entry_count: number;
  };
  policy: {
    rules_sha256: string;
    rules_count: number;
    manifest_sha256: string | null;
  };
  daemon: { version: string; binary_sha256: string };
  enforcement: {
    total_allowed: number;
    total_blocked: number;
    rules: Array<{ rule_label: string; allowed: number; blocked: number }>;
  };
  signer_kid: string;
  signature: string;
  signature_algorithm: "Ed25519";
  payload_encoding: "domain-separated-canonical-json-v1";
  public_key: string;
}

export type TransparencyFindingKind =
  | "empty_input"
  | "malformed_input"
  | "schema_error"
  | "no_public_key"
  | "signature_invalid"
  | "counter_duplicate"
  | "counter_gap"
  | "counter_rollback"
  | "previous_hash_mismatch"
  | "fortress_id_mismatch"
  | "signing_key_mismatch"
  // host-mode (--against-log) finding kinds:
  | "log_unavailable"
  | "log_head_behind_checkpoint"
  | "log_entry_missing"
  | "merkle_root_mismatch"
  | "head_hash_mismatch"
  | "rotation_floor_unauthenticated"
  | "counters_mismatch"
  // offline genesis-completeness finding kinds:
  | "counter_prefix_missing"
  // earliest record claims genesis (counter 1) but its previous_checkpoint_hash
  // is not the genesis sentinel: a forged origin or a withheld predecessor.
  | "genesis_sentinel_mismatch"
  // a non-earliest record carries the genesis sentinel as its previous hash:
  // a spliced/forged second origin in the middle of a chain.
  | "genesis_sentinel_misplaced";

export interface TransparencyFinding {
  kind: TransparencyFindingKind;
  counter?: number;
  expected?: string | number;
  actual?: string | number;
  message: string;
}

export interface TransparencyVerifyReport {
  /**
   * "PASS"    — verified complete from the genesis checkpoint (counter 1 with
   *             the authentic genesis sentinel) with zero findings. The ONLY
   *             clean result; the CLI maps it to exit 0.
   * "PARTIAL" — a suffix fragment verified internally consistent under
   *             --allow-partial, but NOT rooted at genesis. Distinct from PASS
   *             so no caller can read incomplete evidence as complete; the CLI
   *             maps it to a dedicated non-zero exit code (10).
   * "FAIL"    — at least one finding.
   */
  verdict: "PASS" | "PARTIAL" | "FAIL";
  checkpoints_verified: number;
  counter_range: { from: number; to: number } | null;
  /**
   * "pinned": signatures verified against a caller-supplied key (strong).
   * "embedded": signatures verified against the key INSIDE the records
   * (proves internal consistency only — a forger who controls the file
   * controls that key; stated explicitly, never silently downgraded).
   */
  signature_basis: "pinned" | "embedded";
  findings: TransparencyFinding[];
  /** Honest list of properties this offline run could NOT check. */
  not_checked: string[];
}

const OFFLINE_NOT_CHECKED = [
  "audit-log contents: the Merkle root binds the log's hash chain but the offline verifier cannot recompute it without host access to the log (run with --against-log on the fortress host)",
  "completeness: an operator who stops publishing checkpoints truncates the visible chain; only counter continuity across independently obtained checkpoints detects this",
  "binary identity: daemon.version and daemon.binary_sha256 are self-reported by the emitting process; compare binary_sha256 against a published release hash for the named version",
  "policy semantics: policy hashes prove the policy did not change between checkpoints with equal hashes; they do not reveal or prove what the policy allows or blocks",
];

// ---- Schema validation -----------------------------------------------------

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isNonNegativeInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isVerifierCheckpointRecord(
  value: unknown
): value is VerifierCheckpointRecord {
  if (!isObject(value)) return false;
  const audit = value.audit;
  const policy = value.policy;
  const daemon = value.daemon;
  const enforcement = value.enforcement;
  return (
    value.checkpoint_kind === "enforcement-checkpoint" &&
    value.schema_version === TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION &&
    typeof value.counter === "number" &&
    Number.isSafeInteger(value.counter) &&
    value.counter > 0 &&
    typeof value.previous_checkpoint_hash === "string" &&
    (value.previous_checkpoint_hash === TRANSPARENCY_CHECKPOINT_GENESIS ||
      HEX64.test(value.previous_checkpoint_hash)) &&
    typeof value.issued_at === "string" &&
    typeof value.fortress_id === "string" &&
    isObject(audit) &&
    typeof audit.merkle_root === "string" &&
    HEX64.test(audit.merkle_root) &&
    isNonNegativeInt(audit.lowest_sequence) &&
    isNonNegativeInt(audit.highest_sequence) &&
    typeof audit.head_hash === "string" &&
    isNonNegativeInt(audit.entry_count) &&
    isObject(policy) &&
    typeof policy.rules_sha256 === "string" &&
    HEX64.test(policy.rules_sha256) &&
    isNonNegativeInt(policy.rules_count) &&
    (policy.manifest_sha256 === null ||
      (typeof policy.manifest_sha256 === "string" &&
        HEX64.test(policy.manifest_sha256))) &&
    isObject(daemon) &&
    typeof daemon.version === "string" &&
    typeof daemon.binary_sha256 === "string" &&
    HEX64.test(daemon.binary_sha256) &&
    isObject(enforcement) &&
    isNonNegativeInt(enforcement.total_allowed) &&
    isNonNegativeInt(enforcement.total_blocked) &&
    Array.isArray(enforcement.rules) &&
    enforcement.rules.every(
      (rule) =>
        isObject(rule) &&
        typeof rule.rule_label === "string" &&
        HEX64.test(rule.rule_label) &&
        isNonNegativeInt(rule.allowed) &&
        isNonNegativeInt(rule.blocked)
    ) &&
    typeof value.signer_kid === "string" &&
    typeof value.signature === "string" &&
    value.signature.length > 0 &&
    value.signature_algorithm === "Ed25519" &&
    value.payload_encoding === "domain-separated-canonical-json-v1" &&
    typeof value.public_key === "string" &&
    value.public_key.length > 0
  );
}

// ---- Core verification (pure, no I/O) ---------------------------------------

function signedPayloadOf(record: VerifierCheckpointRecord): unknown {
  return {
    checkpoint_kind: record.checkpoint_kind,
    schema_version: record.schema_version,
    counter: record.counter,
    previous_checkpoint_hash: record.previous_checkpoint_hash,
    issued_at: record.issued_at,
    fortress_id: record.fortress_id,
    audit: record.audit,
    policy: record.policy,
    daemon: record.daemon,
    enforcement: record.enforcement,
  };
}

export function checkpointPayloadHash(record: VerifierCheckpointRecord): string {
  return sha256Hex(
    `${TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(signedPayloadOf(record))}`
  );
}

function verifyRecordSignature(
  record: VerifierCheckpointRecord,
  publicKeyB64: string
): boolean {
  try {
    const key = fromBase64url(publicKeyB64);
    if (key.length !== 32) return false;
    const sig = fromBase64url(record.signature);
    if (sig.length !== 64) return false;
    const message = new TextEncoder().encode(
      `${TRANSPARENCY_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(signedPayloadOf(record))}`
    );
    return ed25519.verify(sig, message, key);
  } catch {
    return false;
  }
}

export interface VerifyTransparencyOptions {
  /** Base64url raw 32-byte Ed25519 public key obtained out-of-band. */
  publicKey?: string;
  /**
   * Explicit opt-in to verify against the key embedded in the records.
   * Without `publicKey`, verification REFUSES unless this is set — an
   * embedded-key pass proves internal consistency, not signer identity.
   */
  trustEmbedded?: boolean;
  /**
   * Explicit opt-in to accept a SUFFIX fragment whose earliest checkpoint is
   * not the genesis counter (1). Without this, a chain that does not start at
   * counter 1 is a `counter_prefix_missing` FINDING (FAIL): a clean PASS /
   * exit 0 must mean "verified complete from genesis", so a withheld prefix
   * can never read as success. With it, the missing prefix is downgraded to a
   * `not_checked` note and the suffix's internal consistency can still PASS —
   * for auditors verifying a fragment who already know it is partial.
   */
  allowPartial?: boolean;
}

export function verifyTransparencyCheckpoints(
  input: unknown,
  opts: VerifyTransparencyOptions = {}
): TransparencyVerifyReport {
  const findings: TransparencyFinding[] = [];

  // Accept: bundle object, array of records, or a single record.
  let candidates: unknown[];
  if (isObject(input) && input.format === TRANSPARENCY_BUNDLE_FORMAT) {
    candidates = Array.isArray(input.checkpoints) ? input.checkpoints : [];
  } else if (Array.isArray(input)) {
    candidates = input;
  } else if (isObject(input)) {
    candidates = [input];
  } else {
    return failReport([
      {
        kind: "malformed_input",
        message:
          "input is not a transparency bundle, a checkpoint array, or a checkpoint record",
      },
    ]);
  }

  if (candidates.length === 0) {
    return failReport([
      {
        kind: "empty_input",
        message: "no checkpoint records found in input",
      },
    ]);
  }

  const records: VerifierCheckpointRecord[] = [];
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    if (!isVerifierCheckpointRecord(candidate)) {
      findings.push({
        kind: "schema_error",
        message: `record at index ${i} is not a valid enforcement-checkpoint record`,
      });
      continue;
    }
    records.push(candidate);
  }

  // Key basis. Refuse to silently verify against attacker-controllable
  // embedded keys: that requires the explicit trustEmbedded opt-in.
  let basis: "pinned" | "embedded";
  if (opts.publicKey) {
    basis = "pinned";
  } else if (opts.trustEmbedded) {
    basis = "embedded";
  } else {
    findings.push({
      kind: "no_public_key",
      message:
        "no public key provided; pass the signer's public key (obtained out-of-band) or explicitly opt in to embedded-key verification, which proves internal consistency only",
    });
    return failReport(findings, records.length, "embedded");
  }

  records.sort((a, b) => a.counter - b.counter);

  // Signatures.
  for (const record of records) {
    const key = opts.publicKey ?? record.public_key;
    if (!verifyRecordSignature(record, key)) {
      findings.push({
        kind: "signature_invalid",
        counter: record.counter,
        message: `checkpoint counter ${record.counter}: Ed25519 signature does not verify against the ${basis} public key`,
      });
    }
  }

  // Counter continuity + hash linkage + cross-record consistency.
  for (let i = 1; i < records.length; i++) {
    const prev = records[i - 1]!;
    const curr = records[i]!;
    if (curr.counter === prev.counter) {
      findings.push({
        kind: "counter_duplicate",
        counter: curr.counter,
        message: `two checkpoints carry counter ${curr.counter} (fork or replay)`,
      });
      continue;
    }
    if (curr.counter !== prev.counter + 1) {
      findings.push({
        kind: "counter_gap",
        counter: curr.counter,
        expected: prev.counter + 1,
        actual: curr.counter,
        message: `counter gap: expected ${prev.counter + 1} after ${prev.counter}, found ${curr.counter} (missing or withheld checkpoints)`,
      });
    } else {
      const expectedPrevHash = checkpointPayloadHash(prev);
      if (curr.previous_checkpoint_hash !== expectedPrevHash) {
        findings.push({
          kind: "previous_hash_mismatch",
          counter: curr.counter,
          expected: expectedPrevHash,
          actual: curr.previous_checkpoint_hash,
          message: `checkpoint counter ${curr.counter}: previous_checkpoint_hash does not match the hash of checkpoint ${prev.counter} (replaced or reordered checkpoint)`,
        });
      }
    }
    // Rollback signal inside the covered audit window: the log head must
    // never move backwards between consecutive checkpoints.
    if (curr.audit.highest_sequence < prev.audit.highest_sequence) {
      findings.push({
        kind: "counter_rollback",
        counter: curr.counter,
        expected: `audit highest_sequence >= ${prev.audit.highest_sequence}`,
        actual: curr.audit.highest_sequence,
        message: `checkpoint counter ${curr.counter}: audit log head moved backwards (${prev.audit.highest_sequence} -> ${curr.audit.highest_sequence}); log truncation or state rollback between checkpoints`,
      });
    }
    if (curr.fortress_id !== prev.fortress_id) {
      findings.push({
        kind: "fortress_id_mismatch",
        counter: curr.counter,
        expected: prev.fortress_id,
        actual: curr.fortress_id,
        message: `checkpoint counter ${curr.counter}: fortress_id differs from earlier checkpoints`,
      });
    }
    if (curr.public_key !== prev.public_key) {
      findings.push({
        kind: "signing_key_mismatch",
        counter: curr.counter,
        message: `checkpoint counter ${curr.counter}: embedded public key differs from earlier checkpoints (key rotation must be announced out-of-band; treat as suspect otherwise)`,
      });
    }
  }

  const notChecked = [...OFFLINE_NOT_CHECKED];
  // Genesis completeness. A clean PASS / exit 0 must mean "verified complete
  // from the genesis checkpoint (counter 1) whose previous_checkpoint_hash is
  // the authentic genesis sentinel". Two distinct attacks are blocked here:
  //
  //   (a) Withheld prefix: the earliest record has counter N>1 (1..N-1 absent).
  //       By default a FINDING; `allowPartial` downgrades it to a PARTIAL note
  //       (never PASS) for auditors knowingly verifying a suffix fragment.
  //
  //   (b) Origin spoof: the earliest record claims counter 1 but its
  //       previous_checkpoint_hash is NOT the genesis sentinel — it points at
  //       an undisclosed predecessor (forged origin or withheld prefix wearing
  //       a genesis counter). This is ALWAYS a FINDING; --allow-partial cannot
  //       launder it, because a record asserting counter 1 is asserting it IS
  //       the genesis, and that assertion must be true.
  //
  // `partialAccepted` records that the only reason the chain is not genesis-
  // complete is an honestly-acknowledged missing prefix under allowPartial; it
  // drives the PARTIAL (not PASS) verdict below.
  let partialAccepted = false;
  if (records.length > 0) {
    const earliest = records[0]!;
    if (earliest.counter === 1) {
      // Claims genesis: the genesis sentinel binding is mandatory and is not
      // relaxable by --allow-partial. A counter-1 record with a non-sentinel
      // previous hash is forged or withholds a real predecessor.
      if (
        earliest.previous_checkpoint_hash !== TRANSPARENCY_CHECKPOINT_GENESIS
      ) {
        findings.push({
          kind: "genesis_sentinel_mismatch",
          counter: 1,
          expected: TRANSPARENCY_CHECKPOINT_GENESIS,
          actual: earliest.previous_checkpoint_hash,
          message: `checkpoint counter 1 claims to be the genesis but its previous_checkpoint_hash is "${earliest.previous_checkpoint_hash}", not the genesis sentinel "${TRANSPARENCY_CHECKPOINT_GENESIS}"; this asserts an undisclosed predecessor (forged origin or withheld prefix) and cannot be verified as complete from genesis`,
        });
      }
    } else if (opts.allowPartial) {
      partialAccepted = true;
      notChecked.push(
        `chain prefix: the earliest provided checkpoint has counter ${earliest.counter}, so checkpoints 1..${earliest.counter - 1} were not verified (partial chain accepted via allowPartial; this is a suffix fragment, NOT a complete-from-genesis verification)`
      );
    } else {
      findings.push({
        kind: "counter_prefix_missing",
        counter: earliest.counter,
        expected: 1,
        actual: earliest.counter,
        message: `the earliest provided checkpoint has counter ${earliest.counter}, not the genesis counter 1, so checkpoints 1..${earliest.counter - 1} are withheld or missing; this chain is not verifiable as complete from genesis (pass --allow-partial to verify a suffix fragment, which reports as partial, not PASS)`,
      });
    }
  }
  // Genesis sentinel must appear ONLY on the true origin. Any non-earliest
  // record carrying the sentinel is a spliced/forged second origin: it would
  // also break the linkage check, but flag it explicitly so the evidence is
  // never mistaken for a clean multi-origin chain.
  for (let i = 1; i < records.length; i++) {
    if (
      records[i]!.previous_checkpoint_hash === TRANSPARENCY_CHECKPOINT_GENESIS
    ) {
      findings.push({
        kind: "genesis_sentinel_misplaced",
        counter: records[i]!.counter,
        message: `checkpoint counter ${records[i]!.counter} carries the genesis sentinel "${TRANSPARENCY_CHECKPOINT_GENESIS}" as its previous_checkpoint_hash, but it is not the earliest record; a second genesis inside the chain is forged or spliced`,
      });
    }
  }
  if (basis === "embedded") {
    notChecked.push(
      "signer identity: signatures were verified against the key embedded in the records (explicit opt-in); this proves internal consistency, not who signed"
    );
  }

  // Verdict assembly. PASS is reserved EXCLUSIVELY for a complete-from-genesis
  // chain with zero findings. A suffix accepted under --allow-partial returns
  // the distinct PARTIAL verdict so neither verdict-gating nor exit-code-gating
  // automation can read incomplete evidence as a clean PASS.
  let verdict: "PASS" | "PARTIAL" | "FAIL";
  if (findings.length > 0) {
    verdict = "FAIL";
  } else if (partialAccepted) {
    verdict = "PARTIAL";
  } else {
    verdict = "PASS";
  }

  return {
    verdict,
    checkpoints_verified: records.length,
    counter_range:
      records.length > 0
        ? { from: records[0]!.counter, to: records.at(-1)!.counter }
        : null,
    signature_basis: basis,
    findings,
    not_checked: notChecked,
  };
}

function failReport(
  findings: TransparencyFinding[],
  verified = 0,
  basis: "pinned" | "embedded" = "embedded"
): TransparencyVerifyReport {
  return {
    verdict: "FAIL",
    checkpoints_verified: verified,
    counter_range: null,
    signature_basis: basis,
    findings,
    not_checked: [...OFFLINE_NOT_CHECKED],
  };
}
