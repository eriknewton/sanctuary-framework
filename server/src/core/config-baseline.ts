/**
 * Sanctuary MCP Server — Authenticated config-security baseline (config "5rc")
 *
 * Rebuilds the config-downgrade gate (originally #791) on a CUSTODY-MAC anchor.
 *
 * THE PROBLEM THIS CLOSES. The original gate compared the running config
 * against an adjacent plaintext baseline file (`sanctuary.json.security-
 * baseline.json`). That file was mutable AND unsigned: an on-host attacker who
 * edited `sanctuary.json` to weaken security (disable the approval webhook,
 * drop dashboard TLS, downgrade key protection) could simply rewrite the
 * adjacent baseline to match, and the gate would see "no downgrade." Forging
 * the baseline cost the attacker nothing.
 *
 * THE FIX. The baseline is now authenticated with an HMAC keyed by the operator
 * MASTER KEY (derived via HKDF, label `config-security-baseline-mac`). The
 * master key exists only as wraps in the custody envelope and is derived
 * transiently at boot from the operator credential. Forging the baseline now
 * requires the master key the on-host attacker lacks — exactly the floor the
 * version-anchor rollback record (`state-meta-mac`, F1) uses.
 *
 * VERIFICATION (fail-closed; Sanctuary invariant #5 — never silently degrade):
 *   - MAC present + valid + downgrade detected  -> THROW (refuse boot).
 *   - MAC present + valid + no downgrade         -> advance baseline (re-MAC,
 *                                                   fresh observed_at).
 *   - MAC present + INVALID / marker-stripped /
 *     unparseable / schema mismatch              -> FAIL CLOSED (refuse boot,
 *                                                   `config_baseline_invalid`).
 *                                                   NEVER re-MAC a bare/invalid
 *                                                   record.
 *   - genuine first run (no marker AND no prior
 *     baseline at all)                           -> SEED (write + MAC current
 *                                                   posture). The only
 *                                                   accept-on-missing path:
 *                                                   there is no prior posture to
 *                                                   downgrade from.
 *
 * SEQUENCING. `loadConfig` runs BEFORE the master key is derived, so the MAC
 * check cannot live there (and `loadConfig`/`saveConfig` stay MAC-free, shape-
 * only). `crossCheckConfigBaseline` runs as boot step "5rc", immediately after
 * the master key is established (alongside the "5rb" anti-rollback cross-check).
 *
 * DEBT (documented residual, not closed here — same shape as `state-meta-mac`):
 * an on-host attacker can DELETE the baseline record, which re-enters the
 * genuine-first-run seed path and lets them seed a downgraded posture (a replay
 * of "first run"). The MAC raises forging from "edit a file" to "possess the
 * master key," but deletion-then-reseed is not closed by a record that lives in
 * one deletable location. Closing it needs a floor that does not live in a
 * single deletable place: bind the baseline's existence/epoch into the same
 * boot-anchored monotonic witness the custody anti-rollback floor uses (so a
 * missing baseline on a fortress that previously had one is itself a detectable
 * rollback), or externally attest it. Upgrade path: thread the config-baseline
 * epoch through `observeWitnessEpoch`/`evaluateAndEnforceRollback`
 * (`core/anti-rollback.ts`).
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  assertNoConfigDowngrade,
  configFromSecurityPosture,
  isKeyProtectionValue,
  isPrivacyFailMode,
  isPrivacyFilterMode,
  securityPostureFromConfig,
  ConfigDowngradeError,
  type ConfigSecurityPosture,
  type SanctuaryConfig,
} from "../config.js";
import { canonicalJson } from "../audit/chain.js";
import { derivePurposeKey } from "./key-derivation.js";
import { hmacSha256 } from "./hashing.js";
import {
  constantTimeEqual,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "./encoding.js";

/** Storage namespace + key for the authenticated config-security baseline. */
const CONFIG_BASELINE_NAMESPACE = "_meta";
export const CONFIG_BASELINE_META_KEY = "config-security-baseline-v1";

/** Envelope marker. A record missing this marker is bare/legacy/forged. */
const CONFIG_BASELINE_MARKER = "__sanctuary_config_security_baseline_v1";

/** Schema version of the authenticated baseline record. */
const CONFIG_BASELINE_SCHEMA_VERSION = 1 as const;

/**
 * HKDF purpose label for the baseline MAC key. ADDITIVE — never reuse or alter
 * an existing master-key MAC label (state-meta-mac, custody-envelope-mac,
 * custody-epoch-witness-mac, audit-head-anchor, audit-rotation-anchor,
 * transparency-counter-floor, principal-baseline). Registered in
 * `server/reorg-surface-manifest.md`.
 */
const CONFIG_BASELINE_MAC_PURPOSE = "config-security-baseline-mac";

/**
 * Domain-separation prefix for the MAC input. The MAC covers
 * `CONFIG_BASELINE_MAC_DOMAIN + meta-key + "\n" + canonicalJson(record)`, where
 * `record = { schema_version, observed_at, posture }`. Binding the storage key
 * into the MAC input (as `state-meta-mac` does) prevents replaying a valid
 * baseline envelope under a different `_meta` key.
 */
const CONFIG_BASELINE_MAC_DOMAIN = "sanctuary.config-security-baseline.v1\n";

/** The authenticated record body (the bytes the MAC covers, minus the marker). */
interface ConfigBaselineRecord {
  schema_version: typeof CONFIG_BASELINE_SCHEMA_VERSION;
  observed_at: string;
  posture: ConfigSecurityPosture;
}

/**
 * Thrown when the persisted baseline is present but cannot be authenticated:
 * tampered MAC, stripped marker, unparseable JSON, or schema mismatch. Carries
 * the same `config_baseline_invalid` reason the comparator uses, and NEVER any
 * key bytes (Sanctuary invariant #6).
 */
function configBaselineInvalidError(detail: string): ConfigDowngradeError {
  return new ConfigDowngradeError([
    {
      field: "config.security_baseline",
      reason: "config_baseline_invalid",
      previous: CONFIG_BASELINE_META_KEY,
      next: detail,
    },
  ]);
}

/** MAC over the baseline record, keyed from the master key and bound to the meta key. */
function baselineMacBytes(
  master: Uint8Array,
  metaKey: string,
  record: ConfigBaselineRecord
): Uint8Array {
  const macKey = derivePurposeKey(master, CONFIG_BASELINE_MAC_PURPOSE);
  try {
    return hmacSha256(
      macKey,
      stringToBytes(
        CONFIG_BASELINE_MAC_DOMAIN + metaKey + "\n" + canonicalJson(record)
      )
    );
  } finally {
    macKey.fill(0);
  }
}

/** Validate the shape of a parsed posture; null if any field is wrong-typed. */
function parsePosture(value: unknown): ConfigSecurityPosture | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const p = value as Record<string, unknown>;
  if (
    typeof p.config_version !== "string" ||
    !isKeyProtectionValue(p.state_key_protection) ||
    typeof p.execution_attestation !== "boolean" ||
    typeof p.dashboard_tls_configured !== "boolean" ||
    typeof p.dashboard_auth_configured !== "boolean" ||
    typeof p.webhook_enabled !== "boolean" ||
    !isPrivacyFilterMode(p.privacy_filter_mode) ||
    !isPrivacyFailMode(p.privacy_filter_fail_mode)
  ) {
    return null;
  }
  return {
    config_version: p.config_version,
    state_key_protection: p.state_key_protection,
    execution_attestation: p.execution_attestation,
    dashboard_tls_configured: p.dashboard_tls_configured,
    dashboard_auth_configured: p.dashboard_auth_configured,
    webhook_enabled: p.webhook_enabled,
    privacy_filter_mode: p.privacy_filter_mode,
    privacy_filter_fail_mode: p.privacy_filter_fail_mode,
  };
}

/** Outcome of loading the persisted baseline. */
type BaselineLoad =
  | { status: "absent" }
  | { status: "authenticated"; posture: ConfigSecurityPosture };
// "invalid" is not a return value: it always THROWS (fail-closed) so a caller
// can never accidentally treat an unauthenticated record as absent and reseed.

/**
 * Read and AUTHENTICATE the persisted baseline.
 *   - absent                       -> { status: "absent" } (genuine first run).
 *   - present + marker + valid MAC -> { status: "authenticated", posture }.
 *   - present + anything else      -> THROW configBaselineInvalidError
 *     (tampered MAC, stripped marker, unparseable, schema mismatch). We NEVER
 *     re-MAC or trust a bare/invalid record: doing so would let a filesystem
 *     adversary bypass authentication by stripping the marker and rewriting the
 *     posture.
 */
async function loadAuthenticatedBaseline(
  storage: StorageBackend,
  master: Uint8Array
): Promise<BaselineLoad> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read(CONFIG_BASELINE_NAMESPACE, CONFIG_BASELINE_META_KEY);
  } catch (err) {
    // A read failure on a baseline that may exist is not "absent" — fail closed
    // rather than fall through to the reseed path.
    throw configBaselineInvalidError(
      "baseline read failed: " +
        (err instanceof Error ? err.message : String(err))
    );
  }
  if (!raw) return { status: "absent" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw configBaselineInvalidError("baseline is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw configBaselineInvalidError("baseline root must be an object");
  }
  const obj = parsed as Record<string, unknown>;

  // A present record WITHOUT the marker is a stripped/forged/legacy record. We
  // fail closed rather than treat it as absent: on a fortress that previously
  // had a baseline, a stripped record is exactly the tamper we must catch.
  if (obj[CONFIG_BASELINE_MARKER] !== true) {
    throw configBaselineInvalidError("baseline marker missing (stripped or forged)");
  }

  const data = obj.data;
  const mac = obj.mac;
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    typeof mac !== "string"
  ) {
    throw configBaselineInvalidError("baseline envelope is malformed");
  }
  const body = data as Record<string, unknown>;
  if (
    body.schema_version !== CONFIG_BASELINE_SCHEMA_VERSION ||
    typeof body.observed_at !== "string"
  ) {
    throw configBaselineInvalidError("unsupported baseline schema");
  }
  const posture = parsePosture(body.posture);
  if (!posture) {
    throw configBaselineInvalidError("baseline posture has invalid fields");
  }

  const record: ConfigBaselineRecord = {
    schema_version: CONFIG_BASELINE_SCHEMA_VERSION,
    observed_at: body.observed_at,
    posture,
  };

  let providedMac: Uint8Array;
  try {
    providedMac = fromBase64url(mac);
  } catch {
    throw configBaselineInvalidError("baseline MAC is malformed");
  }
  if (
    !constantTimeEqual(
      providedMac,
      baselineMacBytes(master, CONFIG_BASELINE_META_KEY, record)
    )
  ) {
    throw configBaselineInvalidError(
      "baseline failed authentication (tampered or wrong key)"
    );
  }

  return { status: "authenticated", posture };
}

/**
 * Persist the current config's posture as a freshly MAC-authenticated baseline.
 * Callers MUST hold the master key (the post-key boot step, or any legitimate
 * posture-change path). NOT reachable from `saveConfig` (no key in scope there).
 */
export async function writeAuthenticatedConfigBaseline(
  storage: StorageBackend,
  master: Uint8Array,
  config: SanctuaryConfig
): Promise<void> {
  const record: ConfigBaselineRecord = {
    schema_version: CONFIG_BASELINE_SCHEMA_VERSION,
    observed_at: new Date().toISOString(),
    posture: securityPostureFromConfig(config),
  };
  const envelope = {
    [CONFIG_BASELINE_MARKER]: true,
    data: record,
    mac: toBase64url(
      baselineMacBytes(master, CONFIG_BASELINE_META_KEY, record)
    ),
  };
  await storage.write(
    CONFIG_BASELINE_NAMESPACE,
    CONFIG_BASELINE_META_KEY,
    stringToBytes(JSON.stringify(envelope))
  );
}

/** What the boot cross-check did (for the audit trail / tests). */
export type ConfigBaselineCrossCheck =
  | { kind: "seeded" }
  | { kind: "advanced" };
// "downgrade" and "invalid" are NOT return values: both THROW so boot is
// refused (fail-closed). A throw is the gate.

/**
 * Boot step "5rc": authenticate the persisted config-security baseline against
 * the master key, then compare it to the running config.
 *
 *   - downgrade detected  -> THROW `ConfigDowngradeError` (boot refused).
 *   - invalid baseline    -> THROW `ConfigDowngradeError`
 *                            (`config_baseline_invalid`; boot refused).
 *   - no downgrade        -> advance the baseline (re-MAC, fresh observed_at);
 *                            returns { kind: "advanced" }.
 *   - genuine first run   -> seed the baseline; returns { kind: "seeded" }.
 *
 * Unlike the anti-rollback cross-check (which never refuses boot), this gate
 * MUST refuse: a config downgrade is an operator-policy weakening, and starting
 * with a forged/rolled-back security posture is the exact failure mode
 * Sanctuary invariant #5 forbids.
 */
export async function crossCheckConfigBaseline(args: {
  storage: StorageBackend;
  master: Uint8Array;
  config: SanctuaryConfig;
}): Promise<ConfigBaselineCrossCheck> {
  const { storage, master, config } = args;
  const loaded = await loadAuthenticatedBaseline(storage, master);

  if (loaded.status === "absent") {
    // Genuine first run: no prior posture exists to downgrade FROM. Seed it.
    await writeAuthenticatedConfigBaseline(storage, master, config);
    return { kind: "seeded" };
  }

  // Authenticated baseline present: compare and gate. `configFromSecurityPosture`
  // rebuilds a comparison config whose security-relevant fields equal the stored
  // posture; `assertNoConfigDowngrade` THROWS on any weakening.
  const previous = configFromSecurityPosture(loaded.posture);
  assertNoConfigDowngrade(previous, config);

  // No downgrade: advance the baseline to the current posture (re-MAC).
  await writeAuthenticatedConfigBaseline(storage, master, config);
  return { kind: "advanced" };
}
