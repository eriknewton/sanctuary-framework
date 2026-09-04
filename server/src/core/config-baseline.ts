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
 * DEBT-1 (CLOSED 2026-06-29, via the boot-anchored monotonic witness). The
 * original residual: an on-host attacker without the master key could DELETE the
 * baseline record (re-entering the genuine-first-run seed path) OR present a
 * recognized-OLDER-schema record (the reseed path), and in either case seed a
 * downgraded posture (a replay of "first run"). The custody MAC raised FORGING
 * from "edit a file" to "possess the master key," but neither deletion nor
 * older-schema reseed was closed by a record that lives in ONE deletable
 * location.
 *
 * THE CLOSE-OUT (the upgrade path named in the original DEBT block). The
 * baseline's EXISTENCE and highest sealed SCHEMA are now bound into the same
 * boot-anchored monotonic epoch witness the custody anti-rollback floor uses
 * (`readBaselineEstablishedLatch` / `raiseBaselineEstablishedLatch` in
 * `core/anti-rollback.ts`). On every clean boot the gate raises a monotonic
 * "baseline established" latch + a monotonic sealed-schema floor in the witness
 * (a SEPARATE deletable record, the master-MAC'd epoch witness). Then:
 *   - record ABSENT but the witness latch says a baseline existed
 *                                       -> DELETION replay -> FAIL CLOSED.
 *   - older-schema record BELOW the witness's sealed-schema floor
 *                                       -> DOWNGRADE reseed -> FAIL CLOSED.
 *   - older-schema record AT-OR-ABOVE the floor (or no prior latch)
 *                                       -> legit FORWARD binary upgrade -> reseed
 *                                          (the #805 reseed-not-brick survives).
 *   - genuine first run (no trustworthy latch)  -> seed + raise the latch.
 * This is PREVENTION (boot refused), not just the after-the-fact
 * `config_security_baseline_checked` (outcome `reseeded`) audit entry.
 *
 * CYCLE NOTE. The close-out adds a ONE-DIRECTIONAL `config-baseline ->
 * anti-rollback` import edge only; anti-rollback (and its transitive deps) never
 * import config-baseline, so NO cycle is created and the deliberately-coupled
 * anti-rollback <-> master-custody cycle (cycle 5) is untouched.
 *
 * RESIDUAL (honest, bounded). If the attacker ALSO deletes/tampers the epoch
 * witness, the latch is untrusted and the gate cannot prove a baseline existed
 * from the latch alone; it treats that as a first run and RE-establishes the
 * latch (closing the NEXT replay). On a fortress with real history the joint
 * deletion is independently exposed at boot step 5rb by the rotation/head-anchor
 * splice witnesses; on a brand-new fortress that never rotated/audited, a joint
 * deletion of BOTH records is the same irreducible full-wipe residual Stage 1
 * already documents, bounded only by Stage 2 (Rekor) / Stage 4 (hardware).
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
  readBaselineEstablishedLatch,
  raiseBaselineEstablishedLatch,
} from "./anti-rollback.js";
import {
  constantTimeEqual,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "./encoding.js";

/**
 * Storage namespace + key for the authenticated config-security baseline.
 *
 * MASTER-ROTATION CONTRACT: this record's MAC is keyed from the operator master
 * (`baselineMacBytes` below), so `master-rotation.ts` must restamp it under the
 * new master. The key, marker, MAC purpose, and MAC domain are duplicated there
 * (`CONFIG_BASELINE_*` in `server/src/core/master-rotation.ts`, classified
 * `config-security-baseline` by `classifyMetaKey`) and must match byte-for-byte.
 * Each drift surfaces as a rotation PREFLIGHT refusal, never a corrupt restamp:
 * a KEY drift leaves this record unclassified (generic abort); a PURPOSE or
 * DOMAIN drift fails the engine's old-master MAC verify before any write; a
 * MARKER drift is refused explicitly by the baseline recipe (it sets the
 * engine's `onMarkerMismatch: "abort"`, because `loadAuthenticatedBaseline`
 * below fails the next boot closed on a bare record, so silently leaving it
 * would move the failure from preflight to the first post-rotation boot). If
 * you rename any of the four, or change the MAC input layout, change both files
 * in the same PR.
 */
const CONFIG_BASELINE_NAMESPACE = "_meta";
export const CONFIG_BASELINE_META_KEY = "config-security-baseline-v1";

/**
 * Envelope marker. A record missing this marker is bare/legacy/forged.
 * Must match CONFIG_BASELINE_MARKER in server/src/core/master-rotation.ts.
 */
const CONFIG_BASELINE_MARKER = "__sanctuary_config_security_baseline_v1";

/**
 * Schema version of the authenticated baseline record.
 *
 * v1 -> v2 (#805 review fix): the posture now tracks
 * `dashboard_allow_plaintext_remote`.
 * v2 -> v3 (second-angle sibling-gap sweep): the posture now also tracks
 * `privacy_filter_command`, `disclosure_default_policy`, `verascore_auto_publish`,
 * and `erc8004_confirmation_enabled`. An older record (v1 or v2) lacks these
 * fields, so it cannot be authenticated as v3, but an operator who upgraded
 * the binary is NOT an attacker, so a recognized OLDER schema reseeds (fresh
 * sealed baseline under the same master-key MAC) rather than bricking the boot.
 * An UNKNOWN (future/forged, schema > current) version still fails closed.
 */
const CONFIG_BASELINE_SCHEMA_VERSION = 3 as const;

/**
 * HKDF purpose label for the baseline MAC key. ADDITIVE — never reuse or alter
 * an existing master-key MAC label (state-meta-mac, custody-envelope-mac,
 * custody-epoch-witness-mac, audit-head-anchor, audit-rotation-anchor,
 * transparency-counter-floor, principal-baseline). Registered in
 * `server/reorg-surface-manifest.md`.
 * Must match CONFIG_BASELINE_MAC_PURPOSE in server/src/core/master-rotation.ts.
 */
const CONFIG_BASELINE_MAC_PURPOSE = "config-security-baseline-mac";

/**
 * Domain-separation prefix for the MAC input. The MAC covers
 * `CONFIG_BASELINE_MAC_DOMAIN + meta-key + "\n" + canonicalJson(record)`, where
 * `record = { schema_version, observed_at, posture }`. Binding the storage key
 * into the MAC input (as `state-meta-mac` does) prevents replaying a valid
 * baseline envelope under a different `_meta` key.
 * Must match CONFIG_BASELINE_MAC_DOMAIN in server/src/core/master-rotation.ts,
 * whose restamp recipe appends `META_KEY + "\n"` to this prefix to reproduce
 * the exact MAC input `baselineMacBytes` computes.
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
    typeof p.dashboard_allow_plaintext_remote !== "boolean" ||
    typeof p.webhook_enabled !== "boolean" ||
    !isPrivacyFilterMode(p.privacy_filter_mode) ||
    !isPrivacyFailMode(p.privacy_filter_fail_mode) ||
    typeof p.privacy_filter_command !== "string" ||
    !isDisclosureDefaultPolicy(p.disclosure_default_policy) ||
    typeof p.verascore_auto_publish !== "boolean" ||
    typeof p.erc8004_confirmation_enabled !== "boolean"
  ) {
    return null;
  }
  return {
    config_version: p.config_version,
    state_key_protection: p.state_key_protection,
    execution_attestation: p.execution_attestation,
    dashboard_tls_configured: p.dashboard_tls_configured,
    dashboard_auth_configured: p.dashboard_auth_configured,
    dashboard_allow_plaintext_remote: p.dashboard_allow_plaintext_remote,
    webhook_enabled: p.webhook_enabled,
    privacy_filter_mode: p.privacy_filter_mode,
    privacy_filter_fail_mode: p.privacy_filter_fail_mode,
    privacy_filter_command: p.privacy_filter_command,
    disclosure_default_policy: p.disclosure_default_policy,
    verascore_auto_publish: p.verascore_auto_publish,
    erc8004_confirmation_enabled: p.erc8004_confirmation_enabled,
  };
}

/** Type guard: a valid `disclosure.default_policy` enum value. */
function isDisclosureDefaultPolicy(
  value: unknown
): value is ConfigSecurityPosture["disclosure_default_policy"] {
  return value === "minimum-necessary" || value === "withhold-all";
}

/** Outcome of loading the persisted baseline. */
type BaselineLoad =
  | { status: "absent" }
  | { status: "reseed"; recognizedSchema: number }
  | { status: "authenticated"; posture: ConfigSecurityPosture };
// "invalid" is not a return value: it always THROWS (fail-closed) so a caller
// can never accidentally treat an unauthenticated record as absent and reseed.
// "reseed" is returned ONLY for a recognized older schema version (a binary
// upgrade, not an attack); the caller writes a fresh sealed baseline. It is
// reached BEFORE the MAC check, so it never trusts an old record's posture.

/**
 * Read and AUTHENTICATE the persisted baseline.
 *   - absent                       -> { status: "absent" } (genuine first run).
 *   - recognized OLDER schema      -> { status: "reseed" } (binary upgrade; the
 *     caller writes a fresh sealed baseline rather than bricking the boot).
 *   - present + marker + valid MAC -> { status: "authenticated", posture }.
 *   - present + anything else      -> THROW configBaselineInvalidError
 *     (tampered MAC, stripped marker, unparseable, unknown/future schema). We
 *     NEVER re-MAC or trust a bare/invalid record: doing so would let a
 *     filesystem adversary bypass authentication by stripping the marker and
 *     rewriting the posture.
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
  if (typeof body.observed_at !== "string") {
    throw configBaselineInvalidError("unsupported baseline schema");
  }
  // Schema migration vs. tamper. A recognized OLDER schema (an operator who
  // upgraded the binary) is not necessarily an attack: signal a reseed and carry
  // the recognized schema so the CALLER can distinguish a legit forward upgrade
  // from a downgrade-reseed replay against the boot-anchored witness's
  // sealed-schema floor (DEBT-1 close-out in `crossCheckConfigBaseline`). This
  // branch is reached BEFORE the MAC check, so the older record's MAC is NOT
  // verified here (an older-schema record cannot authenticate as the current
  // schema anyway; the MAC covers the schema): the reseed mints from the CURRENT
  // config and never trusts the old record's posture. An UNKNOWN/FUTURE schema
  // (version > current, or a non-integer) is forged/tampered: fail closed.
  if (body.schema_version !== CONFIG_BASELINE_SCHEMA_VERSION) {
    if (
      typeof body.schema_version === "number" &&
      Number.isInteger(body.schema_version) &&
      body.schema_version >= 1 &&
      body.schema_version < CONFIG_BASELINE_SCHEMA_VERSION
    ) {
      return { status: "reseed", recognizedSchema: body.schema_version };
    }
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
  | { kind: "reseeded" }
  | { kind: "advanced" };
// "downgrade" and "invalid" are NOT return values: both THROW so boot is
// refused (fail-closed). A throw is the gate. "reseeded" is a schema migration
// (recognized older schema -> fresh sealed baseline), distinct from a genuine
// first-run "seeded" so the audit trail records why a new baseline was minted.

/**
 * Build the `config_baseline_rollback` refusal (DEBT-1 close-out): the baseline
 * record is absent (deleted) or presents an older schema (downgrade reseed) on a
 * fortress whose boot-anchored monotonic witness records that a baseline was
 * already established. Distinct reason from `config_baseline_invalid` so the
 * audit trail and operator banner name the deletion/downgrade-replay, not a
 * tampered record. Carries NO key bytes (Sanctuary invariant #6).
 */
function configBaselineRollbackError(detail: string): ConfigDowngradeError {
  return new ConfigDowngradeError([
    {
      field: "config.security_baseline",
      reason: "config_baseline_rollback",
      previous: CONFIG_BASELINE_META_KEY,
      next: detail,
    },
  ]);
}

/**
 * Boot step "5rc": authenticate the persisted config-security baseline against
 * the master key, cross-check its EXISTENCE against the boot-anchored monotonic
 * witness (DEBT-1 close-out), then compare its posture to the running config.
 *
 *   - downgrade detected  -> THROW `ConfigDowngradeError` (boot refused).
 *   - invalid baseline    -> THROW `ConfigDowngradeError`
 *                            (`config_baseline_invalid`; boot refused).
 *   - DELETION replay     -> THROW `ConfigDowngradeError`
 *     (record absent but the witness latch says a baseline WAS established;
 *      `config_baseline_rollback`; boot refused). This closes the DEBT-1
 *      deletion-then-reseed leg with PREVENTION, not just an after-the-fact
 *      `reseeded` audit entry.
 *   - DOWNGRADE reseed    -> THROW `ConfigDowngradeError`
 *     (an older-schema record presented on a fortress whose witness already
 *      sealed a HIGHER schema; `config_baseline_rollback`; boot refused). This
 *      closes the DEBT-1 older-schema-reseed leg.
 *   - no downgrade        -> advance the baseline (re-MAC, fresh observed_at) and
 *                            re-raise the witness latch; returns { kind: "advanced" }.
 *   - genuine first run   -> seed the baseline + raise the witness latch; returns
 *                            { kind: "seeded" }.
 *   - FORWARD schema upgrade (binary upgrade: on-disk schema AT-OR-ABOVE the
 *     witness's sealed-schema floor, or no prior latch) -> reseed under the
 *     current schema + advance the latch; returns { kind: "reseeded" }. NOT a
 *     brick: the #805 reseed-not-brick behavior survives; only a BACKWARD reseed
 *     below the sealed floor is refused.
 *
 * THE WITNESS THREADING (DEBT-1). The config-baseline record lives in a single
 * deletable location; deleting it (or presenting an older-schema record) re-
 * enters the genuine-first-run seed path and seeds a downgraded posture WITHOUT
 * the master key. We close that by binding the baseline's existence + highest
 * sealed schema into the SAME boot-anchored monotonic epoch witness the custody
 * anti-rollback floor uses (`readBaselineEstablishedLatch` /
 * `raiseBaselineEstablishedLatch` in `core/anti-rollback.ts`). The latch lives
 * in a SEPARATE deletable record (the master-MAC'd epoch witness), so a missing
 * baseline on a fortress whose witness says one existed is itself a detected
 * rollback. CYCLE NOTE: this adds a one-directional `config-baseline ->
 * anti-rollback` import edge only; anti-rollback (and its deps) never import
 * config-baseline, so no cycle is created and the deliberately-coupled
 * anti-rollback<->master-custody cycle 5 is untouched.
 *
 * HONEST RESIDUAL. If the witness is UNTRUSTED (the attacker deleted/tampered
 * the epoch witness too), we cannot prove a baseline existed from the latch
 * alone, so we treat it as a first run and re-establish the latch (closing the
 * NEXT replay). On a fortress with real history the joint deletion is exposed by
 * the rotation/head-anchor splice witnesses at boot step 5rb; on a brand-new
 * fortress that never rotated/audited, a joint deletion of both records is the
 * same irreducible full-wipe residual Stage 1 already documents (bounded by
 * Stage 2/4). The latch raises the cost from "delete one record" to "delete the
 * master-MAC'd witness too."
 *
 * Unlike the anti-rollback cross-check (which never refuses boot), this gate
 * MUST refuse: a config downgrade, including a deletion/downgrade replay, is an
 * operator-policy weakening, and starting with a forged/rolled-back security
 * posture is the exact failure mode Sanctuary invariant #5 forbids.
 */
export async function crossCheckConfigBaseline(args: {
  storage: StorageBackend;
  master: Uint8Array;
  config: SanctuaryConfig;
}): Promise<ConfigBaselineCrossCheck> {
  const { storage, master, config } = args;
  const loaded = await loadAuthenticatedBaseline(storage, master);
  // The boot-anchored monotonic witness of whether a baseline was already
  // established (and at what highest schema). Read it BEFORE acting so the
  // seed/reseed paths can tell a genuine first run from a deletion/downgrade
  // replay.
  const latch = await readBaselineEstablishedLatch(storage, master);

  if (loaded.status === "absent") {
    // DEBT-1 deletion leg. A baseline record that is ABSENT on a fortress whose
    // authenticated witness latch says one WAS established is a deletion-replay:
    // the attacker deleted the single deletable record to re-enter the first-run
    // seed path and seed a downgraded posture. Fail closed (refuse boot). Only a
    // GENUINE first run (no trustworthy latch saying otherwise) seeds.
    if (latch.established) {
      throw configBaselineRollbackError(
        "the config-security baseline record is absent, but the boot-anchored " +
          "witness records that a baseline was already established; the record " +
          "appears to have been deleted to replay first-run seeding (a config " +
          "downgrade replay)"
      );
    }
    // Genuine first run (or the irreducible witness-untrusted residual): no
    // trustworthy prior posture exists to downgrade FROM. Seed it, then raise the
    // witness latch so the NEXT deletion is detected.
    await writeAuthenticatedConfigBaseline(storage, master, config);
    await raiseBaselineEstablishedLatch(
      storage,
      master,
      CONFIG_BASELINE_SCHEMA_VERSION
    );
    return { kind: "seeded" };
  }

  if (loaded.status === "reseed") {
    // DEBT-1 reseed leg. A recognized OLDER-schema record. Distinguish a
    // legitimate FORWARD binary upgrade from a BACKWARD downgrade-reseed attack
    // using the witness's monotonic sealed-schema floor:
    //  - presented schema BELOW the sealed floor  -> downgrade reseed: an
    //    attacker rolled a v3 fortress back to a hand-written v2 record to replay
    //    seeding from a downgraded config. Fail closed.
    //  - presented schema AT-OR-ABOVE the floor (or no/legacy floor) -> a genuine
    //    binary upgrade: the prior binary legitimately sealed this older schema.
    //    Reseed (the #805 reseed-not-brick behavior) and advance the floor.
    if (
      latch.established &&
      typeof latch.sealedSchema === "number" &&
      loaded.recognizedSchema < latch.sealedSchema
    ) {
      throw configBaselineRollbackError(
        "the config-security baseline presents schema " +
          `${loaded.recognizedSchema}, but the boot-anchored witness records a ` +
          `higher sealed schema (${latch.sealedSchema}); an older-schema record ` +
          "after a newer one existed is a downgrade-reseed replay, not a binary " +
          "upgrade"
      );
    }
    // Legitimate forward schema upgrade. There is no current-schema posture to
    // downgrade FROM, and the older record's posture is not trusted (it never
    // passed the current MAC check). Mint a fresh sealed baseline + advance the
    // witness floor to the current schema.
    await writeAuthenticatedConfigBaseline(storage, master, config);
    await raiseBaselineEstablishedLatch(
      storage,
      master,
      CONFIG_BASELINE_SCHEMA_VERSION
    );
    return { kind: "reseeded" };
  }

  // Authenticated baseline present: compare and gate. `configFromSecurityPosture`
  // rebuilds a comparison config whose security-relevant fields equal the stored
  // posture; `assertNoConfigDowngrade` THROWS on any weakening.
  const previous = configFromSecurityPosture(loaded.posture);
  assertNoConfigDowngrade(previous, config);

  // No downgrade: advance the baseline to the current posture (re-MAC) and keep
  // the witness latch current (idempotent; raises it if a legacy fortress never
  // had one).
  await writeAuthenticatedConfigBaseline(storage, master, config);
  await raiseBaselineEstablishedLatch(
    storage,
    master,
    CONFIG_BASELINE_SCHEMA_VERSION
  );
  return { kind: "advanced" };
}
