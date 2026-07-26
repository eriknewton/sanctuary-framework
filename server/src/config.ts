/**
 * Sanctuary MCP Server — Configuration
 *
 * Loads and validates server configuration from file or environment variables.
 */

import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { ConfigLoadError } from "./errors/config-error.js";
import { assertHermeticStoragePath } from "./paths.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

/**
 * Strictly parse a whole-string integer from an env var.
 *
 * `parseInt("80abc", 10)` returns `80`, stopping at the first non-digit and
 * silently TRUNCATES, binding the server to a port the operator never typed.
 * Returning `NaN` for any non-clean-integer string instead lets the downstream
 * range check in `validateConfig` REFUSE the value rather than bind a truncated
 * port. This is an independent fail-closed hardening of the env override; it
 * does not depend on any native-side behavior.
 *
 * Forward note (not yet true in-tree): the deferred native macOS embed/badge
 * resolver is intended to parse the SAME env var strictly
 * (`Int(raw.trimmingCharacters(in:))` + a 1...65535 guard) and fall back to
 * 3501, so that once it lands the server and the native reads stay on a single
 * source. Today the native bridge (`SanctuaryServerBridge`) hardcodes port 3501
 * and does not read `SANCTUARY_DASHBOARD_PORT`, so true single-source port
 * parity does NOT hold yet, a valid non-default port still diverges the two.
 *
 * Accepts ASCII digits only (e.g. "3501"). A TCP port is an unsigned quantity,
 * so a leading sign ("+8443", "-1") is never operator intent; rejecting it keeps
 * this reader byte-for-byte aligned with `parseStrictPortEnv` in `paths.ts` (the
 * wrap/Protect boot path), so the same env value never resolves to two different
 * ports across the two TypeScript readers. Returns `NaN` for "", "+8443", "-1",
 * "80abc", "0x10", "3501 5", or any value with a sign or trailing/embedded
 * non-digits, so the caller's validation rejects it.
 */
function strictParseIntEnv(raw: string): number {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    return Number.NaN;
  }
  return Number.parseInt(trimmed, 10);
}

/** Package version, exported for use by other modules (avoids duplicate require paths). */
export const SANCTUARY_VERSION = PKG_VERSION;

/**
 * Marker prefix thrown by `validateConfig` when the ONLY problems are
 * out-of-range / non-integer scalar VALUES on a structurally-valid file (e.g.
 * dashboard.port = 70000). The file-load path keys off this to fail closed
 * WITHOUT quarantining: a value typo is not corruption.
 */
const CONFIG_VALUE_ERROR_PREFIX = "Sanctuary configuration has an invalid value";
/**
 * Marker prefix thrown by `validateConfig` when the config references a feature
 * this build cannot honor (genuine schema mismatch). The file-load path
 * quarantines on this. Kept byte-stable for the existing error contract.
 */
const CONFIG_FEATURE_ERROR_PREFIX =
  "Sanctuary configuration references unimplemented features";

export interface SanctuaryConfig {
  version: string;
  storage_path: string;

  state: {
    encryption: "aes-256-gcm";
    key_protection: "passphrase" | "hardware-key" | "none";
    key_derivation: "argon2id";
    integrity: "merkle-sha256";
    identity_provider: "ed25519";
  };

  execution: {
    environment: "local-process" | "docker" | "tee";
    attestation: boolean;
    resource_limits: {
      max_memory_mb: number;
      max_storage_mb: number;
      max_cpu_percent: number;
    };
  };

  disclosure: {
    proof_system: "groth16" | "plonk" | "schnorr-pedersen" | "commitment-only";
    default_policy: "minimum-necessary" | "withhold-all";
  };

  reputation: {
    mode: "self-custodied" | "service-mediated";
    attestation_format: "eas-compatible";
    export_format: "SANCTUARY_REP_V1";
    service_endpoints: string[];
  };

  transport: "stdio" | "http";
  http_port: number;

  dashboard: {
    enabled: boolean;
    port: number;
    host: string;
    /** Bearer token for dashboard auth. If "auto", one is generated at startup. */
    auth_token?: string;
    /** Auto-open dashboard in default browser on startup. Default: true for localhost. */
    auto_open?: boolean;
    /** TLS cert/key paths for HTTPS dashboard. */
    tls?: {
      cert_path: string;
      key_path: string;
    };
    /**
     * Allow plaintext HTTP on non-loopback dashboard bindings. Default false.
     * Only set when a separate network layer already encrypts the transport.
     */
    allow_plaintext_remote?: boolean;
  };

  webhook: {
    enabled: boolean;
    /** URL to POST approval requests to */
    url: string;
    /** Shared secret for HMAC-SHA256 signatures */
    secret: string;
    /** Port for callback listener (receives approval responses) */
    callback_port: number;
    /** Host for callback listener */
    callback_host: string;
  };

  /** Verascore integration (agent reputation surface) */
  verascore: {
    /** Base URL of the Verascore deployment. */
    url: string;
    /** Whether to auto-publish handshake attestations to Verascore. */
    auto_publish_to_verascore: boolean;
    /** Whether to auto-publish on successful handshake_respond calls. */
    auto_publish_handshakes: boolean;
  };

  /** ERC-8004 registry-read integration. Optional and default-off. */
  erc8004: {
    registry_confirmation: {
      /** When false, resolve_erc8004_identity stays fully offline. */
      enabled: boolean;
      /** Operator-configured JSON-RPC endpoint. Empty means no RPC read. */
      rpc_url: string;
      /** Chain to read against. Defaults to Ethereum mainnet (1). */
      chain_id: number;
      /** RPC request timeout in milliseconds. */
      timeout_ms: number;
    };
  };

  privacy_filter: {
    mode: "local" | "opf" | "off";
    fail_mode: "closed" | "fallback";
    command: string;
    timeout_ms: number;
  };
}

/**
 * Why a config downgrade is refused. Surfaced in `ConfigDowngradeError` and
 * (for the boot gate) in the audit trail; never carries secret values.
 */
export type ConfigDowngradeReason =
  | "config_version_invalid"
  | "config_version_rollback"
  | "state_key_protection_downgrade"
  | "execution_attestation_disabled"
  | "dashboard_tls_disabled"
  | "dashboard_plaintext_remote_enabled"
  | "dashboard_auth_disabled"
  | "webhook_gate_disabled"
  | "privacy_filter_disabled"
  | "privacy_fail_mode_downgrade"
  | "privacy_filter_command_changed"
  | "disclosure_default_policy_loosened"
  | "verascore_autopublish_enabled"
  | "erc8004_confirmation_enabled"
  | "config_baseline_invalid"
  // DEBT-1: the baseline record is absent (deleted) or presents an older schema
  // (downgrade reseed) on a fortress whose boot-anchored monotonic witness
  // records a baseline was already established (a deletion/downgrade replay),
  // refused by the config gate (`core/config-baseline.ts`).
  | "config_baseline_rollback";

export interface ConfigDowngrade {
  field: string;
  reason: ConfigDowngradeReason;
  previous: unknown;
  next: unknown;
}

export class ConfigDowngradeError extends Error {
  constructor(public readonly downgrades: ConfigDowngrade[]) {
    super(
      "Sanctuary configuration downgrade refused: " +
        downgrades.map((d) => `${d.field} (${d.reason})`).join(", ")
    );
    this.name = "ConfigDowngradeError";
  }
}

/**
 * The security-relevant projection of a config, captured in the authenticated
 * baseline. Only fields whose weakening is a security downgrade are recorded;
 * secrets are recorded as presence booleans, never as raw values.
 */
export interface ConfigSecurityPosture {
  config_version: string;
  state_key_protection: SanctuaryConfig["state"]["key_protection"];
  execution_attestation: boolean;
  dashboard_tls_configured: boolean;
  dashboard_auth_configured: boolean;
  /**
   * Whether plaintext HTTP is permitted on non-loopback dashboard bindings.
   * Flipping this false -> true is a security downgrade (it allows the operator
   * console to serve unencrypted traffic on a routable interface), so the
   * posture tracks it and the comparator gates it.
   */
  dashboard_allow_plaintext_remote: boolean;
  webhook_enabled: boolean;
  privacy_filter_mode: SanctuaryConfig["privacy_filter"]["mode"];
  privacy_filter_fail_mode: SanctuaryConfig["privacy_filter"]["fail_mode"];
  /**
   * The configured privacy-filter executable path. Tracked because, while a
   * filtering mode is active ("local"/"opf"), silently REPOINTING this command
   * (e.g. to a no-op binary) disables filtering without ever flipping `mode`
   * to "off", a covert downgrade the mode check alone would miss. The
   * comparator flags any CHANGE to this string while the previous mode was a
   * filtering mode.
   */
  privacy_filter_command: string;
  /**
   * The disclosure default policy. `withhold-all` is strictly stronger than
   * `minimum-necessary`; loosening it (withhold-all -> minimum-necessary)
   * exposes more by default, so the comparator gates the loosening direction.
   */
  disclosure_default_policy: SanctuaryConfig["disclosure"]["default_policy"];
  /**
   * Whether handshake attestations auto-publish to Verascore. Flipping either
   * auto-publish flag false -> true increases external egress of
   * reputation/handshake data, so the posture tracks both as one OR'd signal
   * and the comparator gates false -> true.
   */
  verascore_auto_publish: boolean;
  /**
   * Whether ERC-8004 on-chain registry confirmation is enabled. Default-off;
   * flipping false -> true opens an external JSON-RPC egress path, so the
   * comparator gates the enabling direction.
   */
  erc8004_confirmation_enabled: boolean;
}

/** Default configuration */
export function defaultConfig(): SanctuaryConfig {
  return {
    version: PKG_VERSION,
    // Deliberately the raw join, NOT the guarded homeFortressPath(): this is
    // the CONSTRUCTION of a default value, not a decision to touch that
    // directory. Most callers immediately override storage_path (from the
    // config file, an explicit temp path, or SANCTUARY_STORAGE_PATH), so
    // failing here would fire on hundreds of already-isolated tests that never
    // go near the operator's fortress.
    //
    // CORRECTION (adversarial review of this PR). An earlier version of this
    // comment claimed the guard sits "on the places this value is used to open
    // storage, which is where reaching the real fortress actually costs
    // something", with the implication that leaving this join unguarded was
    // free. It was not. This value flowed unguarded into `saveConfig` via
    // `index.ts` step 20, and five test files that boot the server therefore
    // REWROTE the operator's real `~/.sanctuary/sanctuary.json` on every suite
    // run. Measured, not inferred: an idle control froze the mtime, and two
    // consecutive full-suite runs each moved it.
    //
    // The seam is now closed at the write itself: `saveConfig` below calls
    // `assertHermeticStoragePath` on the directory it is about to write, so an
    // unguarded default that reaches a real write fails closed under Vitest.
    // Constructing the value stays free; SPENDING it does not.
    storage_path: join(homedir(), ".sanctuary"),
    state: {
      encryption: "aes-256-gcm",
      key_protection: "none",
      key_derivation: "argon2id",
      integrity: "merkle-sha256",
      identity_provider: "ed25519",
    },
    execution: {
      environment: "local-process",
      attestation: true,
      resource_limits: {
        max_memory_mb: 512,
        max_storage_mb: 1024,
        max_cpu_percent: 50,
      },
    },
    disclosure: {
      proof_system: "schnorr-pedersen",
      default_policy: "minimum-necessary",
    },
    reputation: {
      mode: "self-custodied",
      attestation_format: "eas-compatible",
      export_format: "SANCTUARY_REP_V1",
      service_endpoints: [],
    },
    transport: "stdio",
    http_port: 3500,
    dashboard: {
      enabled: false,
      port: 3501,
      host: "127.0.0.1",
      allow_plaintext_remote: false,
    },
    webhook: {
      enabled: false,
      url: "",
      secret: "",
      callback_port: 3502,
      callback_host: "127.0.0.1",
    },
    verascore: {
      url: "https://verascore.ai",
      auto_publish_to_verascore: true,
      // DELTA-04: default OFF for privacy. Enable explicitly per deployment.
      auto_publish_handshakes: false,
    },
    erc8004: {
      registry_confirmation: {
        enabled: false,
        rpc_url: "",
        chain_id: 1,
        timeout_ms: 10_000,
      },
    },
    privacy_filter: {
      mode: "local",
      // Fail-closed by default per Sanctuary Invariant #5: never silently
      // degrade to a less-secure behavior on error. Operators who need a
      // legacy fallback path opt in explicitly via config or env var.
      fail_mode: "closed",
      command: "opf",
      timeout_ms: 5000,
    },
  };
}

/**
 * Load configuration from file, falling back to defaults.
 *
 * Precedence (highest wins): CLI flags > env vars > config file > defaults
 * This matches the standard config precedence pattern used by most tools.
 *
 * DOCUMENTED BEHAVIOUR CHANGE: `storage_path` from the config file, and
 * which keychain entry holds the master passphrase
 * ------------------------------------------------------------------------
 * `loadConfig().storage_path` and `paths.resolveStoragePath()` are two
 * different answers to "which fortress", and they can disagree. They diverge
 * in exactly one case: `SANCTUARY_STORAGE_PATH` is unset AND the config file
 * at `~/.sanctuary/sanctuary.json` carries a `storage_path` key pointing
 * somewhere else.
 *
 *   loadConfig().storage_path  -> the config file's value  (e.g. /srv/agent-b)
 *   resolveStoragePath()       -> <home>/.sanctuary
 *
 * The CLI verbs that derive a fortress master key (`sentinel`, `anomaly`,
 * `auto-trigger`, `policy drafts activate`, `template init`) now scope their
 * passphrase lookup to `loadConfig().storage_path` -- the fortress they
 * actually open. Previously the lookup re-resolved ambiently inside
 * `getOrCreatePassphrase()` and therefore used `resolveStoragePath()`.
 *
 * For such an operator the keychain service name consulted changes:
 *
 *   before:  sanctuary-passphrase                       (the HOME-default name)
 *   after:   sanctuary-passphrase-<sha256(storage_path)[0:16]>
 *
 * This is INTENTIONAL, and it is the point of the change: the credential that
 * unlocks a fortress should be named after that fortress, not after whichever
 * directory the process happened to resolve from the environment. The old
 * behaviour meant two fortresses on one host could share one keychain entry.
 *
 * The failure mode when it bites is bounded and FAIL-CLOSED, verified against
 * `core/master-custody.ts`: the fortress-named entry does not exist yet, so
 * `getOrCreatePassphrase` mints a new random passphrase and writes a new
 * keyring entry, and `establishMaster` then fails to unwrap the existing
 * custody envelope and THROWS `CustodyUnlockError`. It does NOT re-mint a
 * master and does NOT re-encrypt or orphan data. The operator sees a hard
 * unlock error plus one spurious keyring entry, and recovers by naming the
 * fortress explicitly (`--fortress <path>` or `SANCTUARY_STORAGE_PATH`), which
 * makes both readers agree again.
 *
 * Reachability is low: nothing in this codebase produces a divergent config,
 * because `saveConfig` writes to `join(config.storage_path, "sanctuary.json")`
 * and so a self-written config is always self-consistent. It requires a
 * hand-edited file or an external provisioner.
 *
 * Preferred long-term resolution is to retire the config-file `storage_path`
 * key so there is exactly one way to name a fortress. That is a deprecation
 * with its own migration and is deliberately not folded into this change.
 */
export async function loadConfig(
  configPath?: string
): Promise<SanctuaryConfig> {
  let config = defaultConfig();

  // Phase 1: Merge config file on top of defaults
  const storagePath = process.env.SANCTUARY_STORAGE_PATH ?? config.storage_path;
  const path = configPath ?? join(storagePath, "sanctuary.json");

  try {
    const raw = await readFile(path, "utf-8");
    // An empty or whitespace-only file is not corruption: it is almost always
    // the truncate-before-write window of a concurrent writer (saveConfig from
    // another process, or a parallel test that shares a config path). The
    // non-atomic writeFile in saveConfig truncates to zero bytes before it
    // rewrites, so a reader can momentarily observe "". JSON.parse("") throws
    // SyntaxError, which would otherwise route to the corruption-quarantine
    // branch below and destructively rename a file that is about to be valid
    // again. Treat it like a missing file and fall back to defaults. Non-empty
    // invalid JSON still quarantines as genuine corruption.
    if (raw.trim() !== "") {
      const fileConfig = JSON.parse(raw);
      if (fileConfig === null || typeof fileConfig !== "object" || Array.isArray(fileConfig)) {
        throw new Error("Sanctuary config field \"$root\" must be an object");
      }
      config = deepMerge(config, fileConfig);
      // Catch shape regressions from a malformed user-supplied JSON
      // (e.g. `dashboard: "not-an-object"`) before downstream code casts.
      assertSanctuaryConfigShape(config as unknown as Record<string, unknown>);
      validateConfig(config);
    }
  } catch (err) {
    if (isErrno(err, "ENOENT")) {
      // No config file: first-run defaults are allowed.
    } else if (err instanceof SyntaxError) {
      const quarantinedPath = await quarantineConfigFile(path);
      throw new ConfigLoadError({
        path,
        classification: "corrupted",
        detail: "The config file is not valid JSON. Wrong-key is not applicable to plaintext config.",
        recovery: "Inspect the quarantined copy, restore a known-good config, or intentionally create a new config before retrying.",
        quarantinedPath,
        cause: err,
      });
    } else if (isConfigValueError(err)) {
      // A structurally-valid, well-typed config file with only an out-of-range
      // or non-integer scalar VALUE (e.g. dashboard.port = 70000). Fail CLOSED
      // (the server must not start with an invalid value) but do NOT
      // quarantine: a value typo is not corruption, and renaming the operator's
      // file away from under them is surprising and destructive. The file is
      // left in place so the operator can read the error and fix the value.
      throw new ConfigLoadError({
        path,
        classification: "invalid-value",
        detail: `${err instanceof Error ? err.message : "The config has an invalid value."} The file was left in place (not quarantined); a value typo is not corruption.`,
        recovery: "Correct the invalid value in the config file in place, then retry. Sanctuary did not start and did not move your file.",
        cause: err,
      });
    } else if (isConfigSchemaError(err)) {
      const quarantinedPath = await quarantineConfigFile(path);
      throw new ConfigLoadError({
        path,
        classification: "schema-mismatch",
        detail: `${err instanceof Error ? err.message : "The config schema is invalid."} Wrong-key is not applicable to plaintext config.`,
        recovery: "Update the config to match the current Sanctuary schema or restore a compatible backup before retrying.",
        quarantinedPath,
        cause: err,
      });
    } else if (isErrno(err, "EACCES") || isErrno(err, "EPERM")) {
      throw new ConfigLoadError({
        path,
        classification: "unreadable",
        detail: "Sanctuary could not read the config file because the operating system denied access. Corruption cannot be determined until the file is readable.",
        recovery: "Fix file ownership or permissions, then retry. Sanctuary did not continue with defaults.",
        cause: err,
      });
    } else {
      throw new ConfigLoadError({
        path,
        classification: "unreadable",
        detail: `Sanctuary could not read the config file. Corruption cannot be determined. ${err instanceof Error ? err.message : String(err)}`,
        recovery: "Resolve the read failure, then retry. Sanctuary did not continue with defaults.",
        cause: err,
      });
    }
  }

  // Phase 2: Apply env var overrides ON TOP of file config (env always wins)
  if (process.env.SANCTUARY_STORAGE_PATH) {
    config.storage_path = process.env.SANCTUARY_STORAGE_PATH;
  }
  if (process.env.SANCTUARY_TRANSPORT) {
    config.transport = process.env.SANCTUARY_TRANSPORT as "stdio" | "http";
  }
  if (process.env.SANCTUARY_HTTP_PORT) {
    config.http_port = parseInt(process.env.SANCTUARY_HTTP_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED === "true") {
    config.dashboard.enabled = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED === "false") {
    config.dashboard.enabled = false;
  }
  if (process.env.SANCTUARY_DASHBOARD_PORT) {
    // Strict whole-string parse so an invalid value (e.g. "80abc") becomes NaN
    // here and is refused by validateConfig, instead of parseInt silently
    // truncating it to a bound-but-unintended port. Fail-closed on bad input.
    config.dashboard.port = strictParseIntEnv(process.env.SANCTUARY_DASHBOARD_PORT);
  }
  if (process.env.SANCTUARY_DASHBOARD_HOST) {
    config.dashboard.host = process.env.SANCTUARY_DASHBOARD_HOST;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN) {
    config.dashboard.auth_token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTO_OPEN === "true") {
    config.dashboard.auto_open = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTO_OPEN === "false") {
    config.dashboard.auto_open = false;
  }
  if (process.env.SANCTUARY_DASHBOARD_TLS_CERT && process.env.SANCTUARY_DASHBOARD_TLS_KEY) {
    config.dashboard.tls = {
      cert_path: process.env.SANCTUARY_DASHBOARD_TLS_CERT,
      key_path: process.env.SANCTUARY_DASHBOARD_TLS_KEY,
    };
  }
  if (process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE === "true") {
    config.dashboard.allow_plaintext_remote = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE === "false") {
    config.dashboard.allow_plaintext_remote = false;
  }
  if (process.env.SANCTUARY_WEBHOOK_ENABLED === "true") {
    config.webhook.enabled = true;
  }
  if (process.env.SANCTUARY_WEBHOOK_ENABLED === "false") {
    config.webhook.enabled = false;
  }
  if (process.env.SANCTUARY_WEBHOOK_URL) {
    config.webhook.url = process.env.SANCTUARY_WEBHOOK_URL;
  }
  if (process.env.SANCTUARY_WEBHOOK_SECRET) {
    config.webhook.secret = process.env.SANCTUARY_WEBHOOK_SECRET;
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT) {
    config.webhook.callback_port = parseInt(process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT, 10);
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST) {
    config.webhook.callback_host = process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST;
  }
  if (process.env.SANCTUARY_VERASCORE_URL) {
    config.verascore.url = process.env.SANCTUARY_VERASCORE_URL;
  }
  if (process.env.SANCTUARY_AUTO_PUBLISH_TO_VERASCORE === "true") {
    config.verascore.auto_publish_to_verascore = true;
  }
  if (process.env.SANCTUARY_AUTO_PUBLISH_TO_VERASCORE === "false") {
    config.verascore.auto_publish_to_verascore = false;
  }
  if (process.env.SANCTUARY_AUTO_PUBLISH_HANDSHAKES === "true") {
    config.verascore.auto_publish_handshakes = true;
  }
  if (process.env.SANCTUARY_AUTO_PUBLISH_HANDSHAKES === "false") {
    config.verascore.auto_publish_handshakes = false;
  }
  if (process.env.SANCTUARY_ERC8004_REGISTRY_CONFIRMATION_ENABLED === "true") {
    config.erc8004.registry_confirmation.enabled = true;
  }
  if (process.env.SANCTUARY_ERC8004_REGISTRY_CONFIRMATION_ENABLED === "false") {
    config.erc8004.registry_confirmation.enabled = false;
  }
  if (process.env.SANCTUARY_ERC8004_RPC_URL) {
    config.erc8004.registry_confirmation.rpc_url =
      process.env.SANCTUARY_ERC8004_RPC_URL;
  }
  if (process.env.SANCTUARY_ERC8004_CHAIN_ID) {
    config.erc8004.registry_confirmation.chain_id = strictParseIntEnv(
      process.env.SANCTUARY_ERC8004_CHAIN_ID,
    );
  }
  if (process.env.SANCTUARY_ERC8004_RPC_TIMEOUT_MS) {
    config.erc8004.registry_confirmation.timeout_ms = strictParseIntEnv(
      process.env.SANCTUARY_ERC8004_RPC_TIMEOUT_MS,
    );
  }
  if (process.env.SANCTUARY_PRIVACY_FILTER) {
    config.privacy_filter.mode = process.env.SANCTUARY_PRIVACY_FILTER as "local" | "opf" | "off";
  }
  if (process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE) {
    config.privacy_filter.fail_mode =
      process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE as "closed" | "fallback";
  }
  if (process.env.SANCTUARY_PRIVACY_FILTER_COMMAND) {
    config.privacy_filter.command = process.env.SANCTUARY_PRIVACY_FILTER_COMMAND;
  }
  if (process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS) {
    config.privacy_filter.timeout_ms = parseInt(
      process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS,
      10
    );
  }

  // Phase 3: Always stamp the running version from package.json (Bug 2 fix —
  // sanctuary.json may store a stale version from first run)
  config.version = PKG_VERSION;

  validateConfig(config);
  return config;
}

function isErrno(err: unknown, code: string): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === code
  );
}

function isConfigSchemaError(err: unknown): boolean {
  return (
    err instanceof Error &&
    (
      err.message.includes(CONFIG_FEATURE_ERROR_PREFIX) ||
      err.message.startsWith("Sanctuary config field")
    )
  );
}

/**
 * True when validateConfig rejected ONLY scalar-value typos (out-of-range or
 * non-integer dashboard.port, sub-floor privacy_filter.timeout_ms) on an
 * otherwise structurally-valid, well-typed config file. The file-load path
 * uses this to fail closed WITHOUT quarantining: a value typo is not
 * corruption and the operator's file must not be moved away.
 */
function isConfigValueError(err: unknown): boolean {
  return err instanceof Error && err.message.startsWith(CONFIG_VALUE_ERROR_PREFIX);
}

async function quarantineConfigFile(path: string): Promise<string | undefined> {
  const quarantinedPath = `${path}.corrupted.${new Date().toISOString()}`;
  try {
    await rename(path, quarantinedPath);
    return quarantinedPath;
  } catch {
    // Best-effort. A concurrent reader may have already quarantined or removed
    // the file, or the rename may be denied. Either way the config is
    // unavailable/corrupt from our perspective, so the caller still surfaces a
    // typed ConfigLoadError (just without a quarantine pointer). Never let a
    // raw fs error escape the corruption path.
    return undefined;
  }
}

/**
 * Save configuration to file.
 *
 * Writes atomically: serialize to a temp file in the same directory (so the
 * rename stays on one filesystem), then rename into place. POSIX rename is
 * atomic, so a concurrent loadConfig reader always observes either the old
 * complete file or the new complete file, never a truncated/empty/partial
 * state. This is the root-cause fix for the config-load race that surfaced as
 * "SyntaxError: Unexpected end of JSON input" under parallel test runs; the
 * empty-read tolerance in loadConfig is the defense-in-depth half.
 *
 * Hermeticity: this is the WRITE chokepoint for the config file, so it is
 * where the test-isolation guard belongs. `defaultConfig()` composes
 * `<home>/.sanctuary` with the raw join on purpose (it is only building a
 * default, and hundreds of already-isolated tests would trip a guard there),
 * but that unguarded value reached this function through `index.ts` step 20
 * and rewrote the operator's real `~/.sanctuary/sanctuary.json` on every suite
 * run. Guarding the construction is wrong; guarding the moment the value is
 * spent on a real write is right. Under Vitest a write into the operator's own
 * fortress now throws `NonHermeticStoragePathError`, whose message names
 * `createTempFortress()` as the fix. Production is untouched: the guard is
 * inert unless `VITEST` is set.
 */
export async function saveConfig(
  config: SanctuaryConfig,
  configPath?: string
): Promise<void> {
  const path =
    configPath ?? join(config.storage_path, "sanctuary.json");
  assertHermeticStoragePath(dirname(path));
  const tmpPath = `${path}.tmp.${process.pid}.${randomBytes(6).toString("hex")}`;
  try {
    // Create the temp file 0o600 from the start so the secret-bearing config
    // is never briefly world-readable.
    await writeFile(tmpPath, JSON.stringify(config, null, 2), { mode: 0o600 });
    await rename(tmpPath, path);
  } catch (err) {
    // Never leave a partial temp file behind, on a write OR a rename failure
    // (e.g. ENOSPC mid-write). Cleanup is itself best-effort.
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

/**
 * Validate that config does not reference unimplemented features and that its
 * scalar values are in range.
 *
 * Two distinct failure kinds are tracked so the file-load path can react
 * appropriately:
 *
 *  - `featureErrors`: the config references a feature this build cannot honor
 *    (e.g. an unimplemented proof_system or key_protection) or has a malformed
 *    shape. This is a genuine schema mismatch; the loader QUARANTINES the file.
 *  - `valueErrors`: a structurally-valid, well-typed config whose only problem
 *    is an out-of-range / non-integer scalar VALUE (e.g. dashboard.port = 70000
 *    or a sub-floor privacy_filter.timeout_ms). This is a recoverable input
 *    typo, so the loader fails CLOSED (refuses to start) but does NOT
 *    quarantine; the operator fixes the value in their file in place.
 *
 * The REFUSAL is unconditional for both kinds (fail-closed); only the
 * destructive quarantine side effect is suppressed for pure value typos.
 *
 * This prevents silent security degradation (SEC-019).
 */
export function validateConfig(config: SanctuaryConfig): void {
  const featureErrors: string[] = [];
  const valueErrors: string[] = [];
  // Back-compat alias: existing checks below push schema/feature problems into
  // `errors`. Pure scalar-range checks push into `valueErrors` explicitly.
  const errors = featureErrors;

  // Implemented key_protection values: "passphrase", "none"
  // Unimplemented: "hardware-key" (planned for future FIDO2/WebAuthn support)
  const implementedKeyProtection = new Set(["passphrase", "none"]);
  if (!implementedKeyProtection.has(config.state.key_protection)) {
    errors.push(
      `Unimplemented config value: state.key_protection = "${config.state.key_protection}". ` +
      `Only ${[...implementedKeyProtection].map(v => `"${v}"`).join(", ")} are currently implemented. ` +
      `Using an unimplemented key protection mode would silently degrade security.`
    );
  }

  // Implemented environment values: "local-process", "docker"
  // Unimplemented: "tee" (TEE-backed execution attestation not yet integrated)
  const implementedEnvironment = new Set(["local-process", "docker"]);
  if (!implementedEnvironment.has(config.execution.environment)) {
    errors.push(
      `Unimplemented config value: execution.environment = "${config.execution.environment}". ` +
      `Only ${[...implementedEnvironment].map(v => `"${v}"`).join(", ")} are currently implemented. ` +
      `Using an unimplemented environment would silently degrade security.`
    );
  }

  // Implemented proof_system values: "schnorr-pedersen" (Schnorr proofs + Pedersen commitments + range proofs — genuine ZK)
  // Also accepts "commitment-only" (legacy alias, equivalent to schnorr-pedersen)
  // Unimplemented: "groth16", "plonk" (SNARK proof systems not yet available)
  const implementedProofSystem = new Set(["schnorr-pedersen", "commitment-only"]);
  if (!implementedProofSystem.has(config.disclosure.proof_system)) {
    errors.push(
      `Unimplemented config value: disclosure.proof_system = "${config.disclosure.proof_system}". ` +
      `Only ${[...implementedProofSystem].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented proof system would silently degrade security.`
    );
  }

  // Implemented disclosure.default_policy values: "minimum-necessary"
  // Unimplemented: "withhold-all" (global withhold policy not yet implemented)
  const implementedDisclosurePolicy = new Set(["minimum-necessary"]);
  if (!implementedDisclosurePolicy.has(config.disclosure.default_policy)) {
    errors.push(
      `Unimplemented config value: disclosure.default_policy = "${config.disclosure.default_policy}". ` +
      `Only ${[...implementedDisclosurePolicy].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented disclosure policy would silently skip disclosure controls.`
    );
  }

  // Implemented reputation.mode values: "self-custodied"
  // Unimplemented: "service-mediated" (third-party reputation service not yet integrated)
  const implementedReputationMode = new Set(["self-custodied"]);
  if (!implementedReputationMode.has(config.reputation.mode)) {
    errors.push(
      `Unimplemented config value: reputation.mode = "${config.reputation.mode}". ` +
      `Only ${[...implementedReputationMode].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented reputation mode would silently skip reputation verification.`
    );
  }

  const implementedPrivacyModes = new Set(["local", "opf", "off"]);
  if (!implementedPrivacyModes.has(config.privacy_filter.mode)) {
    errors.push(
      `Invalid config value: privacy_filter.mode = "${config.privacy_filter.mode}". ` +
      `Use ${[...implementedPrivacyModes].map(v => `"${v}"`).join(", ")}.`
    );
  }

  const implementedPrivacyFailModes = new Set(["closed", "fallback"]);
  if (!implementedPrivacyFailModes.has(config.privacy_filter.fail_mode)) {
    errors.push(
      `Invalid config value: privacy_filter.fail_mode = "${config.privacy_filter.fail_mode}". ` +
      `Use ${[...implementedPrivacyFailModes].map(v => `"${v}"`).join(", ")}.`
    );
  }

  if (!Number.isFinite(config.privacy_filter.timeout_ms) || config.privacy_filter.timeout_ms < 100) {
    // Pure scalar-range typo on a structurally-valid file: refuse, do not quarantine.
    valueErrors.push(
      `Invalid config value: privacy_filter.timeout_ms = "${config.privacy_filter.timeout_ms}". ` +
      `Use an integer timeout of at least 100 ms.`
    );
  }

  // dashboard.port must be a valid TCP port (integer in 1..65535). The env
  // override (SANCTUARY_DASHBOARD_PORT) is read with a strict whole-string
  // parse that yields NaN for a value like "80abc" (instead of the old lenient
  // parseInt that truncated it to 80), and a config-FILE value can be any
  // number; either way an out-of-range or non-integer port would otherwise bind
  // the server to a truncated/out-of-spec port. Refusing an invalid port here
  // (rather than binding it) is an independent fail-closed hardening of the
  // dashboard port. Fails CLOSED.
  //
  // Forward note (not yet true in-tree): the deferred native macOS embed/badge
  // resolver is intended to parse the SAME env var strictly (Int + a 1...65535
  // guard, fallback 3501) so that once it ships, the value the server binds is
  // always one the resolver accepts and the two stay on a single source. Today
  // the native bridge (`SanctuaryServerBridge`) hardcodes 3501 and never reads
  // SANCTUARY_DASHBOARD_PORT, so a VALID non-default port (e.g. 8443) binds the
  // server while every native read still targets 3501, single-source port
  // parity does NOT hold yet. This validation only closes the invalid-port hole.
  if (
    !Number.isInteger(config.dashboard.port) ||
    config.dashboard.port < 1 ||
    config.dashboard.port > 65535
  ) {
    // Pure scalar-range typo on a structurally-valid file: refuse to start, but
    // do NOT quarantine. A port typo is not config corruption; moving the
    // operator's file out from under them is the defect this routing fixes.
    valueErrors.push(
      `Invalid config value: dashboard.port = "${config.dashboard.port}". ` +
      `Use an integer TCP port in the range 1-65535.`
    );
  }

  if (
    config.dashboard.allow_plaintext_remote !== undefined &&
    typeof config.dashboard.allow_plaintext_remote !== "boolean"
  ) {
    valueErrors.push(
      `Invalid config value: dashboard.allow_plaintext_remote = "${String(config.dashboard.allow_plaintext_remote)}". ` +
      `Use true only when a separate network layer already encrypts the transport.`
    );
  }

  if (
    typeof config.erc8004.registry_confirmation.enabled !== "boolean"
  ) {
    valueErrors.push(
      `Invalid config value: erc8004.registry_confirmation.enabled = "${String(config.erc8004.registry_confirmation.enabled)}". ` +
      `Use true or false.`
    );
  }

  if (typeof config.erc8004.registry_confirmation.rpc_url !== "string") {
    valueErrors.push(
      `Invalid config value: erc8004.registry_confirmation.rpc_url must be a string ` +
      `(an http(s) JSON-RPC endpoint URL or an empty string). Value redacted (it may embed a provider API key).`
    );
  } else if (config.erc8004.registry_confirmation.rpc_url !== "") {
    try {
      const parsed = new URL(config.erc8004.registry_confirmation.rpc_url);
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        valueErrors.push(
          `Invalid config value: erc8004.registry_confirmation.rpc_url must use the http(s) scheme ` +
          `(value redacted; it may embed a provider API key).`
        );
      }
    } catch {
      valueErrors.push(
        `Invalid config value: erc8004.registry_confirmation.rpc_url is not a valid URL ` +
        `(value redacted; it may embed a provider API key). Use an http(s) JSON-RPC endpoint URL.`
      );
    }
  }

  if (
    !Number.isInteger(config.erc8004.registry_confirmation.chain_id) ||
    config.erc8004.registry_confirmation.chain_id < 1
  ) {
    valueErrors.push(
      `Invalid config value: erc8004.registry_confirmation.chain_id = "${config.erc8004.registry_confirmation.chain_id}". ` +
      `Use a positive integer chain id.`
    );
  }

  if (
    !Number.isInteger(config.erc8004.registry_confirmation.timeout_ms) ||
    config.erc8004.registry_confirmation.timeout_ms < 100
  ) {
    valueErrors.push(
      `Invalid config value: erc8004.registry_confirmation.timeout_ms = "${config.erc8004.registry_confirmation.timeout_ms}". ` +
      `Use an integer timeout of at least 100 ms.`
    );
  }

  // Feature/schema errors take precedence: a config that references an
  // unimplemented feature (or has a malformed shape) is a genuine schema
  // mismatch and the loader quarantines it. A value typo alongside a feature
  // error is reported together under the feature message (the file is going to
  // be quarantined regardless).
  if (featureErrors.length > 0) {
    throw new Error(
      `${CONFIG_FEATURE_ERROR_PREFIX}:\n${[...featureErrors, ...valueErrors].join("\n")}`
    );
  }

  // Only scalar-value typos: fail closed (refuse to start) WITHOUT quarantine.
  if (valueErrors.length > 0) {
    throw new Error(
      `${CONFIG_VALUE_ERROR_PREFIX}:\n${valueErrors.join("\n")}`
    );
  }
}

/** Deep merge two objects (target takes precedence) */
function deepMerge(base: object, override: object): SanctuaryConfig {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof result[key] === "object" &&
      result[key] !== null
    ) {
      result[key] = deepMerge(
        result[key] as object,
        value as object
      );
    } else {
      result[key] = value;
    }
  }
  return result as unknown as SanctuaryConfig;
}

/**
 * Lightweight structural shape check before downstream consumers treat the
 * loaded config as a SanctuaryConfig. Catches the case where a user's
 * config file overrides a load-bearing object key with a primitive (e.g.
 * `dashboard: "broken"`) - without this, the cast in deepMerge would
 * silently produce a malformed config that crashes downstream consumers
 * in surprising ways.
 *
 * Not a full validator - that's the existing `validateConfig` step. This
 * only asserts top-level required keys exist with the right kind (object
 * vs string vs number vs boolean). Called once on the merged config in
 * loadConfig (NOT recursively from deepMerge).
 */
export function assertSanctuaryConfigShape(c: Record<string, unknown>): void {
  const requiredObjectKeys = [
    "state",
    "execution",
    "disclosure",
    "reputation",
    "dashboard",
    "webhook",
    "verascore",
    "erc8004",
    "privacy_filter",
  ];
  for (const k of requiredObjectKeys) {
    if (typeof c[k] !== "object" || c[k] === null || Array.isArray(c[k])) {
      throw new Error(
        `Sanctuary config field "${k}" must be an object; got ${
          c[k] === null ? "null" : Array.isArray(c[k]) ? "array" : typeof c[k]
        }`
      );
    }
  }
  const erc8004 = c.erc8004 as Record<string, unknown>;
  if (
    typeof erc8004.registry_confirmation !== "object" ||
    erc8004.registry_confirmation === null ||
    Array.isArray(erc8004.registry_confirmation)
  ) {
    throw new Error(
      `Sanctuary config field "erc8004.registry_confirmation" must be an object; got ${
        erc8004.registry_confirmation === null
          ? "null"
          : Array.isArray(erc8004.registry_confirmation)
            ? "array"
            : typeof erc8004.registry_confirmation
      }`
    );
  }
  if (typeof c.version !== "string") {
    throw new Error(`Sanctuary config field "version" must be a string`);
  }
  if (typeof c.storage_path !== "string") {
    throw new Error(`Sanctuary config field "storage_path" must be a string`);
  }
  if (c.transport !== "stdio" && c.transport !== "http") {
    throw new Error(
      `Sanctuary config field "transport" must be "stdio" | "http"; got ${JSON.stringify(c.transport)}`
    );
  }
  if (typeof c.http_port !== "number" || !Number.isFinite(c.http_port)) {
    throw new Error(`Sanctuary config field "http_port" must be a finite number`);
  }
}

// ─── Config security-downgrade comparator ────────────────────────────────────
//
// These helpers detect whether one config posture is a SECURITY DOWNGRADE of
// another. They are pure (no key, no I/O) and shared by the authenticated
// boot-time baseline gate in `core/config-baseline.ts`. The comparator logic is
// the sound half of the original (#791) downgrade gate; the FORGEABLE anchor it
// shipped with (a plaintext adjacent `.security-baseline.json`) has been
// discarded and replaced by a master-key-keyed MAC.

/** Throw `ConfigDowngradeError` if `next` weakens any security posture vs `previous`. */
export function assertNoConfigDowngrade(
  previous: SanctuaryConfig,
  next: SanctuaryConfig
): void {
  const downgrades = detectConfigDowngrades(previous, next);
  if (downgrades.length > 0) {
    throw new ConfigDowngradeError(downgrades);
  }
}

/** Enumerate every security-relevant field where `next` is weaker than `previous`. */
export function detectConfigDowngrades(
  previous: SanctuaryConfig,
  next: SanctuaryConfig
): ConfigDowngrade[] {
  const downgrades: ConfigDowngrade[] = [];
  const previousVersion = parseVersion(previous.version);
  const nextVersion = parseVersion(next.version);
  if (!previousVersion || !nextVersion) {
    downgrades.push({
      field: "version",
      reason: "config_version_invalid",
      previous: previous.version,
      next: next.version,
    });
  } else if (compareParsedVersions(nextVersion, previousVersion) < 0) {
    downgrades.push({
      field: "version",
      reason: "config_version_rollback",
      previous: previous.version,
      next: next.version,
    });
  }

  const previousKeyProtection = keyProtectionRank(previous.state.key_protection);
  const nextKeyProtection = keyProtectionRank(next.state.key_protection);
  if (nextKeyProtection < previousKeyProtection) {
    downgrades.push({
      field: "state.key_protection",
      reason: "state_key_protection_downgrade",
      previous: previous.state.key_protection,
      next: next.state.key_protection,
    });
  }

  if (previous.execution.attestation && !next.execution.attestation) {
    downgrades.push({
      field: "execution.attestation",
      reason: "execution_attestation_disabled",
      previous: previous.execution.attestation,
      next: next.execution.attestation,
    });
  }

  if (hasDashboardTls(previous) && !hasDashboardTls(next)) {
    downgrades.push({
      field: "dashboard.tls",
      reason: "dashboard_tls_disabled",
      previous: previous.dashboard.tls,
      next: next.dashboard.tls ?? null,
    });
  }

  if (
    previous.dashboard.allow_plaintext_remote !== true &&
    next.dashboard.allow_plaintext_remote === true
  ) {
    downgrades.push({
      field: "dashboard.allow_plaintext_remote",
      reason: "dashboard_plaintext_remote_enabled",
      previous: previous.dashboard.allow_plaintext_remote ?? false,
      next: next.dashboard.allow_plaintext_remote,
    });
  }

  if (hasDashboardAuth(previous) && !hasDashboardAuth(next)) {
    downgrades.push({
      field: "dashboard.auth_token",
      reason: "dashboard_auth_disabled",
      previous: redactConfiguredSecret(previous.dashboard.auth_token),
      next: redactConfiguredSecret(next.dashboard.auth_token),
    });
  }

  if (previous.webhook.enabled && !next.webhook.enabled) {
    downgrades.push({
      field: "webhook.enabled",
      reason: "webhook_gate_disabled",
      previous: previous.webhook.enabled,
      next: next.webhook.enabled,
    });
  }

  if (previous.privacy_filter.mode !== "off" && next.privacy_filter.mode === "off") {
    downgrades.push({
      field: "privacy_filter.mode",
      reason: "privacy_filter_disabled",
      previous: previous.privacy_filter.mode,
      next: next.privacy_filter.mode,
    });
  }

  if (
    previous.privacy_filter.fail_mode === "closed" &&
    next.privacy_filter.fail_mode === "fallback"
  ) {
    downgrades.push({
      field: "privacy_filter.fail_mode",
      reason: "privacy_fail_mode_downgrade",
      previous: previous.privacy_filter.fail_mode,
      next: next.privacy_filter.fail_mode,
    });
  }

  // Privacy-filter command repoint while filtering is active. If the previous
  // mode was a filtering mode (not "off") and the command path changed, the
  // operator's filter may have been silently swapped for a no-op binary while
  // `mode` still reads as filtering (a covert disable the mode check misses).
  // We treat ANY change to the command while the previous mode was filtering as
  // a potential downgrade. The command path is not a secret (it is an
  // executable name/path, never a credential), so it is safe to record.
  if (
    previous.privacy_filter.mode !== "off" &&
    previous.privacy_filter.command !== next.privacy_filter.command
  ) {
    downgrades.push({
      field: "privacy_filter.command",
      reason: "privacy_filter_command_changed",
      previous: previous.privacy_filter.command,
      next: next.privacy_filter.command,
    });
  }

  // Disclosure default policy loosening. `withhold-all` is strictly stronger
  // than `minimum-necessary`; dropping from a stronger to a weaker default
  // discloses more by default. Flag any loosening (rank decrease).
  if (
    disclosureDefaultPolicyRank(next.disclosure.default_policy) <
    disclosureDefaultPolicyRank(previous.disclosure.default_policy)
  ) {
    downgrades.push({
      field: "disclosure.default_policy",
      reason: "disclosure_default_policy_loosened",
      previous: previous.disclosure.default_policy,
      next: next.disclosure.default_policy,
    });
  }

  // Verascore auto-publish enablement increases external egress of
  // reputation/handshake data. Either flag flipping false -> true is a
  // downgrade (more data leaves the host by default).
  if (
    !verascoreAutoPublishEnabled(previous) &&
    verascoreAutoPublishEnabled(next)
  ) {
    downgrades.push({
      field: "verascore.auto_publish",
      reason: "verascore_autopublish_enabled",
      previous: verascoreAutoPublishEnabled(previous),
      next: verascoreAutoPublishEnabled(next),
    });
  }

  // ERC-8004 registry confirmation enablement opens an external JSON-RPC
  // egress path that is default-off; flipping it on is a posture-weakening
  // increase in external network reach.
  if (
    !previous.erc8004.registry_confirmation.enabled &&
    next.erc8004.registry_confirmation.enabled
  ) {
    downgrades.push({
      field: "erc8004.registry_confirmation.enabled",
      reason: "erc8004_confirmation_enabled",
      previous: previous.erc8004.registry_confirmation.enabled,
      next: next.erc8004.registry_confirmation.enabled,
    });
  }

  return downgrades;
}

/** Project a full config to the security-relevant posture stored in the baseline. */
export function securityPostureFromConfig(
  config: SanctuaryConfig
): ConfigSecurityPosture {
  return {
    config_version: config.version,
    state_key_protection: config.state.key_protection,
    execution_attestation: config.execution.attestation,
    dashboard_tls_configured: hasDashboardTls(config),
    dashboard_auth_configured: hasDashboardAuth(config),
    dashboard_allow_plaintext_remote:
      config.dashboard?.allow_plaintext_remote === true,
    webhook_enabled: config.webhook.enabled,
    privacy_filter_mode: config.privacy_filter.mode,
    privacy_filter_fail_mode: config.privacy_filter.fail_mode,
    privacy_filter_command: config.privacy_filter.command,
    disclosure_default_policy: config.disclosure.default_policy,
    verascore_auto_publish: verascoreAutoPublishEnabled(config),
    erc8004_confirmation_enabled: config.erc8004.registry_confirmation.enabled,
  };
}

/**
 * Reconstruct a comparison config from a stored posture. The result is NOT a
 * usable runtime config (only the security-relevant fields are meaningful); it
 * exists purely so `detectConfigDowngrades` can compare the persisted posture
 * against the running config with the same logic used for live saves.
 */
export function configFromSecurityPosture(
  posture: ConfigSecurityPosture
): SanctuaryConfig {
  const config = defaultConfig();
  config.version = posture.config_version;
  config.state.key_protection = posture.state_key_protection;
  config.execution.attestation = posture.execution_attestation;
  config.dashboard = {
    ...config.dashboard,
    allow_plaintext_remote: posture.dashboard_allow_plaintext_remote,
    ...(posture.dashboard_auth_configured ? { auth_token: "configured" } : {}),
    ...(posture.dashboard_tls_configured
      ? { tls: { cert_path: "configured", key_path: "configured" } }
      : {}),
  };
  config.webhook.enabled = posture.webhook_enabled;
  config.privacy_filter.mode = posture.privacy_filter_mode;
  config.privacy_filter.fail_mode = posture.privacy_filter_fail_mode;
  config.privacy_filter.command = posture.privacy_filter_command;
  config.disclosure.default_policy = posture.disclosure_default_policy;
  // `verascore_auto_publish` is the OR of the two auto-publish flags. Project
  // it back onto `auto_publish_to_verascore` (handshakes left false); the OR
  // reconstructs the same posture value the comparator compares against.
  config.verascore.auto_publish_to_verascore = posture.verascore_auto_publish;
  config.verascore.auto_publish_handshakes = false;
  config.erc8004.registry_confirmation.enabled =
    posture.erc8004_confirmation_enabled;
  return config;
}

/** Type guard: a valid `state.key_protection` enum value. */
export function isKeyProtectionValue(
  value: unknown
): value is SanctuaryConfig["state"]["key_protection"] {
  return value === "none" || value === "passphrase" || value === "hardware-key";
}

/** Type guard: a valid `privacy_filter.mode` enum value. */
export function isPrivacyFilterMode(
  value: unknown
): value is SanctuaryConfig["privacy_filter"]["mode"] {
  return value === "local" || value === "opf" || value === "off";
}

/** Type guard: a valid `privacy_filter.fail_mode` enum value. */
export function isPrivacyFailMode(
  value: unknown
): value is SanctuaryConfig["privacy_filter"]["fail_mode"] {
  return value === "closed" || value === "fallback";
}

function hasDashboardTls(config: SanctuaryConfig): boolean {
  const tls = config.dashboard.tls;
  return (
    typeof tls?.cert_path === "string" &&
    tls.cert_path.trim().length > 0 &&
    typeof tls.key_path === "string" &&
    tls.key_path.trim().length > 0
  );
}

function hasDashboardAuth(config: SanctuaryConfig): boolean {
  const token = config.dashboard.auth_token;
  return typeof token === "string" && token.trim().length > 0;
}

/** Reduce a secret-bearing field to a presence marker, never echoing the value. */
function redactConfiguredSecret(value: string | undefined): string | null {
  if (typeof value !== "string" || value.trim().length === 0) return null;
  return "configured";
}

function keyProtectionRank(
  value: SanctuaryConfig["state"]["key_protection"]
): number {
  switch (value) {
    case "none":
      return 0;
    case "passphrase":
      return 1;
    case "hardware-key":
      return 2;
  }
}

/**
 * Strength ordering for `disclosure.default_policy`. Higher rank = stronger
 * (discloses less by default). `withhold-all` is the strongest; dropping to a
 * lower rank is a loosening the comparator gates.
 */
function disclosureDefaultPolicyRank(
  value: SanctuaryConfig["disclosure"]["default_policy"]
): number {
  switch (value) {
    case "minimum-necessary":
      return 0;
    case "withhold-all":
      return 1;
  }
}

/** True when either Verascore auto-publish flag is on (external egress of attestations). */
function verascoreAutoPublishEnabled(config: SanctuaryConfig): boolean {
  return (
    config.verascore.auto_publish_to_verascore === true ||
    config.verascore.auto_publish_handshakes === true
  );
}

type ParsedVersion = readonly [number, number, number];

function parseVersion(version: string): ParsedVersion | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$/.exec(version);
  if (!match) return null;
  return [
    Number.parseInt(match[1]!, 10),
    Number.parseInt(match[2]!, 10),
    Number.parseInt(match[3]!, 10),
  ];
}

function compareParsedVersions(
  left: ParsedVersion,
  right: ParsedVersion
): number {
  for (let i = 0; i < 3; i += 1) {
    const delta = left[i]! - right[i]!;
    if (delta !== 0) return delta;
  }
  return 0;
}
