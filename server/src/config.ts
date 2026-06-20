/**
 * Sanctuary MCP Server — Configuration
 *
 * Loads and validates server configuration from file or environment variables.
 */

import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { ConfigLoadError } from "./errors/config-error.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

/**
 * Strictly parse a whole-string integer from an env var.
 *
 * `parseInt("80abc", 10)` returns `80` — it stops at the first non-digit and
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
 * parity does NOT hold yet — a valid non-default port still diverges the two.
 *
 * Accepts an optional sign and ASCII digits only (e.g. "3501", "+8443"). Returns
 * `NaN` for "", "80abc", "0x10", "3501 5", or any value with trailing/embedded
 * non-digits, so the caller's validation rejects it.
 */
function strictParseIntEnv(raw: string): number {
  const trimmed = raw.trim();
  if (!/^[+-]?\d+$/.test(trimmed)) {
    return Number.NaN;
  }
  return Number.parseInt(trimmed, 10);
}

/** Package version, exported for use by other modules (avoids duplicate require paths). */
export const SANCTUARY_VERSION = PKG_VERSION;

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

  privacy_filter: {
    mode: "local" | "opf" | "off";
    fail_mode: "closed" | "fallback";
    command: string;
    timeout_ms: number;
  };
}

/** Default configuration */
export function defaultConfig(): SanctuaryConfig {
  return {
    version: PKG_VERSION,
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
      err.message.includes("Sanctuary configuration references unimplemented features") ||
      err.message.startsWith("Sanctuary config field")
    )
  );
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
 */
export async function saveConfig(
  config: SanctuaryConfig,
  configPath?: string
): Promise<void> {
  const path =
    configPath ?? join(config.storage_path, "sanctuary.json");
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
 * Validate that config does not reference unimplemented features.
 * Throws a descriptive error if any unimplemented value is found.
 * This prevents silent security degradation (SEC-019).
 */
export function validateConfig(config: SanctuaryConfig): void {
  const errors: string[] = [];

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
    errors.push(
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
  // server while every native read still targets 3501 — single-source port
  // parity does NOT hold yet. This validation only closes the invalid-port hole.
  if (
    !Number.isInteger(config.dashboard.port) ||
    config.dashboard.port < 1 ||
    config.dashboard.port > 65535
  ) {
    errors.push(
      `Invalid config value: dashboard.port = "${config.dashboard.port}". ` +
      `Use an integer TCP port in the range 1-65535.`
    );
  }

  if (errors.length > 0) {
    throw new Error(
      `Sanctuary configuration references unimplemented features:\n${errors.join("\n")}`
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
