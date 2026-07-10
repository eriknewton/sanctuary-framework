/**
 * Operator-owned enforcement-export configuration + fail-closed validation.
 *
 * SAFE BY DEFAULT: an absent config, or a config that names no sink, resolves to
 * the LOCAL sink (`file`), which never touches the network. Outbound push to a
 * Cortex/XSIAM HTTP collector is opt-in and requires ALL of:
 *   1. `sink: "http"` (explicit opt-in),
 *   2. `enabled: true` (a second explicit switch), and
 *   3. a well-formed, pinned `destination_url` (https, or loopback for tests),
 * and, at enable time, a Tier-1 operator approval (see `./exporter.ts`).
 *
 * FAIL CLOSED ON MALFORMED INTENT (AGENTS.md must-never #5): a present-but-invalid
 * config throws `EnforcementExportConfigError` rather than silently degrading to a
 * different (for example local) lane. Mirrors the distress-lane config posture in
 * `server/src/distress/config.ts`.
 *
 * This module is pure validation over an already-parsed object; it does no I/O
 * and never reads a real `~/.sanctuary` path, so it is trivially hermetic.
 */

/** Where mapped enforcement events are delivered. */
export type EnforcementExportSinkKind = "file" | "http";

/** The default, network-free sink used when nothing else is configured. */
export const DEFAULT_EXPORT_SINK: EnforcementExportSinkKind = "file";

/** Validated exporter configuration. */
export interface EnforcementExportConfig {
  /** Which sink to deliver through. `file` (default) never touches the network. */
  sink: EnforcementExportSinkKind;
  /**
   * Master opt-in for OUTBOUND push. Must be `true` for the `http` sink to be
   * usable. Meaningless (and must be absent/false) for the `file` sink.
   */
  enabled: boolean;
  /**
   * The single PINNED collector URL for the `http` sink. Required with
   * `sink: "http"`. https is required for non-loopback destinations; loopback
   * http is permitted so a local collector / test can be pinned. There is no
   * agent-chosen or per-batch destination: exactly this URL or nothing.
   */
  destination_url?: string;
  /**
   * Local file path for the `file` sink (NDJSON, append). When omitted the file
   * sink writes to the injected writer (stdout by default). Never a network path.
   */
  file_path?: string;
}

export class EnforcementExportConfigError extends Error {
  constructor(message: string) {
    super(`enforcement-export config invalid: ${message}`);
    this.name = "EnforcementExportConfigError";
  }
}

const KNOWN_KEYS = new Set(["sink", "enabled", "destination_url", "file_path"]);

/** The default, network-free config: local file sink, no outbound push. */
export function defaultExportConfig(): EnforcementExportConfig {
  return { sink: DEFAULT_EXPORT_SINK, enabled: false };
}

/** True iff `url` is a well-formed http(s) URL whose non-loopback form is https. */
function validatePinnedUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new EnforcementExportConfigError("destination_url must be a well-formed URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new EnforcementExportConfigError("destination_url must be http or https");
  }
  const host = parsed.hostname;
  const isLoopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
  // Parsed protocol is already lowercased by URL, so a mixed-case "HTTP://"
  // cannot dodge the https requirement.
  if (parsed.protocol === "http:" && !isLoopback) {
    throw new EnforcementExportConfigError(
      "destination_url must use https for non-loopback collectors",
    );
  }
}

/**
 * Validate an already-parsed candidate config. Throws on any structural problem
 * (fail closed). An absent/empty candidate returns the safe default.
 */
export function validateExportConfig(raw: unknown): EnforcementExportConfig {
  if (raw === undefined || raw === null) return defaultExportConfig();
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new EnforcementExportConfigError("top level must be a JSON object");
  }
  const record = raw as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new EnforcementExportConfigError(`unknown key "${key}"`);
    }
  }

  let sink: EnforcementExportSinkKind = DEFAULT_EXPORT_SINK;
  if (record.sink !== undefined) {
    if (record.sink !== "file" && record.sink !== "http") {
      throw new EnforcementExportConfigError('sink must be "file" or "http"');
    }
    sink = record.sink;
  }

  let enabled = false;
  if (record.enabled !== undefined) {
    if (typeof record.enabled !== "boolean") {
      throw new EnforcementExportConfigError("enabled must be a boolean");
    }
    enabled = record.enabled;
  }

  const config: EnforcementExportConfig = { sink, enabled };

  if (record.file_path !== undefined) {
    if (typeof record.file_path !== "string" || record.file_path.length === 0) {
      throw new EnforcementExportConfigError("file_path must be a non-empty string");
    }
    config.file_path = record.file_path;
  }

  if (sink === "http") {
    if (typeof record.destination_url !== "string" || record.destination_url.length === 0) {
      throw new EnforcementExportConfigError(
        'destination_url is required when sink is "http"',
      );
    }
    validatePinnedUrl(record.destination_url);
    config.destination_url = record.destination_url;
    // Note: `enabled` is validated but NOT forced true here. The exporter treats
    // `sink: "http"` + `enabled: false` as "configured but not armed" and
    // refuses outbound delivery (fail closed) rather than erroring at load.
  } else if (record.destination_url !== undefined) {
    // A destination_url with the file sink is a contradiction the operator
    // should resolve, not a value we silently ignore.
    throw new EnforcementExportConfigError(
      'destination_url is only valid with sink "http"',
    );
  }

  return config;
}
