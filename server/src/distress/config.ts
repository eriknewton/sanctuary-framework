/**
 * HABEAS PORT — distress lane configuration.
 *
 * One operator-owned file configures the distress lane for BOTH consumers:
 *   - the Castle Wall daemon (derives the reserved webhook allow-rule), and
 *   - the MCP server (delivers distress signals to the destination).
 *
 * Location: `<fortress>/policy/egress/distress.json` — alongside
 * agent-origin.json and operator-baseline.json, in the operator-owned policy
 * directory the agent cannot write. Loaded once at startup and frozen, like
 * the Principal Policy. The agent can neither read nor edit it through any
 * MCP surface.
 *
 * Shape (all fields optional; an absent file means local-only lane):
 *   {
 *     "webhook_url": "https://ops.example.com/distress",
 *     "webhook_secret": "<HMAC shared secret, required with webhook_url>",
 *     "max_signals_per_hour": 5
 *   }
 *
 * Fail-closed validation: a PRESENT but malformed file is an error (the
 * operator expressed intent we could not honor), never a silent fallback.
 * A missing file is the documented default: local notification + audit only.
 */

import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import {
  parseHabeasWebhookTarget,
  type HabeasWebhookTarget,
} from "../castle-wall/allowlist/habeas-port.js";

export const DISTRESS_CONFIG_FILENAME = "distress.json";

/** Default and bounds for the distress rate limit (signals per rolling hour). */
export const DISTRESS_DEFAULT_MAX_PER_HOUR = 5;
export const DISTRESS_MIN_MAX_PER_HOUR = 1;
export const DISTRESS_MAX_MAX_PER_HOUR = 60;

/** Validated distress lane configuration. */
export interface DistressConfig {
  /** Operator webhook destination; undefined = local-only lane. */
  webhook_url?: string;
  /** HMAC-SHA256 shared secret; always present when webhook_url is. */
  webhook_secret?: string;
  /** Rate limit; values outside [1, 60] are rejected at load. */
  max_signals_per_hour: number;
  /** Parsed webhook host:port for rule derivation (derived, not persisted). */
  webhook_target?: HabeasWebhookTarget;
}

/** Local-only default used when no config file exists. */
export function defaultDistressConfig(): DistressConfig {
  return { max_signals_per_hour: DISTRESS_DEFAULT_MAX_PER_HOUR };
}

export class DistressConfigError extends Error {
  constructor(message: string) {
    super(`distress.json invalid: ${message}`);
    this.name = "DistressConfigError";
  }
}

/**
 * Validate a parsed candidate. Throws DistressConfigError on any structural
 * problem — a malformed operator intent must never silently degrade to a
 * different lane shape (hard constraint #5).
 */
export function validateDistressConfig(raw: unknown): DistressConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new DistressConfigError("top level must be a JSON object");
  }
  const record = raw as Record<string, unknown>;
  const known = new Set(["webhook_url", "webhook_secret", "max_signals_per_hour"]);
  for (const key of Object.keys(record)) {
    if (!known.has(key)) {
      throw new DistressConfigError(`unknown key "${key}"`);
    }
  }

  let maxPerHour = DISTRESS_DEFAULT_MAX_PER_HOUR;
  if (record.max_signals_per_hour !== undefined) {
    // Out-of-range values are REJECTED, not clamped: silent clamping would
    // misrepresent operator intent (codex round-1 finding 6).
    if (
      typeof record.max_signals_per_hour !== "number" ||
      !Number.isInteger(record.max_signals_per_hour) ||
      record.max_signals_per_hour < DISTRESS_MIN_MAX_PER_HOUR ||
      record.max_signals_per_hour > DISTRESS_MAX_MAX_PER_HOUR
    ) {
      throw new DistressConfigError(
        `max_signals_per_hour must be an integer in [${DISTRESS_MIN_MAX_PER_HOUR}, ` +
          `${DISTRESS_MAX_MAX_PER_HOUR}]`,
      );
    }
    maxPerHour = record.max_signals_per_hour;
  }

  const config: DistressConfig = { max_signals_per_hour: maxPerHour };

  if (record.webhook_url !== undefined) {
    if (typeof record.webhook_url !== "string") {
      throw new DistressConfigError("webhook_url must be a string");
    }
    const target = parseHabeasWebhookTarget(record.webhook_url);
    if (target === null) {
      throw new DistressConfigError(
        "webhook_url must be a well-formed http(s) URL",
      );
    }
    const isLoopback =
      target.host === "127.0.0.1" || target.host === "::1" || target.host === "localhost";
    // Scheme check uses the PARSED protocol (URL lowercases it), so a
    // mixed-case "HTTP://" spelling cannot dodge the https requirement
    // (codex round-1 finding 5).
    if (new URL(record.webhook_url).protocol === "http:" && !isLoopback) {
      throw new DistressConfigError(
        "webhook_url must use https for non-loopback destinations",
      );
    }
    if (typeof record.webhook_secret !== "string" || record.webhook_secret.length < 16) {
      throw new DistressConfigError(
        "webhook_secret (>= 16 chars) is required when webhook_url is set; " +
          "distress payloads are always HMAC-signed",
      );
    }
    config.webhook_url = record.webhook_url;
    config.webhook_secret = record.webhook_secret;
    config.webhook_target = target;
  } else if (record.webhook_secret !== undefined) {
    throw new DistressConfigError("webhook_secret requires webhook_url");
  }

  return config;
}

/**
 * Read `<fortressPath>/policy/egress/distress.json`. Missing file → the
 * local-only default. Present-but-invalid file → throws (fail closed). A
 * file readable by non-owner is rejected when it carries a secret.
 */
export async function readDistressConfig(fortressPath: string): Promise<DistressConfig> {
  const filePath = join(fortressPath, "policy", "egress", DISTRESS_CONFIG_FILENAME);
  let rawText: string;
  try {
    rawText = await readFile(filePath, "utf8");
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return defaultDistressConfig();
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new DistressConfigError("file is not valid JSON");
  }
  const config = validateDistressConfig(parsed);
  if (config.webhook_secret !== undefined) {
    const fileStat = await stat(filePath);
    if ((fileStat.mode & 0o077) !== 0) {
      throw new DistressConfigError(
        "file carries webhook_secret but is readable by non-owner; chmod 600 it",
      );
    }
  }
  return config;
}
