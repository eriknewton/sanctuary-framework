/**
 * Plugin substrate — verdict types + the composition combiner (design §3.3, §3.3a, §3.4;
 * RFC §4.2a, the single most important invariant-preserving rule).
 *
 * THE INVARIANT: adding a plugin must never loosen an outcome. A plugin can move an
 * outcome only toward deny/escalate, never toward permit. There is NO "allow" verdict in
 * the type, by construction. `intersectVerdicts` is the ONLY combiner, and its signature
 * takes only enforcement-relevant decisions — never confidence/signals/rationale — so
 * "enforcement never reads confidence" is true by TYPE, not by discipline (codex MEDIUM).
 *
 * `plugin_error` is host-minted (crash/timeout/malformed/desync) and never vendor-supplied
 * (codex BLOCKING): a plugin cannot avoid objection by failing.
 */

import { reject } from "./errors.js";
import { parseStrictJson } from "./strict-json.js";

/** What a plugin may emit on the wire. No "allow"; no "plugin_error". */
export type PluginDecision = "deny" | "escalate" | "observe" | "no_objection";

/** The enforcement-relevant decision space the host works with (adds host-minted plugin_error). */
export type EnforcementDecision = PluginDecision | "plugin_error";

/** The host's own independent decision at a hook. It owns "permit" — plugins never do. */
export type HostDecision = "permit" | "escalate" | "deny";

export const PLUGIN_DECISIONS: readonly PluginDecision[] = [
  "deny",
  "escalate",
  "observe",
  "no_objection",
] as const;

/**
 * A verdict as parsed off the wire. Validated against this exact closed shape with no
 * extra keys (codex HIGH: a verdict that validates differently than interpreted is a
 * permit-bypass). `confidence`, `signals`, `rationale` are ATTRIBUTION-only and flow to
 * the telemetry sink, never to the combiner (§3.3b: both are tainted).
 */
export interface PluginVerdict {
  decision: PluginDecision;
  request_id: string;
  nonce: string;
  rationale: string;
  confidence?: number;
  signals?: Record<string, number | string | boolean>;
}

/**
 * Enforcement strictness lattice (design §3.4). Higher = stricter = closer to deny.
 * `plugin_error` slots above escalate (it is at least escalate, and = deny for
 * enforcement hooks via the hook fail-closed table, applied by the caller before
 * intersect). observe/no_objection are non-permitting telemetry levels.
 *
 *   deny (4) > plugin_error (3) > escalate (2) > observe (1) > no_objection (0)
 */
const ENFORCEMENT_RANK: Record<EnforcementDecision, number> = {
  no_objection: 0,
  observe: 1,
  escalate: 2,
  plugin_error: 3,
  deny: 4,
};

/** Map a host decision to a comparable rank on the same lattice. permit is the floor. */
const HOST_RANK: Record<HostDecision, number> = {
  permit: 0, // host permit competes at the bottom — any plugin objection (≥escalate) overrides toward strict
  escalate: 2,
  deny: 4,
};

/** The composed outcome of a hook evaluation. permit is reachable ONLY from a host permit. */
export type ComposedOutcome = "permit" | "observe" | "escalate" | "plugin_error" | "deny";

/**
 * Compose the host's decision with the plugin decisions for one hook.
 *
 * STRICTEST-WINS, monotone by construction:
 * - The result is the strictest (highest-rank) of {host, ...plugins}.
 * - Because permit ranks at the floor (0) alongside no_objection, a host `permit` survives
 *   only when EVERY plugin decision is no_objection (rank 0). The moment any plugin returns
 *   observe/escalate/plugin_error/deny, the outcome moves strictly toward deny — never the
 *   reverse. There is no input by which a plugin can lower the outcome below the host's.
 * - deny is absorbing.
 *
 * Properties (proven in verdict.property.test.ts): pure, commutative, associative,
 * idempotent; adding a decision never reduces strictness; no added decision moves the
 * outcome toward permit.
 *
 * The signature accepts ONLY decisions — never PluginVerdict — so confidence can never
 * reach enforcement (codex MEDIUM, structural).
 */
export function intersectVerdicts(
  hostDecision: HostDecision,
  decisions: readonly EnforcementDecision[],
): ComposedOutcome {
  let maxRank = HOST_RANK[hostDecision];
  let outcome: ComposedOutcome = hostDecision === "permit" ? "permit" : hostDecision;

  for (const d of decisions) {
    const r = ENFORCEMENT_RANK[d];
    if (r === undefined) {
      // Unknown decision is not coerced — it is a host-minted plugin_error upstream.
      // Defensive: treat as plugin_error rank here too, never as a permit.
      if (ENFORCEMENT_RANK.plugin_error > maxRank) {
        maxRank = ENFORCEMENT_RANK.plugin_error;
        outcome = "plugin_error";
      }
      continue;
    }
    if (r > maxRank) {
      maxRank = r;
      outcome = d as ComposedOutcome;
    }
  }

  return outcome;
}

/**
 * Parse a RAW wire verdict frame (the JSON text/bytes a plugin wrote to stdout) and
 * validate it. This is the entry point the supervisor (S4) MUST use — NOT `JSON.parse`
 * then `parsePluginVerdict` — because bare `JSON.parse` silently collapses duplicate keys
 * (a `{"decision":"deny","decision":"no_objection"}` permit-bypass, codex HIGH). The
 * strict parser rejects duplicate keys, prototype keys, non-finite numbers, over-deep
 * nesting, and trailing bytes with a named reason before shape validation runs.
 */
export function parseVerdictFrame(
  text: string,
  expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
): PluginVerdict {
  const raw = parseStrictJson(text);
  return parsePluginVerdict(raw, expected);
}

/**
 * Validate an ALREADY-PARSED wire object as a PluginVerdict against the closed shape,
 * binding it to the pending request's request_id + nonce. Any miss is a NAMED rejection
 * (the caller mints plugin_error). A vendor-supplied "allow" or "plugin_error" is
 * explicitly rejected.
 *
 * Prefer `parseVerdictFrame` for untrusted wire input — passing an object that already
 * went through bare `JSON.parse` loses the duplicate-key guarantee.
 */
export function parsePluginVerdict(
  raw: unknown,
  expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
): PluginVerdict {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    reject("verdict_unknown_decision", "verdict must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;

  const ALLOWED_KEYS = new Set([
    "decision",
    "request_id",
    "nonce",
    "rationale",
    "confidence",
    "signals",
  ]);
  for (const k of Object.keys(obj)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      reject("json_prototype_key", `verdict contains a prototype-pollution key "${k}"`);
    }
    if (!ALLOWED_KEYS.has(k)) {
      reject("verdict_unknown_key", `verdict has unknown key "${k}"`);
    }
  }

  const decision = obj.decision;
  if (decision === "allow" || decision === "permit") {
    reject("verdict_allow_not_permitted", 'a plugin may not return "allow"/"permit" — no such verdict exists');
  }
  if (decision === "plugin_error") {
    reject(
      "verdict_vendor_supplied_plugin_error",
      'a plugin may not return "plugin_error" — it is host-minted only',
    );
  }
  if (typeof decision !== "string" || !PLUGIN_DECISIONS.includes(decision as PluginDecision)) {
    reject("verdict_unknown_decision", `verdict decision "${String(decision)}" is not a valid plugin decision`);
  }

  if (obj.request_id !== expected.request_id) {
    reject("verdict_request_id_mismatch", "verdict request_id does not match the pending request");
  }
  if (obj.nonce !== expected.nonce) {
    reject("verdict_nonce_mismatch", "verdict nonce does not match the pending request");
  }

  if (typeof obj.rationale !== "string") {
    reject("verdict_unknown_decision", "verdict rationale must be a string");
  }
  if ((obj.rationale as string).length > MAX_RATIONALE_LEN) {
    reject("frame_too_large", `verdict rationale exceeds ${MAX_RATIONALE_LEN} chars`);
  }

  let confidence: number | undefined;
  if (obj.confidence !== undefined) {
    const c = obj.confidence;
    if (typeof c !== "number" || !Number.isFinite(c)) {
      reject("json_non_finite_number", "verdict confidence must be a finite number");
    }
    if (c < 0 || c > 1) {
      reject("invalid_field_value", "verdict confidence must be in [0,1]");
    }
    confidence = c;
  }

  let signals: Record<string, number | string | boolean> | undefined;
  if (obj.signals !== undefined) {
    if (obj.signals === null || typeof obj.signals !== "object" || Array.isArray(obj.signals)) {
      reject("invalid_field_value", "verdict signals must be an object");
    }
    const sig = obj.signals as Record<string, unknown>;
    const declared = new Set(expected.declaredSignalKeys);
    const out: Record<string, number | string | boolean> = {};
    for (const [k, v] of Object.entries(sig)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") {
        reject("json_prototype_key", `signals contains a prototype-pollution key "${k}"`);
      }
      if (!declared.has(k)) {
        reject("verdict_undeclared_signal_key", `signal key "${k}" was not declared in governance.yaml`);
      }
      if (typeof v === "number") {
        if (!Number.isFinite(v)) reject("json_non_finite_number", `signal "${k}" is non-finite`);
        out[k] = v;
      } else if (typeof v === "string") {
        if (v.length > MAX_SIGNAL_STRING_LEN) {
          reject("frame_too_large", `signal "${k}" string exceeds ${MAX_SIGNAL_STRING_LEN} chars`);
        }
        out[k] = v;
      } else if (typeof v === "boolean") {
        out[k] = v;
      } else {
        reject("invalid_field_value", `signal "${k}" must be number|string|boolean`);
      }
    }
    signals = out;
  }

  return {
    decision: decision as PluginDecision,
    request_id: expected.request_id,
    nonce: expected.nonce,
    rationale: obj.rationale as string,
    ...(confidence !== undefined ? { confidence } : {}),
    ...(signals !== undefined ? { signals } : {}),
  };
}

export const MAX_RATIONALE_LEN = 4096;
export const MAX_SIGNAL_STRING_LEN = 1024;
