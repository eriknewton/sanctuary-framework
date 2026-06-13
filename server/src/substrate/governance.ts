/**
 * Plugin substrate — governance.yaml schema + recursively-closed validator
 * (design §3.1; RFC §4.1, §4.1a, §8).
 *
 * governance.yaml is the entire declaration surface. The parser is the restricted-YAML
 * profile (restricted-yaml.ts); this module enforces a recursively-closed schema
 * (additionalProperties:false at EVERY object level — codex MEDIUM, round 1) and the
 * security rules the contract fixes:
 *   - unknown key anywhere (top-level OR nested) → reject install (never ignore)
 *   - declared fields must be in the host closed allowlist (fields.ts)
 *   - an enforcement hook may NOT declare a fail-open fail-mode (§3.1, codex BLOCKING)
 *   - every endpoint must declare a data class (RFC §5.3)
 *
 * The signed object (manifest.governance_hash) is sha256(canonical-JSON(this parse)).
 */

import { canonicalize } from "./canonical-json.js";
import { reject } from "./errors.js";
import { HookClass, validateArgumentSelectors, validateDeclaredFields } from "./fields.js";
import { parseRestrictedYaml, YamlValue } from "./restricted-yaml.js";
import { sha256Hex } from "./manifest.js";
import { validateBundlePath, validateId } from "./paths.js";

/** A fail-mode a plugin may declare per hook. */
export type FailMode = "deny" | "escalate" | "observe" | "no_objection";

/** Hook classes that ENFORCE — their fail-mode must be at least as strict as escalate. */
const ENFORCEMENT_HOOKS: ReadonlySet<HookClass> = new Set<HookClass>([
  "egress_decision",
  "policy_decision",
  "substrate_identity",
]);

/** Fail-modes that are fail-OPEN (not permitted for enforcement hooks). */
const FAIL_OPEN: ReadonlySet<FailMode> = new Set<FailMode>(["observe", "no_objection"]);

export type DataClass = "low" | "sensitive";

export interface EndpointDecl {
  host: string;
  port: number;
  data_class: DataClass;
}

export interface HookDecl {
  hook_class: HookClass;
  fields: string[];
  fail_mode: FailMode;
  /** Sensitive arguments_fields JSON-pointer selectors (policy_decision only). */
  argument_selectors?: string[];
}

export interface Governance {
  plugin_id: string;
  version: string;
  channel: string;
  entry: string;
  hooks: HookDecl[];
  endpoints: EndpointDecl[];
  /** Declared signal keys the plugin may emit (closes the undeclared-signal exfil path). */
  signal_keys: string[];
}

export const MAX_GOVERNANCE_BYTES = 256 * 1024; // 256 KiB

/** Closed top-level key set. */
const TOP_KEYS = new Set([
  "plugin_id",
  "version",
  "channel",
  "entry",
  "hooks",
  "endpoints",
  "signal_keys",
]);

const VERSION_RE = /^\d+\.\d+\.\d+$/;
const CHANNEL_RE = /^[a-z][a-z0-9-]{0,31}$/;

/**
 * Parse + validate governance.yaml text into a typed Governance, fully fail-closed.
 * `hostAllowedSelectors` is the per-tool host-allowlisted Sensitive JSON-pointer set the
 * installer supplies (S4); pass [] when not validating argument selectors in isolation.
 */
export function parseGovernance(
  text: string,
  hostAllowedSelectors: readonly string[] = [],
): Governance {
  if (text.length > MAX_GOVERNANCE_BYTES) {
    reject("manifest_too_large", `governance.yaml exceeds ${MAX_GOVERNANCE_BYTES} bytes`);
  }

  const parsed = parseRestrictedYaml(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    reject("yaml_malformed", "governance.yaml must be a mapping at the top level");
  }
  const root = parsed as Record<string, YamlValue>;

  rejectUnknownKeys(root, TOP_KEYS, "unknown_top_level_key", "(top level)");

  const plugin_id = requireString(root, "plugin_id");
  validateId(plugin_id, "plugin");
  const version = requireString(root, "version");
  if (!VERSION_RE.test(version)) reject("invalid_field_value", `version "${version}" must be semver x.y.z`);
  const channel = requireString(root, "channel");
  if (!CHANNEL_RE.test(channel)) reject("invalid_field_value", `channel "${channel}" is invalid`);
  const entry = requireString(root, "entry");
  // entry is a bundle path; apply the SAME validation as descriptor paths so the S1
  // governance surface is self-contained (codex LOW), not reliant on the verify step.
  validateBundlePath(entry);

  const hooks = parseHooks(root.hooks, hostAllowedSelectors);
  const endpoints = parseEndpoints(root.endpoints);
  const signal_keys = parseSignalKeys(root.signal_keys);

  return { plugin_id, version, channel, entry, hooks, endpoints, signal_keys };
}

/** sha256(canonical-JSON(parsed governance)) — the value bound in the BundleDescriptor. */
export function governanceHash(g: Governance): string {
  // Canonicalize a stable projection (the typed object), not the raw YAML text, so two
  // byte-different-but-logically-identical manifests hash the same.
  const bytes = new TextEncoder().encode(canonicalize(g));
  return sha256Hex(bytes);
}

function parseHooks(raw: YamlValue, hostAllowedSelectors: readonly string[]): HookDecl[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    reject("missing_required_field", "governance.hooks must be a non-empty list");
  }
  const HOOK_KEYS = new Set(["hook_class", "fields", "fail_mode", "argument_selectors"]);
  const out: HookDecl[] = [];
  const seenClasses = new Set<string>();

  for (const item of raw) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      reject("invalid_field_value", "each hook must be a mapping");
    }
    const h = item as Record<string, YamlValue>;
    rejectUnknownKeys(h, HOOK_KEYS, "unknown_nested_key", "hooks[]");

    const hook_class = requireString(h, "hook_class") as HookClass;
    if (!ENFORCEMENT_HOOKS.has(hook_class) && hook_class !== "ingress_content") {
      reject("invalid_field_value", `unknown hook_class "${hook_class}"`);
    }
    if (seenClasses.has(hook_class)) {
      reject("invalid_field_value", `hook_class "${hook_class}" declared more than once`);
    }
    seenClasses.add(hook_class);

    const fieldsRaw = h.fields;
    if (!Array.isArray(fieldsRaw)) reject("missing_required_field", `hook ${hook_class} fields must be a list`);
    const fields = fieldsRaw.map((f) => {
      if (typeof f !== "string") reject("invalid_field_value", `field in ${hook_class} must be a string`);
      return f;
    });
    const split = validateDeclaredFields(hook_class, fields);

    const fail_mode = requireString(h, "fail_mode") as FailMode;
    if (!(["deny", "escalate", "observe", "no_objection"] as string[]).includes(fail_mode)) {
      reject("invalid_field_value", `hook ${hook_class} fail_mode "${fail_mode}" is invalid`);
    }
    if (ENFORCEMENT_HOOKS.has(hook_class) && FAIL_OPEN.has(fail_mode)) {
      reject(
        "fail_open_enforcement_fail_mode",
        `enforcement hook ${hook_class} may not declare fail-open fail_mode "${fail_mode}"`,
      );
    }

    let argument_selectors: string[] | undefined;
    if (split.sensitive.includes("arguments_fields")) {
      const selRaw = h.argument_selectors;
      if (!Array.isArray(selRaw) || selRaw.length === 0) {
        reject(
          "undeclared_field_selector",
          `hook ${hook_class} requested arguments_fields but declared no argument_selectors`,
        );
      }
      argument_selectors = selRaw.map((s) => {
        if (typeof s !== "string") reject("undeclared_field_selector", "argument_selector must be a string");
        return s;
      });
      validateArgumentSelectors(argument_selectors, hostAllowedSelectors);
    } else if (h.argument_selectors !== undefined) {
      reject("invalid_field_value", `hook ${hook_class} declared argument_selectors without arguments_fields`);
    }

    out.push({
      hook_class,
      fields,
      fail_mode,
      ...(argument_selectors ? { argument_selectors } : {}),
    });
  }
  return out;
}

function parseEndpoints(raw: YamlValue): EndpointDecl[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) reject("invalid_field_value", "governance.endpoints must be a list");
  const EP_KEYS = new Set(["host", "port", "data_class"]);
  const out: EndpointDecl[] = [];
  for (const item of raw) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      reject("invalid_field_value", "each endpoint must be a mapping");
    }
    const e = item as Record<string, YamlValue>;
    rejectUnknownKeys(e, EP_KEYS, "unknown_nested_key", "endpoints[]");
    const host = requireString(e, "host");
    const port = e.port;
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
      reject("invalid_field_value", `endpoint port for "${host}" must be 1..65535`);
    }
    const data_class = e.data_class;
    if (data_class !== "low" && data_class !== "sensitive") {
      reject("undeclared_data_class_endpoint", `endpoint "${host}" must declare data_class low|sensitive`);
    }
    out.push({ host, port, data_class });
  }
  return out;
}

function parseSignalKeys(raw: YamlValue): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) reject("invalid_field_value", "governance.signal_keys must be a list");
  const out: string[] = [];
  const seen = new Set<string>();
  for (const k of raw) {
    if (typeof k !== "string" || k.length === 0) reject("invalid_field_value", "signal_keys entries must be strings");
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(k)) reject("invalid_field_value", `signal key "${k}" is invalid`);
    if (seen.has(k)) reject("invalid_field_value", `signal key "${k}" declared more than once`);
    seen.add(k);
    out.push(k);
  }
  return out;
}

function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  reason: "unknown_top_level_key" | "unknown_nested_key",
  where: string,
): void {
  for (const k of Object.keys(obj)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      reject("json_prototype_key", `${where} contains a prototype-pollution key "${k}"`);
    }
    if (!allowed.has(k)) {
      reject(reason, `${where} has unknown key "${k}"`);
    }
  }
}

function requireString(obj: Record<string, YamlValue>, key: string): string {
  // Object.hasOwn guards against inherited reads even if a caller passes a
  // prototype-bearing object (the YAML parser returns null-proto maps; this is
  // defense in depth — codex HIGH follow-up).
  const v = Object.hasOwn(obj, key) ? obj[key] : undefined;
  if (typeof v !== "string" || v.length === 0) {
    reject("missing_required_field", `governance.${key} is required and must be a non-empty string`);
  }
  return v;
}
