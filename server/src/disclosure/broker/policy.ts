/**
 * Sanctuary MCP Server — L3 Secret Broker: Policy Schema Extension
 *
 * Additive layer on top of the existing Principal Policy YAML: a new
 * optional top-level `skills:` section declares which skills may access
 * which secrets from the broker, at what scope, and with what TTL.
 *
 * Design (see Spike 2 for rationale):
 * - Absence of `skills:` means NO skill has broker access. Safe default.
 * - Scope values: "read" | "rotate" (rotate implies read).
 * - TTL optional; falls back to broker default (15 min) if unset.
 *
 * This module only parses/validates. The Broker/TokenIssuer enforces.
 */

import type { SecretScope } from "./backend-interface.js";
import type { SkillSecretGrant } from "./token-issuer.js";

export interface SkillSecretsPolicy {
  /** Skill name — must match the `skill` field a skill self-declares when requesting a token. */
  name: string;
  /** Secret grants this skill is authorized for. */
  secrets: SecretGrantPolicy[];
}

export interface SecretGrantPolicy {
  /** Secret name as stored in the broker backend. */
  name: string;
  /** Requested access scope. Defaults to "read" if omitted. */
  scope?: SecretScope;
  /** TTL cap in seconds. Broker still clamps at MAX_TOKEN_TTL_SECONDS. */
  ttl?: number;
}

export interface BrokerPolicySection {
  /** Optional; absence means no grants. */
  skills?: SkillSecretsPolicy[];
}

/** Valid scope strings per v0.10.0. Keep in sync with `SecretScope`. */
const VALID_SCOPES = new Set<string>(["read", "rotate"]);

/**
 * Parse and validate the `skills:` section of a loaded policy object.
 * Returns a flat list of grants ready for `TokenIssuer.setGrant`. Throws
 * with a descriptive message on malformed input.
 */
export function parseBrokerPolicy(raw: unknown): SkillSecretGrant[] {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== "object") {
    throw new Error("Broker policy root must be an object");
  }
  const section = raw as BrokerPolicySection;
  if (section.skills === undefined) return [];
  if (!Array.isArray(section.skills)) {
    throw new Error("Broker policy `skills` must be an array");
  }

  const grants: SkillSecretGrant[] = [];
  const seen = new Set<string>();
  for (const [i, skillEntry] of section.skills.entries()) {
    if (!skillEntry || typeof skillEntry !== "object") {
      throw new Error(`skills[${i}] must be an object`);
    }
    const skillName = (skillEntry as SkillSecretsPolicy).name;
    if (typeof skillName !== "string" || skillName.length === 0) {
      throw new Error(`skills[${i}].name must be a non-empty string`);
    }
    if (!/^[A-Za-z0-9._\-:]+$/.test(skillName)) {
      throw new Error(
        `skills[${i}].name contains invalid characters: ${JSON.stringify(skillName)}`
      );
    }
    const secrets = (skillEntry as SkillSecretsPolicy).secrets;
    if (!Array.isArray(secrets)) {
      throw new Error(`skills[${i}].secrets must be an array`);
    }
    for (const [j, secretEntry] of secrets.entries()) {
      if (!secretEntry || typeof secretEntry !== "object") {
        throw new Error(`skills[${i}].secrets[${j}] must be an object`);
      }
      const sg = secretEntry as SecretGrantPolicy;
      if (typeof sg.name !== "string" || sg.name.length === 0) {
        throw new Error(
          `skills[${i}].secrets[${j}].name must be a non-empty string`
        );
      }
      if (!/^[A-Za-z0-9._\-:/]+$/.test(sg.name)) {
        throw new Error(
          `skills[${i}].secrets[${j}].name contains invalid characters: ${JSON.stringify(sg.name)}`
        );
      }
      const scope: SecretScope = sg.scope ?? "read";
      if (!VALID_SCOPES.has(scope)) {
        throw new Error(
          `skills[${i}].secrets[${j}].scope must be one of "read" | "rotate" (got ${JSON.stringify(sg.scope)})`
        );
      }
      if (sg.ttl !== undefined) {
        if (typeof sg.ttl !== "number" || !Number.isFinite(sg.ttl) || sg.ttl <= 0) {
          throw new Error(
            `skills[${i}].secrets[${j}].ttl must be a positive number of seconds`
          );
        }
      }
      const key = `${skillName}\u0000${sg.name}`;
      if (seen.has(key)) {
        throw new Error(
          `Duplicate grant for skill ${JSON.stringify(skillName)} secret ${JSON.stringify(sg.name)}`
        );
      }
      seen.add(key);
      grants.push({
        skill: skillName,
        secret: sg.name,
        scope,
        ttlSeconds: sg.ttl,
      });
    }
  }
  return grants;
}

// ---------------------------------------------------------------------------
// Surrogate bindings: a SEPARATE, versioned policy document
// ---------------------------------------------------------------------------
//
// WHY THIS IS NOT IN `broker-policy.json` (design v2.1 finding A2-B2). v2 of the
// design kept surrogate bindings in the broker's own policy file and relied on an
// old broker failing to parse them. That was wrong: the shipped `secrets grant`
// writer (`cli/secrets.ts`) overwrites an existing entry's scope in place, so an
// operator on an old build could rewrite a surrogate entry to `read` and the old
// broker would then serve the value. So bindings live in their own file that
// `loadBrokerPolicyRaw`, `saveBrokerPolicy`, `secrets grant` and `secrets revoke`
// never read or write, and the VALUE lives under a separate keychain label the
// broker never looks under. The version field below is defense in depth; the label
// split is what actually makes a downgrade safe.
//
// ONE PARSER, THREE READERS (AGENTS.md rule 11). The broker, the operator CLI and
// root arming all parse bindings through `parseSurrogatePolicyDocument` and nothing
// else. Element grammar is not re-implemented here either: it comes from
// `credential-surrogate/binding.ts`, which the root helper daemon also uses when it
// loads its table. Four stages, one grammar.

import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_DESTINATIONS_PER_BINDING,
} from "../../credential-surrogate/constants.js";
import {
  validateSurrogateAgentId,
  validateSurrogateEnvName,
  validateSurrogateHeaderName,
  validateSurrogateHost,
  validateSurrogatePort,
  validateSurrogateSecretName,
  type SurrogateBinding,
} from "../../credential-surrogate/binding.js";

/** The only `surrogate_policy_version` this build serves. An unknown version is a parse error, never a best effort. */
export const SURROGATE_POLICY_VERSION = 1;

/**
 * Fixed failure classes for the audit detail.
 *
 * The audit line carries ONE of these and never parser message text. A message
 * built from the input would put policy content (secret names, hosts, a
 * malformed value) into the fortress chain, and `POLICY_LOAD_FAILED` is written
 * on a path that by definition just read something it could not trust.
 */
export type SurrogatePolicyFailureClass =
  | "read_error"
  | "json_error"
  | "schema_error"
  | "conflict"
  | "duplicate_binding"
  | "bad_version";

/**
 * A refusal to load a policy document, carrying only its class.
 *
 * `message` is a fixed string derived from the class, so a caller that logs the
 * error object cannot leak the document. Callers that need to distinguish causes
 * read `failureClass`, never the message.
 */
export class SurrogatePolicyError extends Error {
  readonly failureClass: SurrogatePolicyFailureClass;

  constructor(failureClass: SurrogatePolicyFailureClass) {
    super(`surrogate policy refused: ${failureClass}`);
    this.name = "SurrogatePolicyError";
    this.failureClass = failureClass;
  }
}

/** The document shape on disk. */
export interface SurrogatePolicyDocument {
  surrogate_policy_version: number;
  bindings: SurrogateBinding[];
}

const DOCUMENT_KEYS = ["surrogate_policy_version", "bindings"];
const BINDING_KEYS = ["secret", "agent", "env", "destinations", "header"];
const DESTINATION_KEYS = ["host", "port"];

function hasExactlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  if (actual.length !== keys.length) return false;
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) return false;
  }
  return true;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

/**
 * Parse and validate a surrogate policy document. Throws {@link SurrogatePolicyError}
 * on any deviation; there is no partial result, because a partially-read binding
 * set would arm an agent with a destination map nobody wrote.
 *
 * Strictness, and what each rule stops:
 *   - unknown keys refused at every level, so a field a future version means
 *     something by cannot be silently ignored by this one;
 *   - an unknown version refused outright;
 *   - element grammar from `credential-surrogate/binding.ts`, so the parser, root
 *     arming and the helper cannot disagree about a destination;
 *   - 1 to `MAX_SURROGATE_DESTINATIONS_PER_BINDING` destinations, all port 443;
 *   - at most `MAX_SURROGATE_BINDINGS_PER_AGENT` bindings for any one agent
 *     (AGENTS.md rule 8: the table is capped where it is built, not where it is
 *     used, and it is replaced whole per generation rather than grown);
 *   - TWO bindings naming the same secret refused (finding B2-S7). One secret
 *     binds to one agent and one header in slice 1; two rows would leave it
 *     ambiguous which header a value is written into, and a later removal would
 *     drop one row while the helper still served the other.
 */
export function parseSurrogatePolicyDocument(raw: unknown): SurrogatePolicyDocument {
  const doc = asRecord(raw);
  if (doc === null) throw new SurrogatePolicyError("schema_error");
  if (!hasExactlyKeys(doc, DOCUMENT_KEYS)) throw new SurrogatePolicyError("schema_error");
  if (doc.surrogate_policy_version !== SURROGATE_POLICY_VERSION) {
    throw new SurrogatePolicyError("bad_version");
  }
  if (!Array.isArray(doc.bindings)) throw new SurrogatePolicyError("schema_error");

  const bindings: SurrogateBinding[] = [];
  const secretsSeen = new Set<string>();
  const perAgent = new Map<string, number>();

  for (const entry of doc.bindings) {
    const b = asRecord(entry);
    if (b === null) throw new SurrogatePolicyError("schema_error");
    if (!hasExactlyKeys(b, BINDING_KEYS)) throw new SurrogatePolicyError("schema_error");
    if (validateSurrogateSecretName(b.secret) !== null) throw new SurrogatePolicyError("schema_error");
    if (validateSurrogateAgentId(b.agent) !== null) throw new SurrogatePolicyError("schema_error");
    if (validateSurrogateEnvName(b.env) !== null) throw new SurrogatePolicyError("schema_error");
    if (validateSurrogateHeaderName(b.header) !== null) throw new SurrogatePolicyError("schema_error");
    if (!Array.isArray(b.destinations)) throw new SurrogatePolicyError("schema_error");
    if (b.destinations.length < 1 || b.destinations.length > MAX_SURROGATE_DESTINATIONS_PER_BINDING) {
      throw new SurrogatePolicyError("schema_error");
    }

    const destinations: Array<{ host: string; port: number }> = [];
    const hostsSeen = new Set<string>();
    for (const rawDestination of b.destinations) {
      const d = asRecord(rawDestination);
      if (d === null) throw new SurrogatePolicyError("schema_error");
      if (!hasExactlyKeys(d, DESTINATION_KEYS)) throw new SurrogatePolicyError("schema_error");
      if (validateSurrogateHost(d.host) !== null) throw new SurrogatePolicyError("schema_error");
      if (validateSurrogatePort(d.port) !== null) throw new SurrogatePolicyError("schema_error");
      // A repeated host inside one binding is refused rather than deduped: it
      // makes the destination count (and so the cap) mean something different
      // from what the operator wrote.
      if (hostsSeen.has(d.host as string)) throw new SurrogatePolicyError("schema_error");
      hostsSeen.add(d.host as string);
      destinations.push({ host: d.host as string, port: d.port as number });
    }

    const secret = b.secret as string;
    if (secretsSeen.has(secret)) throw new SurrogatePolicyError("duplicate_binding");
    secretsSeen.add(secret);

    const agent = b.agent as string;
    const count = (perAgent.get(agent) ?? 0) + 1;
    if (count > MAX_SURROGATE_BINDINGS_PER_AGENT) throw new SurrogatePolicyError("schema_error");
    perAgent.set(agent, count);

    bindings.push({ secret, agent, env: b.env as string, destinations, header: b.header as string });
  }

  return { surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings };
}

/**
 * Secret names that are BOTH surrogate-bound and named by a `read` or `rotate`
 * grant, under any skill.
 *
 * This is defense in depth, not the mechanism. The mechanism is the keychain
 * label: a broker handed a grant for a bound name looks under `sanctuary-broker*`
 * and gets `SecretNotFoundError`, whatever any policy file says. The conflict rule
 * exists so that a policy in that state is refused loudly at arm time and yields
 * zero grants at broker open, rather than quietly looking like a working `read`
 * grant that always fails.
 *
 * Returned sorted so an audit detail is stable across runs and two loads of the
 * same policy produce the same line.
 */
export function findSurrogateGrantConflicts(
  bindings: readonly SurrogateBinding[],
  grants: readonly SkillSecretGrant[],
): string[] {
  const bound = new Set(bindings.map((b) => b.secret));
  const conflicts = new Set<string>();
  for (const grant of grants) {
    // Every broker scope is read-or-stronger today, so any grant naming a bound
    // secret is a conflict. Pinned to VALID_SCOPES above: if a scope that does not
    // imply a value read is ever added, this predicate is where it gets excluded.
    if (bound.has(grant.secret)) conflicts.add(grant.secret);
  }
  return Array.from(conflicts).sort();
}

/** Every secret name a binding names, as the required set `TokenIssuer` refuses against. */
export function surrogateBoundSecretNames(
  bindings: readonly SurrogateBinding[],
): ReadonlySet<string> {
  return new Set(bindings.map((b) => b.secret));
}
