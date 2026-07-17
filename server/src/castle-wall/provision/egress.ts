/**
 * Confined-agent egress provisioning (Option A, per-uid signed allow-list;
 * design doc Review/Sanctuary/Confined_Agent_Egress_Design_2026-07-10.md,
 * revised per the 2026-07-10 adversarial review).
 *
 * The 2026-07-09 full-op drill proved `protect --hermes` confines the agent
 * correctly (per-uid deny, operator free) but provisions NO egress path, so
 * the confined CoS could not reach even its own endpoints (api.venice.ai hit
 * `(default-deny: no matching rule)` for everything). This module closes that
 * gap: it declares the per-harness endpoint set (the `HarnessEndpointSet`),
 * builds provenance-tagged, revocable allow rules from it, publishes them as
 * ordinary rule files under the fortress's `policy/egress/rules/` directory
 * (the SAME source the policy daemon reads, composes, and signs with the
 * existing pinned signer -- no new key, no new trust anchor), and statically
 * verifies each declared endpoint evaluates to an allow through the same TS
 * matcher the enforcement paths use.
 *
 * ONE LIST, TWO CONSUMERS (design section 3.1): the endpoint set feeds BOTH
 * the rule provisioning below AND the pre/post-arm probes in
 * `wrap/auto-provision.ts`, so the granted set and the verified set can never
 * drift (the same single-source pattern `egress-gate/parity.ts` enforces for
 * the gate).
 *
 * PROVENANCE-TAGGED RULE IDS (design section 2.3, Option-B forward-compat):
 * every provisioned rule id is `provisioned-<harness>-<digest12>` with
 * `derived: true` and a description naming the harness, mirroring the
 * observe/learn `derived-observe-<digest>` convention. The Option-B migration
 * (and `unprovision`) rescinds exactly the `provisioned-<harness>-*` rules in
 * one signed republish; nothing here relies on scoping semantics B would not
 * have (rules ship UNSCOPED in v1 -- the matching `.unattributed` uid-mode
 * evaluator hardening lands in the SAME PR per HIGH-1).
 *
 * SECURITY: this module never signs anything itself and never talks to the
 * sysext. Publishing means writing rule FILES; the reachable policy daemon
 * (guaranteed by the orchestrator's ensure-policy-daemon step) re-reads,
 * re-derives (#380 DNS), re-signs with the pinned key, and broadcasts on the
 * injected `reloadPolicy` call. A reload that cannot be confirmed is a
 * fail-closed refusal, never a silent pass (AGENTS.md invariant #5).
 */

import { readdir, mkdir, writeFile, unlink, readFile } from "node:fs/promises";
import { join } from "node:path";

import { sha256 } from "@noble/hashes/sha256";

import { canonicalize } from "../../mesh/canonical-json.js";
import { stringToBytes } from "../../core/encoding.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { validateRule } from "../allowlist/schema.js";
import {
  DERIVED_DNS_RULE_ID,
  deriveDnsRuleForHostnameRules,
} from "../allowlist/dns-derivation.js";
import {
  allowlistAllowsTarget,
  canonicalizeConnectAuthority,
} from "../egress-proxy.js";
import { MESSAGING_HOST_DENYLIST } from "../runtime/curated-allowlist.js";

/**
 * Risk class a harness adapter declares for one of its endpoints.
 *
 *  - `standard`: a single-purpose API host; host+port+protocol is an honest
 *    description of the granted authority.
 *  - `broad-authority-gateway`: a shared multi-API frontend (e.g. Google's
 *    `www.googleapis.com`) where an exact-host rule grants EVERY API served
 *    under that SNI, because API selection lives in the URL path the sysext
 *    never sees (MED-1). Such a grant must be named as broad in the Tier-1
 *    confirm, never presented under a "tiny host set" banner.
 *
 * Messaging-exfil risk is NOT a declared class: it is COMPUTED from the
 * canonical `MESSAGING_HOST_DENYLIST` (see {@link endpointIsMessagingExfilRisk})
 * so this module can never drift from the curated-allowlist posture.
 */
export type HarnessEndpointRiskClass = "standard" | "broad-authority-gateway";

/** One endpoint a harness needs to reach to function. */
export interface HarnessEndpoint {
  /** Human-readable name for plans/probes/audit, e.g. "LLM (Venice)". */
  readonly name: string;
  /** Exact hostname (SNI-matched by the sysext; never a wildcard). */
  readonly host: string;
  /** Destination port (pinned; never "any port on that host"). */
  readonly port: number;
  /** Protocol (pinned). All declared endpoints today are tcp/TLS. */
  readonly protocol: "tcp";
  /** Declared risk class (see {@link HarnessEndpointRiskClass}). */
  readonly riskClass: HarnessEndpointRiskClass;
}

/**
 * The per-harness curated endpoint set (design section 3.1): the harness
 * adapter that installs the harness declares what the harness needs.
 * Versioned WITH the adapter; a changed set produces a provisioning diff at
 * the next protect/upgrade run (additions confirmed, removals revoked).
 */
export interface HarnessEndpointSet {
  readonly harnessId: string;
  readonly endpoints: ReadonlyArray<HarnessEndpoint>;
}

/**
 * The Hermes CoS endpoint seed set.
 *
 * MED-1 (googleapis breadth honesty): the previously-recorded single Google
 * host, `www.googleapis.com`, is Google's SHARED multi-API gateway (Drive,
 * Sheets, Cloud Storage and more, all on 443 under one SNI); an exact-host
 * rule there grants upload/exfil-capable APIs the Workspace MCP never needs.
 * Per the design's mitigation ladder step 1, this seed prefers the
 * PER-SERVICE hosts Hermes actually needs: the Gmail and Calendar API hosts
 * for the Workspace MCP's calls, plus the two OAuth token-refresh hosts. If
 * the LIVE Workspace MCP turns out to route through the shared frontend, the
 * denied flow surfaces as an observe candidate at the drill (an expected,
 * in-design event) and the broad grant is then accepted EXPLICITLY through
 * the Tier-1 gate with the `broad-authority-gateway` marking -- never
 * silently seeded here.
 *
 * `api.telegram.org` is on `MESSAGING_HOST_DENYLIST` (a low-friction exfil
 * channel for generic agents) but is the CoS's operator channel; the confirm
 * plan renders it with the exfil-risk marking so the operator signs the
 * messaging grant knowingly (design section 3.1(b) resolution).
 */
export const HERMES_ENDPOINT_SET: HarnessEndpointSet = Object.freeze({
  harnessId: "hermes",
  endpoints: Object.freeze([
    Object.freeze({
      name: "LLM (Venice)",
      host: "api.venice.ai",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
    Object.freeze({
      name: "Telegram Bot API",
      host: "api.telegram.org",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
    Object.freeze({
      name: "Google Workspace MCP (Gmail API)",
      host: "gmail.googleapis.com",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
    Object.freeze({
      name: "Google Workspace MCP (Calendar API)",
      host: "calendar-json.googleapis.com",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
    Object.freeze({
      name: "Google OAuth (token refresh)",
      host: "oauth2.googleapis.com",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
    Object.freeze({
      name: "Google OAuth (account endpoints)",
      host: "accounts.google.com",
      port: 443,
      protocol: "tcp" as const,
      riskClass: "standard" as const,
    }),
  ]),
});

/** Audit operation stamped on a successful provision (distinct LOCAL value; never widens a shared enum). */
export const EGRESS_PROVISIONED_AUDIT_OP = "egress_provisioned";
/** Audit operation stamped on a refuse-to-arm / failed-verify refusal (distinct LOCAL value). */
export const EGRESS_PROVISION_REFUSED_AUDIT_OP = "egress_provision_refused";
/** Audit operation the policy daemon stamps when the periodic as-uid egress liveness probe fails (MED-3 secondary signal). */
export const EGRESS_PROBE_FAILED_AUDIT_OP = "egress_probe_failed";

/**
 * Non-listed hostname used as the post-arm NEGATIVE control: a process
 * running as the agent uid must NOT be able to reach it through the armed
 * wall. Deliberately a real, always-up host so "blocked" is attributable to
 * the wall rather than to the host being down.
 */
export const AGENT_EGRESS_NEGATIVE_CONTROL_HOST = "example.com";

/** Prefix all provisioned rule ids for `harnessId` carry (the revocation handle). */
export function provisionedRuleIdPrefix(harnessId: string): string {
  return `provisioned-${harnessId}-`;
}

/** Compute SHA-256 hex of UTF-8 bytes (local copy; avoids importing the runtime publisher). */
function sha256HexOf(text: string): string {
  const digest = sha256(stringToBytes(text));
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    const b = digest[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Stable, recognizable provisioned-rule id: `provisioned-<harness>-<digest12>`
 * where the digest covers the effective match (harness, host, port, protocol),
 * mirroring the observe/learn `derived-observe-<digest>` convention. Stable
 * across runs (idempotent re-provision rewrites the same file) and stable
 * against description-only edits.
 */
export function provisionedRuleId(harnessId: string, endpoint: HarnessEndpoint): string {
  const digest = sha256HexOf(
    canonicalize({
      harness: harnessId,
      host: endpoint.host,
      port: endpoint.port,
      protocol: endpoint.protocol,
    }),
  ).slice(0, 12);
  return `${provisionedRuleIdPrefix(harnessId)}${digest}`;
}

/**
 * True iff the endpoint's host matches the canonical messaging-exfil
 * denylist (substring, case-insensitive -- the same matcher posture the
 * curated-allowlist guard documents). Computed, never hand-declared, so the
 * exfil-risk marking in the Tier-1 confirm can never drift from the
 * canonical list.
 */
export function endpointIsMessagingExfilRisk(endpoint: HarnessEndpoint): boolean {
  const host = endpoint.host.toLowerCase();
  return MESSAGING_HOST_DENYLIST.some((denied) => host.includes(denied.toLowerCase()));
}

/**
 * Routing mode for the provisioned endpoint rules (Unified Protect Slice 5
 * S5-4, the exclusive routing model, design BLOCKER-1 fix):
 *
 *  - `coarse` (default, byte-identical to the shipped v1 shape): rules ship
 *    UNSCOPED (`scope: {}`), so the confined agent may reach its declared
 *    endpoints DIRECTLY. The drill-proven coarse posture.
 *  - `exclusive`: rules are RE-SCOPED AWAY FROM THE AGENT to the gate
 *    principal (`scope.uids = [gate_uid]`, the S5-0 per-principal axis), so
 *    the GATE uid is kernel-bounded to the declared endpoint set while the
 *    agent's only sanctioned path off the box is the gate channel. macOS-only
 *    (the Linux daemon fail-closed refuses `uids`-bearing rule files by
 *    design); the exclusive-routing composer asserts no agent-reachable
 *    direct endpoint allow survives composition.
 */
export type ProvisionedEgressRouting =
  | { readonly mode: "coarse" }
  | { readonly mode: "exclusive"; readonly gate_uid: number };

/**
 * Build the provisioned allow rules for a harness endpoint set (pure).
 *
 * Shape decisions (design section 3.3): exact host + pinned port + pinned
 * protocol; `derived: true` + provenance id + harness-naming description
 * (section 2.3). Scope is routing-mode dependent (see
 * {@link ProvisionedEgressRouting}): UNSCOPED in coarse mode (the shipped v1
 * shape, byte-identical), gate-uid-scoped in exclusive mode (S5-4). Throws
 * when any built rule fails schema validation -- a rule that cannot be
 * published safely must abort the flow, never be silently dropped -- and
 * when an exclusive routing carries a non-positive gate uid.
 */
export function buildProvisionedEgressRules(
  set: HarnessEndpointSet,
  createdAt: string,
  routing: ProvisionedEgressRouting = { mode: "coarse" },
): AllowlistRule[] {
  if (
    routing.mode === "exclusive" &&
    (!Number.isInteger(routing.gate_uid) || routing.gate_uid <= 0)
  ) {
    throw new Error(
      `provisioned egress rules: exclusive routing requires a positive integer gate_uid, got ${String(
        (routing as { gate_uid: unknown }).gate_uid,
      )}`,
    );
  }
  const scope: AllowlistRule["scope"] =
    routing.mode === "exclusive" ? { uids: [routing.gate_uid] } : {};
  const routingNote =
    routing.mode === "exclusive"
      ? " Exclusive routing: bound to the sanctuary-gate principal (S5-0 uids scope); the agent transits the gate."
      : "";
  const rules: AllowlistRule[] = set.endpoints.map((endpoint) => ({
    id: provisionedRuleId(set.harnessId, endpoint),
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: createdAt,
    description:
      `Provisioned egress for harness "${set.harnessId}": ${endpoint.name} ` +
      `(${endpoint.host}:${endpoint.port}/${endpoint.protocol}). Published by 'sanctuary protect'; ` +
      `revocable via unprovision (provenance-tagged id).` +
      routingNote,
    match: {
      host: [endpoint.host],
      port: [endpoint.port],
      protocol: endpoint.protocol,
    },
    scope: { ...scope },
    disposition: "allow",
    derived: true,
  }));
  for (const rule of rules) {
    const issues = validateRule(rule);
    if (issues.length > 0) {
      throw new Error(
        `provisioned egress rule ${rule.id} failed schema validation: ${issues.join("; ")}`,
      );
    }
  }
  return rules;
}

/**
 * Operator-facing plan lines for the Tier-1 confirm (design section 3.1(b)):
 * every grant is named BEFORE the one-confirm ceremony, messaging hosts carry
 * the exfil-risk marking so the operator signs that grant knowingly, and a
 * broad-authority gateway is named as such (MED-1) -- never under a "tiny
 * host set" banner.
 */
export function renderEgressPlanLines(set: HarnessEndpointSet): string[] {
  const lines: string[] = [
    `Egress grants to provision for "${set.harnessId}" (signed, revocable allow rules for the agent; everything else stays default-deny):`,
  ];
  for (const endpoint of set.endpoints) {
    const markings: string[] = [];
    if (endpointIsMessagingExfilRisk(endpoint)) {
      markings.push(
        "EXFIL-RISK: messaging host (denylisted for generic agents; this harness's operator channel -- grant it knowingly)",
      );
    }
    if (endpoint.riskClass === "broad-authority-gateway") {
      markings.push(
        "BROAD AUTHORITY: shared multi-API gateway; a host rule grants EVERY API served under this SNI",
      );
    }
    const marking = markings.length > 0 ? ` [${markings.join("; ")}]` : "";
    lines.push(`  - ${endpoint.name}: ${endpoint.host}:${endpoint.port}/${endpoint.protocol}${marking}`);
  }
  return lines;
}

/** One row of the static (pre-arm) endpoint evaluation table. */
export interface EndpointStaticCheck {
  name: string;
  host: string;
  port: number;
  /** True iff the endpoint evaluates to an allow through the TS matcher. */
  allowed: boolean;
}

/** Result of the static pre-arm verification. */
export interface StaticEgressVerifyResult {
  ok: boolean;
  checks: EndpointStaticCheck[];
  /**
   * True iff the scoped DNS allow (#380) exists for the ruleset: either an
   * operator-authored rule already claims the reserved id, or derivation
   * from the current resolver set produces one. False (fail-closed) when
   * the resolver set is unknown -- hostname allows without DNS would brick
   * the agent's resolution anyway.
   */
  dnsRulePresent: boolean;
}

/**
 * Statically verify (pure) that every declared endpoint evaluates to an
 * allow-disposition match through the SAME TS matcher the enforcement paths
 * use (`allowlistAllowsTarget`, the egress-proxy/gate evaluator), plus the
 * #380 derived-DNS presence requirement. Runs against rules READ BACK from
 * the persisted rules directory (the daemon's actual signing source), never
 * against in-memory intent (design section 5 layer 1).
 *
 * F1 parity: an EMPTY endpoint set fails closed with a synthetic row --
 * "nothing was verified" must never read as "everything passed".
 */
export function verifyProvisionedEgressStatically(
  rules: ReadonlyArray<AllowlistRule>,
  set: HarnessEndpointSet,
  resolvers: readonly unknown[],
  nowIso: string,
): StaticEgressVerifyResult {
  if (set.endpoints.length === 0) {
    return {
      ok: false,
      checks: [{ name: "(no endpoints declared)", host: "", port: 0, allowed: false }],
      dnsRulePresent: false,
    };
  }
  const mutableRules = [...rules];
  const checks: EndpointStaticCheck[] = set.endpoints.map((endpoint) => {
    let allowed: boolean;
    try {
      const target = canonicalizeConnectAuthority(`${endpoint.host}:${endpoint.port}`);
      allowed = allowlistAllowsTarget(mutableRules, target);
    } catch {
      // Fail-closed: an endpoint whose authority cannot even be
      // canonicalized can never be verified as allowed.
      allowed = false;
    }
    return { name: endpoint.name, host: endpoint.host, port: endpoint.port, allowed };
  });
  const dnsRulePresent =
    rules.some((rule) => rule.id === DERIVED_DNS_RULE_ID) ||
    deriveDnsRuleForHostnameRules({
      rules: mutableRules,
      resolvers,
      createdAt: nowIso,
    }) !== null;
  return {
    ok: checks.every((c) => c.allowed) && dnsRulePresent,
    checks,
    dnsRulePresent,
  };
}

/** Render the per-endpoint PASS/FAIL table (static or as-uid) for the operator. */
export function renderEndpointCheckLines(checks: ReadonlyArray<EndpointStaticCheck>): string[] {
  return checks.map(
    (c) =>
      `  [${c.allowed ? "PASS" : "FAIL"}] ${c.name}${c.host ? ` (${c.host}:${c.port})` : ""}`,
  );
}

/** The fortress-relative rules directory the policy daemon reads and signs from. */
export function egressRulesDir(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", "rules");
}

/**
 * Read the operator-authored ruleset back from the persisted rules directory
 * (the daemon's signing source). Mirrors the daemon's own read half
 * (`loadManifestState`): every `.json` file must parse and validate; an
 * invalid rule file throws (fail-closed -- the daemon would refuse the same
 * ruleset, so verification against it would be meaningless).
 */
export async function readEgressRulesFromDisk(fortressPath: string): Promise<AllowlistRule[]> {
  const dir = egressRulesDir(fortressPath);
  let filenames: string[];
  try {
    filenames = (await readdir(dir)).filter((name) => name.endsWith(".json"));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return [];
    throw err;
  }
  filenames.sort();
  const rules: AllowlistRule[] = [];
  for (const filename of filenames) {
    const raw = await readFile(join(dir, filename), "utf8");
    const parsed = JSON.parse(raw) as AllowlistRule;
    const issues = validateRule(parsed);
    if (issues.length > 0) {
      throw new Error(`rule ${filename} invalid: ${issues.join("; ")}`);
    }
    rules.push(parsed);
  }
  return rules;
}

/** Injected reload trigger: asks the reachable policy daemon to re-read, re-sign, and broadcast. */
export interface PolicyReloadTrigger {
  (): Promise<{ ok: boolean; error?: string }>;
}

/** Input to {@link publishProvisionedEgressRules}. */
export interface PublishProvisionedEgressInput {
  fortressPath: string;
  endpointSet: HarnessEndpointSet;
  /**
   * Trigger a policy reload on the REACHABLE policy daemon (the orchestrator
   * guarantees one exists before this step). Failure -- including an
   * unreachable socket -- is a fail-closed refusal.
   */
  reloadPolicy: PolicyReloadTrigger;
  /**
   * Routing mode for the published rules (S5-4). Default coarse (the shipped
   * v1 shape, byte-identical). Exclusive scopes every provisioned rule to the
   * gate principal; the same provenance-tagged ids are reused, so a mode
   * switch republishes (overwrites) the same files rather than duplicating.
   */
  routing?: ProvisionedEgressRouting;
  now?: () => Date;
}

/** Outcome of {@link publishProvisionedEgressRules}. */
export type PublishProvisionedEgressResult =
  | { ok: true; ruleIds: string[]; staleRuleIdsRemoved: string[] }
  | { ok: false; error: string };

/**
 * Publish the harness's provisioned egress rules: write one canonical-JSON
 * rule file per endpoint into the fortress rules directory, remove any STALE
 * `provisioned-<harness>-*` files no longer in the declared set (the
 * section-3.5 currency diff: removals revoke), then trigger the policy
 * daemon's reload so the new ruleset is composed, signed by the pinned
 * signer, and broadcast. Fail-closed: any write, scrub, or reload failure
 * returns `ok: false` and the caller must abort before arm.
 */
export async function publishProvisionedEgressRules(
  input: PublishProvisionedEgressInput,
): Promise<PublishProvisionedEgressResult> {
  const now = input.now ?? (() => new Date());
  const dir = egressRulesDir(input.fortressPath);
  try {
    const rules = buildProvisionedEgressRules(
      input.endpointSet,
      now().toISOString(),
      input.routing ?? { mode: "coarse" },
    );
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const wantedFilenames = new Set(rules.map((rule) => `${rule.id}.json`));
    for (const rule of rules) {
      await writeFile(join(dir, `${rule.id}.json`), stringToBytes(canonicalize(rule)), {
        mode: 0o600,
      });
    }
    // Currency scrub: a stale provisioned rule for this harness (an endpoint
    // the adapter no longer declares) is revoked in the same publish.
    const prefix = provisionedRuleIdPrefix(input.endpointSet.harnessId);
    const staleRuleIdsRemoved: string[] = [];
    for (const filename of await readdir(dir)) {
      if (!filename.startsWith(prefix) || !filename.endsWith(".json")) continue;
      if (wantedFilenames.has(filename)) continue;
      await unlink(join(dir, filename));
      staleRuleIdsRemoved.push(filename.slice(0, -".json".length));
    }
    const reload = await input.reloadPolicy();
    if (!reload.ok) {
      return {
        ok: false,
        error: `policy reload after publishing egress rules failed: ${reload.error ?? "unknown error"}`,
      };
    }
    return { ok: true, ruleIds: rules.map((rule) => rule.id), staleRuleIdsRemoved };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/** Input to {@link scrubProvisionedEgressRules}. */
export interface ScrubProvisionedEgressInput {
  fortressPath: string;
  harnessId: string;
  /**
   * Optional reload trigger. The scrub itself is authoritative on the
   * persisted source; the reload propagates it to a still-running daemon.
   * A reload failure is reported (never thrown) because the rules are
   * already gone from the signing source -- the next daemon load cannot
   * resurrect them.
   */
  reloadPolicy?: PolicyReloadTrigger;
}

/** Outcome of {@link scrubProvisionedEgressRules}. */
export interface ScrubProvisionedEgressResult {
  removedRuleIds: string[];
  /** False when the optional reload could not be confirmed (rules are still scrubbed on disk). */
  reloadOk: boolean;
}

/**
 * Remove every `provisioned-<harness>-*` rule file from the fortress rules
 * directory and VERIFY none survive (design section 6: no orphan grants).
 * Throws when the post-scrub verification still finds a matching file --
 * fail-loud, mirroring `uninstallAgentHarnessDaemon`'s teardown semantics.
 * Idempotent: scrubbing an already-clean directory removes nothing and
 * succeeds.
 */
export async function scrubProvisionedEgressRules(
  input: ScrubProvisionedEgressInput,
): Promise<ScrubProvisionedEgressResult> {
  const dir = egressRulesDir(input.fortressPath);
  const prefix = provisionedRuleIdPrefix(input.harnessId);
  const removedRuleIds: string[] = [];
  let filenames: string[];
  try {
    filenames = await readdir(dir);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { removedRuleIds: [], reloadOk: true };
    }
    throw err;
  }
  for (const filename of filenames) {
    if (!filename.startsWith(prefix) || !filename.endsWith(".json")) continue;
    await unlink(join(dir, filename));
    removedRuleIds.push(filename.slice(0, -".json".length));
  }
  // Verified read-back: the scrub is only a scrub if nothing survives.
  const survivors = (await readdir(dir)).filter(
    (name) => name.startsWith(prefix) && name.endsWith(".json"),
  );
  if (survivors.length > 0) {
    throw new Error(
      `egress rule scrub left ${survivors.length} provisioned rule file(s) behind: ${survivors.join(", ")}`,
    );
  }
  let reloadOk = true;
  if (input.reloadPolicy) {
    try {
      reloadOk = (await input.reloadPolicy()).ok;
    } catch {
      reloadOk = false;
    }
  }
  return { removedRuleIds, reloadOk };
}

/** One row of the post-arm as-uid probe report. */
export interface AgentEgressProbeRow {
  name: string;
  host: string;
  port: number;
  /** "reachable" for declared endpoints; "blocked" for the negative control. */
  expected: "reachable" | "blocked";
  observed: "reachable" | "blocked";
  pass: boolean;
}

/** Aggregate post-arm as-uid verification report. */
export interface AgentEgressVerifyReport {
  ok: boolean;
  rows: AgentEgressProbeRow[];
}

/** One probe to run as the agent uid. */
export interface AgentEgressProbeSpec {
  name: string;
  host: string;
  port: number;
  expected: "reachable" | "blocked";
}

/**
 * Build the as-uid probe list for an endpoint set: every declared endpoint
 * (expected reachable through the armed wall) plus the non-listed
 * negative-control host (expected BLOCKED as the agent uid -- a reachable
 * negative control means the wall is not confining the agent). Throws when
 * the negative control collides with a declared endpoint (the control would
 * be meaningless). F1 parity: an empty endpoint set yields an empty spec
 * list, which {@link buildAgentEgressReport} fails closed on.
 */
export function buildAgentEgressProbeSpecs(set: HarnessEndpointSet): AgentEgressProbeSpec[] {
  if (set.endpoints.some((e) => e.host.toLowerCase() === AGENT_EGRESS_NEGATIVE_CONTROL_HOST)) {
    throw new Error(
      `negative-control host ${AGENT_EGRESS_NEGATIVE_CONTROL_HOST} collides with a declared endpoint`,
    );
  }
  if (set.endpoints.length === 0) {
    return [];
  }
  const specs: AgentEgressProbeSpec[] = set.endpoints.map((endpoint) => ({
    name: endpoint.name,
    host: endpoint.host,
    port: endpoint.port,
    expected: "reachable" as const,
  }));
  specs.push({
    name: "negative control (non-listed host must be blocked)",
    host: AGENT_EGRESS_NEGATIVE_CONTROL_HOST,
    port: 443,
    expected: "blocked",
  });
  return specs;
}

/**
 * Fold observed reachability into the report (pure). `observedReachable[i]`
 * corresponds to `specs[i]`. Empty specs fail closed (F1: nothing verified is
 * never a pass).
 */
export function buildAgentEgressReport(
  specs: ReadonlyArray<AgentEgressProbeSpec>,
  observedReachable: ReadonlyArray<boolean>,
): AgentEgressVerifyReport {
  if (specs.length === 0) {
    return {
      ok: false,
      rows: [
        {
          name: "(no endpoints declared)",
          host: "",
          port: 0,
          expected: "reachable",
          observed: "blocked",
          pass: false,
        },
      ],
    };
  }
  const rows: AgentEgressProbeRow[] = specs.map((spec, i) => {
    const observed: "reachable" | "blocked" = observedReachable[i] === true ? "reachable" : "blocked";
    return {
      name: spec.name,
      host: spec.host,
      port: spec.port,
      expected: spec.expected,
      observed,
      pass: observed === spec.expected,
    };
  });
  return { ok: rows.every((r) => r.pass), rows };
}

/** Render the as-uid PASS/FAIL table for the operator. */
export function renderAgentEgressReportLines(report: AgentEgressVerifyReport): string[] {
  return report.rows.map(
    (row) =>
      `  [${row.pass ? "PASS" : "FAIL"}] ${row.name}${row.host ? ` (${row.host}:${row.port})` : ""}: ` +
      `expected ${row.expected}, observed ${row.observed}`,
  );
}

/**
 * The argv for one as-uid TLS connectivity probe. The whole protect flow runs
 * as root (enforced up front), so `sudo -u '#<uid>'` genuinely changes the
 * REAL uid the wall and pf key on (`OriginClassifier` classifies on ruid).
 * `/usr/bin/curl` completing ANY HTTP response over https proves TCP + TLS
 * through the armed wall; a wall block surfaces as a connect timeout/reset
 * (nonzero exit). `--fail` is deliberately absent: an HTTP-level error (403,
 * 404) still proves reachability.
 *
 * MED-2 (PR-905 review): `--noproxy '*'` disables ALL proxy use for this
 * probe. Without it, if the agent account's environment carries
 * HTTP(S)_PROXY (or curl's `.curlrc` sets one), curl could reach the endpoint
 * THROUGH a proxy and report exit 0 while the DIRECT path the Castle Wall
 * actually governs is blocked -- a false PASS that would bless a broken
 * egress path. The wall enforces the direct connection, so the probe MUST
 * test the direct connection. `'*'` bypasses the proxy for every host.
 */
export function asUidTlsProbeArgv(
  uid: number,
  host: string,
  port: number,
): { file: string; args: string[] } {
  if (!Number.isSafeInteger(uid) || uid <= 0) {
    throw new Error(`as-uid probe requires a positive integer uid, got ${String(uid)}`);
  }
  return {
    file: "/usr/bin/sudo",
    args: [
      "-n",
      "-u",
      `#${uid}`,
      "/usr/bin/curl",
      // MED-2: force the DIRECT path (never a proxy), matching what the wall
      // governs. A proxied success would be a false PASS over a blocked
      // direct path.
      "--noproxy",
      "*",
      "--silent",
      "--show-error",
      "--max-time",
      "10",
      "--output",
      "/dev/null",
      `https://${host}:${port}/`,
    ],
  };
}

/**
 * Decide reachability from the probe process outcome (pure; fail-closed).
 * Only a clean exit 0 counts as reachable; every other exit code, a spawn
 * error, or a signal death counts as blocked/unverified.
 */
export function asUidProbeReachableDecision(exitCode: number | null): boolean {
  return exitCode === 0;
}
