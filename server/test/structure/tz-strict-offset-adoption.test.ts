/**
 * TZ-SIB-01 / TZ-SIB-02 — server-wide structure pin for the strict-offset
 * timestamp predicate (`parseIsoInstantWithOffset`, `core/time.ts`).
 *
 * Capability pinned: timestamps entering trust arithmetic are read through ONE
 * strict ISO-8601-with-mandatory-offset predicate, defined once, and the
 * adopted call sites are asserted BY NAME. The module-scoped half of this pin
 * (the guardian quorum module's four fields) lives in
 * `c12-replay-parity.test.ts` ("TZ-WINDOW-01" case — must match the import it
 * asserts from `core/time.js`); this file carries the halves a module-scoped
 * pin cannot: single definition, the consumers outside that module, and a
 * server-wide freeze on the bare `Date.parse` idiom so a NEW bare `Date.parse`
 * site cannot land silently.
 *
 * SCOPE BOUND of the freeze (the scope is part of the claim): it is lexical
 * over the `Date.parse` spelling only. It does not see the `new Date(<string>)`
 * idiom (register id TZ-SIB-04) or an aliased reference to `Date.parse` —
 * distinguishing string arguments needs type information, which is a separate
 * guard, not a wider regex. Zero aliasing sites exist today.
 *
 * WHY by-name and not by count: a bare occurrence count stays green when a
 * call is swapped onto a different field — that exact defect shape has shipped
 * once already (see the TZ-WINDOW-01 pin's history). So each adopted site is
 * asserted by its argument spelling.
 *
 * STATED BOUND of the freeze: the grandfathered table records an EXACT
 * executable-occurrence count per file, so it detects any addition or removal,
 * but a same-file swap of one existing call onto a different field is inside
 * the count and outside this pin. The adopted sites — the ones a trust
 * decision reads — are the by-name assertions above the freeze; a
 * grandfathered file that adopts the predicate shrinks its count and MUST
 * remove or update its entry, so the table only ratchets down.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { stripCodeComments } from "./public-surface";

const HERE = fileURLToPath(import.meta.url);
const SERVER_DIR = join(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");

/** The single home of the predicate; must match the import in consumers. */
const PREDICATE_FILE = "core/time.ts";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

/** Executable code only: comments are prose ABOUT the rule, never a use. */
function readCode(rel: string): string {
  return stripCodeComments(readFileSync(join(SERVER_SRC, rel), "utf8"), rel);
}

/**
 * Every file under `server/src` with at least one executable `Date.parse` call
 * outside the shared predicate, with its EXACT count and the reason the entry
 * exists. New timestamp parsing routes through `parseIsoInstantWithOffset`
 * (`core/time.ts`); adding an entry here is a review decision that needs its
 * own one-line justification, exactly like these.
 *
 * The justifications describe what each call site does (all are visible in
 * the file itself); they are scope statements for this pin, not audits of the
 * named files.
 */
const GRANDFATHERED: ReadonlyMap<string, { count: number; why: string }> =
  new Map([
    ["agent-native/cooperative-surface.ts", { count: 2, why: "TTL/expiry comparisons on local capability records" }],
    ["agent-native/safety-base.ts", { count: 1, why: "expiry comparison on a local binding" }],
    ["anomaly-detection/detectors/audit-event-class-distribution-detector.ts", { count: 1, why: "windowing of locally-persisted audit entries" }],
    ["anomaly-detection/feature-extractors/credential-use-sequence.ts", { count: 1, why: "ordering of locally-persisted audit entries" }],
    ["anomaly-detection/feature-extractors/cross-agent-timing.ts", { count: 1, why: "ordering of locally-persisted audit entries" }],
    ["anomaly-detection/feature-extractors/time-of-day-activity.ts", { count: 1, why: "ordering of locally-persisted audit entries" }],
    ["attestation/attestation-event.ts", { count: 1, why: "shape check on an event timestamp field" }],
    ["auto-trigger/calibration-suggester.ts", { count: 1, why: "suppressed-until comparison on local config" }],
    ["auto-trigger/promotion-criteria.ts", { count: 3, why: "ordering of locally-observed events" }],
    ["castle-wall/observe/refresh.ts", { count: 3, why: "epoch-ms conversion of locally-recorded review stamps" }],
    ["castle-wall/observe/store.ts", { count: 2, why: "shape checks on persisted metadata" }],
    ["chat/agent-context-cache.ts", { count: 1, why: "last-activity ordering for a local cache" }],
    ["chat/operator-chat-service.ts", { count: 1, why: "ordering of local chat entries" }],
    ["cli/audit.ts", { count: 3, why: "operator-typed search bounds + entry filtering (CLI)" }],
    ["cli/license.ts", { count: 1, why: "expiry parse of a license field (CLI display)" }],
    ["cognitive/state-store.ts", { count: 1, why: "round-trip equality check (exact-form by construction)" }],
    ["coordination/workflow-grouper.ts", { count: 3, why: "ordering of locally-observed events" }],
    ["dashboard/v1_1/client.ts", { count: 4, why: "display filtering in the dashboard client" }],
    ["disclosure/broker/token-issuer.ts", { count: 2, why: "expiry comparisons on locally-issued bindings" }],
    ["egress-gate/arming-wiring.ts", { count: 1, why: "subprocess lstart parsing, LC_ALL=C pinned (MED-4)" }],
    ["entitlement/fleet-cap.ts", { count: 1, why: "expiry comparison on a locally-verified activation" }],
    ["evidence-pack/inventory.ts", { count: 3, why: "shape/ordering checks on pack metadata" }],
    ["exit/v2-memory-archive.ts", { count: 1, why: "round-trip equality check (exact-form by construction)" }],
    ["handshake/attestation.ts", { count: 2, why: "expiry/issuance comparisons on a verified attestation body" }],
    ["honeypot/tool-call-trap-runtime.ts", { count: 3, why: "ages/ordering of local activation records" }],
    ["intelligence/selector.ts", { count: 1, why: "cutoff filtering of local entries" }],
    ["memory-checkpoint/retention.ts", { count: 2, why: "retention-expiry comparisons on local records" }],
    ["mesh/envelope.ts", { count: 1, why: "ULID event-id timestamp with an explicit Date.now fallback" }],
    ["mesh/lifecycle/durable-claim-set-store.ts", { count: 1, why: "expiry sweep of stored claims" }],
    ["mesh/lifecycle/local-state.ts", { count: 2, why: "valid_from/valid_until comparisons on stored records" }],
    ["mesh/lifecycle/operator-cloud-join-approver.ts", { count: 1, why: "expiry comparison on a verified claim" }],
    ["mesh/lifecycle/standalone-join-approver.ts", { count: 1, why: "expiry comparison on a verified token" }],
    ["mesh/trust-root-hybrid.ts", { count: 1, why: "certificate expiry comparison" }],
    ["mesh/trust-root.ts", { count: 2, why: "certificate expiry comparisons" }],
    ["operational/audit-log.ts", { count: 1, why: "ordering of local audit entries" }],
    ["policy-engine/canonical-policy.ts", { count: 1, why: "shape check on a compiled_at field" }],
    ["policy-engine/english-policy-routes.ts", { count: 2, why: "since-filtering of local compile history" }],
    ["policy-engine/envelope.ts", { count: 1, why: "validUntil default derivation" }],
    ["principal-policy/approval-aggregator.ts", { count: 9, why: "ordering/windowing of local approval entries" }],
    ["principal-policy/dashboard.ts", { count: 1, why: "remaining-time display for break-glass" }],
    ["principal-policy/feature-health.ts", { count: 3, why: "ordering of local health entries" }],
    ["principal-policy/fleet-roster.ts", { count: 2, why: "roster receive-time ordering" }],
    ["principal-policy/gate.ts", { count: 1, why: "expiry comparison on a stored envelope" }],
    ["principal-policy/plugin-feature-health.ts", { count: 1, why: "ordering of local health entries" }],
    ["principal-policy/posture.ts", { count: 3, why: "ordering of local posture entries" }],
    ["principal-policy/unified-inbox-bridge.ts", { count: 6, why: "time-range/snooze filtering of local inbox entries" }],
    ["principal-policy/unified-inbox-retention-policy.ts", { count: 1, why: "retention anchor on local entries" }],
    ["recognition/did-web.ts", { count: 6, why: "DID document validity-window arithmetic" }],
    ["sentinel/sentinels/anomaly-trigger.ts", { count: 1, why: "ordering of local findings" }],
    ["sentinel/sentinels/cross-agent-chatter-watcher.ts", { count: 2, why: "ordering of local audit entries" }],
    ["sentinel/sentinels/suspicious-tool-call-detector.ts", { count: 1, why: "windowing of local audit entries" }],
    ["sovereignty-profile.ts", { count: 1, why: "shape check on an updated_at field" }],
    ["supervisor/supervisor.ts", { count: 1, why: "age computation on a local enforcement stamp" }],
    ["transparency/emitter.ts", { count: 1, why: "ordering of local acquisition stamps" }],
    ["v1/federation-guardian-disable-gate.ts", { count: 1, why: "completion-time comparison on a locally-initiated flow" }],
    ["v1/federation-policy-bundle.ts", { count: 1, why: "shape check on a signed_at field" }],
    ["v1/federation-revocation.ts", { count: 3, why: "shape checks + certificate expiry comparison" }],
    ["v1/federation-sync-state-store.ts", { count: 1, why: "shape check on a persisted pair" }],
    ["v1/operator-authorization-spent-store.ts", { count: 1, why: "expiry comparison on a spent-store entry" }],
    ["v1/operator-signed.ts", { count: 2, why: "issuance/expiry comparisons on an operator-signed envelope" }],
    ["wrap/cli.ts", { count: 4, why: "ordering/filtering of local log entries" }],
  ]);

describe("TZ-SIB strict-offset adoption (server-wide pin)", () => {
  it("the predicate and its pattern are defined exactly ONCE, in core/time.ts", () => {
    // One definition is the rule-5 half: a second hand-written copy of the
    // strict check is the hand-mirror shape that drifts. The pattern constant
    // is pinned too, so the looser rule cannot return as a private regex next
    // to a private parse.
    const definitionRe =
      /function\s+parseIsoInstantWithOffset\s*\(|(?:const|let|var)\s+parseIsoInstantWithOffset\b/g;
    const patternRe = /(?:const|let|var)\s+ISO_INSTANT_WITH_OFFSET_RE\b/g;
    let definitionSites = 0;
    for (const abs of walk(SERVER_SRC)) {
      const rel = abs.slice(SERVER_SRC.length + 1);
      const code = readCode(rel);
      const definitions = code.match(definitionRe) ?? [];
      const patterns = code.match(patternRe) ?? [];
      if (definitions.length > 0 || patterns.length > 0) {
        expect(
          rel,
          `parseIsoInstantWithOffset / its pattern defined outside ${PREDICATE_FILE}`
        ).toBe(PREDICATE_FILE);
        definitionSites += definitions.length;
      }
    }
    expect(definitionSites).toBe(1);
  });

  it("TZ-SIB-01: the DMswitch gate reads its stamp through the predicate, BY NAME", () => {
    const code = readCode("mesh/recovery-flows/dmswitch.ts");
    // The import half of the cross-file contract (the export half is the
    // definition pin above).
    expect(code).toMatch(
      /import \{ parseIsoInstantWithOffset \} from "\.\.\/\.\.\/core\/time\.js";/
    );
    // By name: the exact argument spelling, so swapping the call onto some
    // other field cannot stay green.
    expect(code).toMatch(
      /parseIsoInstantWithOffset\(\s*params\.last_operator_activity_at\s*\)/
    );
    // Zero bare Date.parse — enforced again by the freeze below, asserted here
    // so a failure names the adopted site directly.
    expect(code.match(/Date\.parse\s*\(/g) ?? []).toHaveLength(0);
  });

  it("TZ-SIB-02: the prompt ordering reads BOTH stamps through the predicate, BY NAME", () => {
    const code = readCode("mesh/guardian/recovery-prompt.ts");
    expect(code).toMatch(
      /import \{ parseIsoInstantWithOffset \} from "\.\.\/\.\.\/core\/time\.js";/
    );
    for (const spelling of ["state.rotated_at", "latest.rotated_at"]) {
      expect(
        code.includes(`parseIsoInstantWithOffset(${spelling})`),
        `no parseIsoInstantWithOffset call passes ${spelling}`
      ).toBe(true);
    }
    expect(code.match(/Date\.parse\s*\(/g) ?? []).toHaveLength(0);
  });

  it("server-wide freeze: every executable Date.parse is the predicate's own, or grandfathered at its exact count", () => {
    const seen = new Map<string, number>();
    for (const abs of walk(SERVER_SRC)) {
      const rel = abs.slice(SERVER_SRC.length + 1);
      const count = (readCode(rel).match(/Date\.parse\s*\(/g) ?? []).length;
      if (count > 0) seen.set(rel, count);
    }

    // The predicate's own parse: exactly one, and it sits inside the function
    // (after the shape test), which is what makes it strict rather than bare.
    expect(seen.get(PREDICATE_FILE)).toBe(1);
    const predicateCode = readCode(PREDICATE_FILE);
    const fnStart = predicateCode.indexOf(
      "export function parseIsoInstantWithOffset"
    );
    expect(fnStart).toBeGreaterThan(0);
    expect(predicateCode.indexOf("Date.parse")).toBeGreaterThan(fnStart);
    seen.delete(PREDICATE_FILE);

    // No NEW site, no count creep: a file not in the table, or above its
    // recorded count, fails here. Route the new parse through
    // parseIsoInstantWithOffset (core/time.ts), or add a justified entry in
    // review.
    for (const [rel, count] of seen) {
      const entry = GRANDFATHERED.get(rel);
      expect(
        entry,
        `new bare Date.parse in ${rel} (${count} site${count === 1 ? "" : "s"}) — use parseIsoInstantWithOffset from core/time.ts`
      ).toBeDefined();
      expect(
        count,
        `Date.parse count changed in ${rel}: recorded ${entry?.count}, found ${count} — adopt the predicate or update the entry in review`
      ).toBe(entry?.count);
    }

    // The ratchet's other face: an entry whose file dropped its calls (or was
    // moved/deleted) is stale and must be removed, so the table only shrinks.
    for (const [rel, entry] of GRANDFATHERED) {
      expect(
        seen.get(rel),
        `stale grandfathered entry for ${rel} (recorded ${entry.count}) — remove or update it`
      ).toBe(entry.count);
      expect(entry.why.length).toBeGreaterThan(0);
    }
  });
});
