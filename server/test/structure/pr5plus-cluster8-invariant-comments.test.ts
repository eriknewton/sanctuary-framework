import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function nthIndexOf(source: string, needle: string, occurrence: number): number {
  let from = 0;
  for (let i = 0; i <= occurrence; i += 1) {
    const found = source.indexOf(needle, from);
    if (found === -1) return -1;
    if (i === occurrence) return found;
    from = found + needle.length;
  }
  return -1;
}

function around(source: string, anchor: string, occurrence = 0): string {
  const index = nthIndexOf(source, anchor, occurrence);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 1_000), index + anchor.length + 1_200);
}

function expectNear(
  source: string,
  anchor: string,
  snippets: readonly string[],
  occurrence = 0
): void {
  const window = around(source, anchor, occurrence);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("PR-5+ cluster-8 invariant comment hygiene", () => {
  it("keeps recognition DID and hosted-registry trust boundaries documented", () => {
    const didWeb = read("server/src/recognition/did-web.ts");
    const hostedRegistry = read("server/src/recognition/did-web-hosted-registry.ts");
    const hostedRoute = read("server/src/recognition/did-web-hosted-route.ts");

    expectNear(didWeb, "if (unsafeHost !== undefined) {", [
      "refused before fetch",
      "cannot steer resolution to local or private infrastructure",
    ]);
    expectNear(didWeb, "const selected = selectVerificationMethod(", [
      "caller-pinned",
      "expected assertion key",
    ]);
    expectNear(didWeb, "if (v[\"id\"] !== expectedDid) return false;", [
      "requested DID before any verification method",
    ]);
    expectNear(hostedRegistry, "if (persisted.fortress_id !== this.fortressId) return null;", [
      "AAD and the inner fortress_id must both match",
      "copied from another fortress reads as absent",
    ]);
    expectNear(hostedRoute, "if (!entry) {", [
      "wrong-fortress ciphertext",
      "never serves unverified fallback data",
    ]);
  });

  it("keeps security scanner recommendation and normalization boundaries documented", () => {
    const source = read("server/src/security/injection-detector.ts");

    expectNear(source, "if (!this.config.enabled) {", [
      "explicit operator configuration",
      "not a detector inference",
    ]);
    expectNear(source, "const stripped = this.stripInvisibleChars(value);", [
      "stripped plus confusable-normalized text",
      "cannot preserve a bypass phrase",
    ]);
    expectNear(source, "if (signals.length === 0) {", [
      "every enabled scanner produced no signal",
      "not derived from caller-provided recommendation text",
    ]);
    expectNear(source, "case \"low\":", [
      "only policy mode that tolerates medium/low signals",
      "still escalates any high signal",
    ]);
  });

  it("keeps disclosure proof, policy, broker, and keychain boundaries documented", () => {
    const commitments = read("server/src/disclosure/commitments.ts");
    const policies = read("server/src/disclosure/policies.ts");
    const zkProofs = read("server/src/disclosure/zk-proofs.ts");
    const tokenIssuer = read("server/src/disclosure/broker/token-issuer.ts");
    const broker = read("server/src/disclosure/broker/broker.ts");
    const keychain = read("server/src/disclosure/broker/keychain-backend.ts");
    const open = read("server/src/disclosure/broker/open.ts");

    expectNear(commitments, "return constantTimeEqual(commitmentBytes, expectedBytes);", [
      "recomputes SHA-256(value || blinding)",
      "never trusted",
    ]);
    expectNear(policies, "if (matchedRule.withhold.includes(field)) {", [
      "explicit deny cannot be weakened",
    ]);
    expectNear(zkProofs, "const e = fiatShamirChallenge(", [
      "cannot choose its own challenge",
    ], 1);
    expectNear(tokenIssuer, "if (req.skill !== req.caller.skill) {", [
      "verified caller claims",
      "cannot mint a token for another skill",
    ]);
    expectNear(tokenIssuer, "const grant = this.grants.get(grantKey(binding.skill, binding.secret));", [
      "Re-check the live grant on every read",
      "cannot outlive a revoked or narrowed policy",
    ]);
    expectNear(broker, "const redacted = entries.map((e) => redactAuditEntryForAgent(e));", [
      "secret names, and denial reasons never reach agent audit reads",
    ]);
    expectNear(keychain, "validateSecretName(name);", [
      "cannot inject args or poison dump parsing",
    ]);
    expectNear(open, "return [];", [
      "zero grants",
      "denies access instead of allowing all",
    ]);
  });

  it("keeps attestation event, badge, catalog, and custody-stub boundaries documented", () => {
    const events = read("server/src/attestation/attestation-event.ts");
    const service = read("server/src/attestation/attestation-service.ts");
    const badges = read("server/src/attestation/badge-state.ts");
    const catalog = read("server/src/attestation/failure-catalog.ts");
    const custody = read("server/src/attestation/custody-provenance-stub.ts");

    expectNear(events, "if (!event.event_type.startsWith(ATTESTATION_EVENT_TYPE_PREFIX)) {", [
      "attestation-scoped",
      "federation envelope",
    ]);
    expectNear(events, "if (payload.event_type !== evt.event_type) {", [
      "inner and outer event types must match",
      "applying another",
    ]);
    expectNear(service, "state: result.state,", [
      "Processing failures degrade into an explicit badge",
      "never a throw or an implicit green",
    ]);
    expectNear(badges, "return makeBadge(\"offline\", \"global\", fortress_id, [], \"global.no_data\");", [
      "absence of attestation evidence never becomes a healthy badge",
    ]);
    expectNear(catalog, "throw new FailureCatalogInvariantError(", [
      "Catalog drift fails at import",
      "malformed failure table",
    ]);
    expectNear(custody, "state: \"unknown_custody\",", [
      "without the adapter it must never claim sovereign provenance",
    ]);
  });
});
