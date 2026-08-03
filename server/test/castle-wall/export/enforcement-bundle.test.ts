/**
 * Hermetic tests for the pure enforcement-evidence bundle body builder.
 *
 * These tests use an injected producer-signature verifier, a fixed clock, and
 * synthetic AuditEntry rows. They touch no filesystem, network, or real keys.
 */

import { describe, expect, it } from "vitest";

import type { AuditEntry } from "../../../src/operational/audit-log.js";
import type { VerifyProducerSignatureFn } from "../../../src/castle-wall/audit-attribution.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import {
  buildEnforcementBundleBody,
  ENFORCEMENT_BUNDLE_CLAIMS_SCOPE,
  ENFORCEMENT_BUNDLE_SCHEMA,
  ENFORCEMENT_BUNDLE_TYP,
  type BuildEnforcementBundleOptions,
} from "../../../src/castle-wall/export/index.js";

const SUBJECT_FORTRESS_ID = "fortress:test";
const AGENT_SUBJECT = `${SUBJECT_FORTRESS_ID}/uid-503`;
const PINNED_PRODUCER_KEY = "pinned-producer-key";
const ROW_KID = "cw-row-kid";
const ENVELOPE_KID = "bundle-kid";
const CAPTURED_AT_MS = 1_777_777_777_777;
const GENERATED_AT = new Date("2026-08-03T12:00:00.000Z");

const verifyProducerSignature: VerifyProducerSignatureFn = (
  input,
  pinnedProducerKeyB64url,
) => {
  if (
    pinnedProducerKeyB64url === PINNED_PRODUCER_KEY &&
    typeof input.signatureB64url === "string" &&
    input.signatureB64url.startsWith("sig:valid:")
  ) {
    return { ok: true };
  }
  return { ok: false, reason: "test verifier rejected signature" };
};

function bundleOptions(
  overrides: Partial<BuildEnforcementBundleOptions> = {},
): BuildEnforcementBundleOptions {
  return {
    producer: "sanctuary.castle-wall",
    kid: ENVELOPE_KID,
    now: () => GENERATED_AT,
    mapOptions: {
      pinnedProducerKeyB64url: PINNED_PRODUCER_KEY,
      subjectFortressId: SUBJECT_FORTRESS_ID,
      verifyProducerSignature,
    },
    ...overrides,
  };
}

function withProducerEvidence(
  entry: AuditEntry,
  seq: number,
  signature: string = `sig:valid:${seq}`,
): AuditEntry {
  const signedBody: AuditEntry = {
    ...entry,
    identity_id: AGENT_SUBJECT,
    details: { ...(entry.details ?? {}) },
  };
  const signedCanonical = JSON.stringify(signedBody);
  return {
    ...signedBody,
    details: {
      ...(signedBody.details ?? {}),
      [CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY]: seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: signature,
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: ROW_KID,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: signedCanonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: CAPTURED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

function egressDeny(
  seq: number,
  extraDetails: Record<string, unknown> = {},
): AuditEntry {
  return withProducerEvidence(
    {
      timestamp: "2026-08-03T10:00:00.000Z",
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "system",
      result: "failure",
      details: {
        dest_host: "evil.example.com",
        dest_ip: "203.0.113.10",
        dest_port: 443,
        dest_protocol: "tcp",
        rule_id: "rule-deny-evil",
        agent_template: "coding-assistant",
        ...extraDetails,
      },
    },
    seq,
  );
}

function egressAllow(seq: number): AuditEntry {
  return withProducerEvidence(
    {
      timestamp: "2026-08-03T10:01:00.000Z",
      layer: "l1",
      operation: "egress_allowed",
      identity_id: "system",
      result: "success",
      details: {
        destination: {
          host: "api.example.com",
          ip: "198.51.100.20",
          port: 443,
          protocol: "tcp",
        },
        rule_id: "rule-allow-api",
        agent: { template: "coding-assistant" },
      },
    },
    seq,
  );
}

function unsignedEgressDeny(): AuditEntry {
  return {
    timestamp: "2026-08-03T10:02:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: AGENT_SUBJECT,
    result: "failure",
    details: {
      dest_host: "unsigned.example.com",
      dest_port: 443,
      dest_protocol: "tcp",
      rule_id: "rule-unsigned",
      agent_template: "coding-assistant",
    },
  };
}

describe("buildEnforcementBundleBody", () => {
  it("emits rule-attributed records with producer evidence and measured summary counts", () => {
    const deny = egressDeny(10);
    const allow = egressAllow(11);

    const bundle = buildEnforcementBundleBody([deny, allow], bundleOptions());

    expect(bundle).toMatchObject({
      typ: ENFORCEMENT_BUNDLE_TYP,
      schema: ENFORCEMENT_BUNDLE_SCHEMA,
      producer: "sanctuary.castle-wall",
      kid: ENVELOPE_KID,
      key_distribution: null,
      generated_at: "2026-08-03T12:00:00.000Z",
      claims_scope: ENFORCEMENT_BUNDLE_CLAIMS_SCOPE,
      summary: { total: 2, allow: 1, deny: 1 },
    });
    expect(bundle.records).toHaveLength(2);
    expect(bundle.records[0]).toMatchObject({
      timestamp: "2026-08-03T10:00:00.000Z",
      decision: "deny",
      destination_host: "evil.example.com",
      destination_ip: "203.0.113.10",
      destination_port: 443,
      destination_protocol: "tcp",
      rule_id: "rule-deny-evil",
      agent_id: AGENT_SUBJECT,
      agent_template: "coding-assistant",
      enforcement_point: "castle_wall",
    });
    expect(bundle.records[1]).toMatchObject({
      decision: "allow",
      destination_host: "api.example.com",
      destination_ip: "198.51.100.20",
      rule_id: "rule-allow-api",
    });
    expect(bundle.records[0].producer_evidence).toEqual({
      signed_canonical:
        deny.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY],
      signature: "sig:valid:10",
      kid: ROW_KID,
      seq: 10,
      captured_at_ms: CAPTURED_AT_MS,
    });
    expect(Object.keys(bundle.records[0].producer_evidence).sort()).toEqual(
      ["captured_at_ms", "kid", "seq", "signature", "signed_canonical"].sort(),
    );
  });

  it("drops unsigned rows and rows rejected by the injected verifier", () => {
    const valid = egressDeny(20);
    const forged = withProducerEvidence(
      {
        timestamp: "2026-08-03T10:03:00.000Z",
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "system",
        result: "success",
        details: {
          dest_host: "forged.example.com",
          dest_port: 443,
          dest_protocol: "tcp",
          rule_id: "rule-forged",
        },
      },
      21,
      "sig:forged",
    );

    const bundle = buildEnforcementBundleBody(
      [valid, unsignedEgressDeny(), forged],
      bundleOptions(),
    );

    expect(bundle.records).toHaveLength(1);
    expect(bundle.records[0].destination_host).toBe("evil.example.com");
    expect(JSON.stringify(bundle)).not.toContain("unsigned.example.com");
    expect(JSON.stringify(bundle)).not.toContain("forged.example.com");
  });

  it("keeps a redacted rule id redacted instead of laundering a sibling rule id", () => {
    const redacted = egressDeny(30, {
      rule_id: "[redacted]",
      rule_id_matched: "rule-should-not-be-laundered",
    });

    const bundle = buildEnforcementBundleBody([redacted], bundleOptions());

    expect(bundle.records).toHaveLength(1);
    expect(bundle.records[0].rule_id).toBeNull();
  });

  it("drops producer-signed rows whose verbatim evidence would leak forbidden details", () => {
    const secretValue = "SECRET-DO-NOT-LEAK";
    const dirtyButSigned = egressDeny(40, {
      namespace_payload: secretValue,
      private_key: secretValue,
      policy_text: secretValue,
      reason: secretValue,
    });
    const clean = egressAllow(41);

    const bundle = buildEnforcementBundleBody(
      [dirtyButSigned, clean],
      bundleOptions(),
    );
    const serialized = JSON.stringify(bundle);

    expect(bundle.records).toHaveLength(1);
    expect(bundle.records[0].destination_host).toBe("api.example.com");
    for (const forbidden of [
      "namespace_payload",
      "private_key",
      "policy_text",
      "reason",
      secretValue,
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(Object.keys(bundle.records[0]).sort()).toEqual(
      [
        "agent_id",
        "agent_template",
        "decision",
        "destination_host",
        "destination_ip",
        "destination_port",
        "destination_protocol",
        "enforcement_point",
        "producer_evidence",
        "rule_id",
        "timestamp",
      ].sort(),
    );
  });

  it("preserves key_distribution as null when absent and as the exact supplied string", () => {
    const withoutDistribution = buildEnforcementBundleBody([], bundleOptions());
    const withDistribution = buildEnforcementBundleBody(
      [],
      bundleOptions({
        keyDistribution: "https://keys.example.com/.well-known/jwks.json",
      }),
    );

    expect(withoutDistribution.key_distribution).toBeNull();
    expect(withDistribution.key_distribution).toBe(
      "https://keys.example.com/.well-known/jwks.json",
    );
  });
});
