/**
 * Canonical CompiledPolicy shape — encode/decode, schema enforcement,
 * four-slot invariant.
 */

import { describe, expect, it } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import {
  CompiledPolicyShapeError,
  PolicyBlobDecodeError,
} from "../../src/policy-engine/errors.js";
import {
  decodePolicyBlob,
  encodePolicyBlob,
  validateCompiledPolicyShape,
} from "../../src/policy-engine/canonical-policy.js";
import { buildNullPolicy } from "../../src/policy-engine/null-policy.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";

describe("policy-engine/canonical-policy — shape check", () => {
  it("accepts a valid null policy", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    expect(() => validateCompiledPolicyShape(p)).not.toThrow();
  });

  it("rejects a policy with only three slots", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" }) as unknown as Record<
      string,
      unknown
    >;
    delete (p.slots as Record<string, unknown>).outputs;
    expect(() => validateCompiledPolicyShape(p)).toThrow(CompiledPolicyShapeError);
  });

  it("rejects a policy that adds a fifth slot", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" }) as unknown as Record<
      string,
      unknown
    >;
    (p.slots as Record<string, unknown>).emails = {
      slot: "emails",
      mode: "deny",
      grants: [],
    };
    expect(() => validateCompiledPolicyShape(p)).toThrow(CompiledPolicyShapeError);
  });

  it("rejects deny-mode rule that carries grants", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    p.slots.memory.grants.push({ counterparty: "a2", action: "read" });
    expect(() => validateCompiledPolicyShape(p)).toThrow(CompiledPolicyShapeError);
  });

  it("rejects unknown schema_version", () => {
    const p = buildNullPolicy({
      agent_id: "a1",
      fortress_id: "f1",
    }) as unknown as CompiledPolicy & { schema_version: string };
    (p as unknown as { schema_version: string }).schema_version = "0.2";
    expect(() => validateCompiledPolicyShape(p)).toThrow(CompiledPolicyShapeError);
  });

  it("rejects negative policy_version", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    (p as unknown as { policy_version: number }).policy_version = -1;
    expect(() => validateCompiledPolicyShape(p)).toThrow(CompiledPolicyShapeError);
  });
});

describe("policy-engine/canonical-policy — encode/decode round-trip", () => {
  it("round-trips the null policy byte-identically", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    const blob = encodePolicyBlob(p);
    const decoded = decodePolicyBlob(blob);
    expect(decoded).toEqual(p);
    expect(encodePolicyBlob(decoded)).toBe(blob);
  });

  it("produces a stable digest independent of key insertion order", () => {
    const p1 = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    const p2: CompiledPolicy = {
      compiled_at: p1.compiled_at,
      source_english: p1.source_english,
      auto_trigger_ladder: { ...p1.auto_trigger_ladder },
      capabilities: { ...p1.capabilities },
      slots: { ...p1.slots },
      policy_version: p1.policy_version,
      fortress_id: p1.fortress_id,
      agent_id: p1.agent_id,
      schema_version: p1.schema_version,
    };
    expect(encodePolicyBlob(p1)).toBe(encodePolicyBlob(p2));
  });

  it("rejects a tampered base64url blob", () => {
    // `!!!` is not valid base64url alphabet — decoder throws.
    expect(() => decodePolicyBlob("!!!not-base64url!!!")).toThrow(PolicyBlobDecodeError);
  });

  it("rejects a blob whose JSON parses but fails shape check", () => {
    const blob = toBase64url(new TextEncoder().encode('{"not":"a policy"}'));
    expect(() => decodePolicyBlob(blob)).toThrow();
  });
});
