/**
 * Sanctuary v1.1 Acceptance Drill - Pillar 3: Internal Coordination.
 *
 * Proves that two wrapped agents can complete a local handoff with signed
 * Layer 1 records, signed Layer 2 audit-payload transitions, deterministic
 * lifecycle reconstruction, and policy-gate denial without any record
 * being persisted on deny. Plus a structural sub-drill that asserts the
 * coordination module's import graph contains zero Concordia or Verascore
 * references.
 *
 * The drill builds on the existing real-crypto coordination fixture
 * (`server/test/coordination/fixture.ts`) so signing, persistence, and
 * audit emission all run end-to-end. No mocks at the contract boundary.
 *
 * Acceptance checklist mapping: Pillar 3 of
 * `server/docs/v1.1-acceptance-checklist.md`.
 */

import { describe, expect, it } from "vitest";
import { dirname, isAbsolute, join, normalize, relative } from "node:path";
import { existsSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  type CoordinationGateDecision,
  type CoordinationPolicyGate,
  verifyAuditPayload,
  verifyHandoffRecord,
} from "../../src/coordination/index.js";
import { buildCoordinationFixture } from "../coordination/fixture.js";

function freshTaskScope() {
  return {
    category: "delegate_subtask" as const,
    requested_capabilities: ["plans", "outputs"],
    priority: "normal" as const,
  };
}

function freshContextRef() {
  return {
    policy_context_id: "drill-pc-1",
    audit_entry_id: "drill-ae-1",
    placeholder_refs: [],
  };
}

function gate(decision: CoordinationGateDecision): CoordinationPolicyGate {
  return { evaluateContextTransfer: () => decision };
}

describe("v1.1 acceptance drill - Pillar 3: internal coordination lifecycle", () => {
  it("propose -> accept -> complete with verified signatures and signature_scheme inside the signed bytes at every stage", async () => {
    const f = buildCoordinationFixture();

    // Step 1: sender proposes.
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    expect(proposed.status).toBe("created");
    expect(proposed.record).toBeDefined();
    const record = proposed.record!;
    expect(record.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(record.signature_scheme).toBe("ed25519-v1");
    expect(verifyHandoffRecord(record, f.keyResolver)).toBe(true);
    expect(proposed.audit_payload.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(proposed.audit_payload, f.keyResolver)).toBe(
      true,
    );
    expect(proposed.audit_payload.actor_role).toBe("sender");
    expect(proposed.audit_payload.actor_id).toBe(f.sender.agent_id);
    expect(proposed.audit_payload.previous_status).toBe("created");
    expect(proposed.audit_payload.new_status).toBe("created");

    // Step 2: recipient accepts.
    const accepted = await f.coordinator.acceptHandoff({
      handoff_id: record.handoff_id,
      recipient: f.recipient.signer,
    });
    expect(accepted.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(accepted, f.keyResolver)).toBe(true);
    expect(accepted.actor_role).toBe("recipient");
    expect(accepted.actor_id).toBe(f.recipient.agent_id);
    expect(accepted.previous_status).toBe("created");
    expect(accepted.new_status).toBe("accepted");

    // Step 3: recipient completes.
    const completed = await f.coordinator.completeHandoff({
      handoff_id: record.handoff_id,
      recipient: f.recipient.signer,
      completion_audit_ref: "drill-completion-1",
    });
    expect(completed.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(completed, f.keyResolver)).toBe(true);
    expect(completed.actor_role).toBe("recipient");
    expect(completed.previous_status).toBe("accepted");
    expect(completed.new_status).toBe("completed");

    // Persisted state reflects completion.
    const persisted = await f.coordinator.getHandoff(record.handoff_id);
    expect(persisted?.status).toBe("completed");

    // Lifecycle audit chain is reconstructable in deterministic order.
    expect(accepted.previous_status).toBe(proposed.audit_payload.new_status);
    expect(completed.previous_status).toBe(accepted.new_status);

    // The Layer 1 record's verifyHandoffRecord and the Layer 2 audit
    // payload's verifyAuditPayload BOTH carry signature_scheme inside
    // the signed bytes - substituting the scheme post-sign breaks
    // verification. (Substitution-resistance is asserted in detail in
    // server/test/coordination/lifecycle.test.ts; this drill asserts the
    // happy path while documenting the cross-scheme guard.)
  });
});

describe("v1.1 acceptance drill - Pillar 3 policy-gate sub-drill", () => {
  it("policy deny short-circuits handoff creation: no record persisted, signed operator denial emitted with actor_role=policy_gate", async () => {
    const f = buildCoordinationFixture({
      policyGate: gate({ decision: "deny", reason_code: "no_matching_grant" }),
    });

    const result = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["credentials"],
        priority: "normal",
      },
      context_reference: freshContextRef(),
      operator: f.operator.signer,
    });

    expect(result.status).toBe("denied");
    expect(result.record).toBeUndefined();
    expect(result.audit_payload.actor_role).toBe("policy_gate");
    expect(result.audit_payload.actor_id).toBe(f.operator.identity_id);
    expect(result.audit_payload.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(result.audit_payload, f.keyResolver)).toBe(true);

    // Generic denial reason: machine-friendly token, no policy-rule
    // disclosure to the agent.
    expect(result.audit_payload.reason_class).toBe("policy_deny");

    // No persisted handoff on deny.
    const persisted = await f.coordinator.listHandoffs();
    expect(persisted).toHaveLength(0);
  });
});

describe("v1.1 acceptance drill - Pillar 3 non-Concordia-dependency sub-drill", () => {
  /**
   * Structural assertion mirroring
   * server/test/coordination/no-concordia-dependency.test.ts: the
   * coordination workstream MUST NOT import from concordia, the
   * Sanctuary↔Concordia bridge module, or the composition layer.
   *
   * The acceptance drill carries this check so a future build thread
   * cannot regress the non-dependency invariant by deleting the original
   * test in isolation.
   */
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const SRC_ROOT = join(__dirname, "../../src");
  const ENTRY = join(SRC_ROOT, "coordination/index.ts");

  const FORBIDDEN_PATH_FRAGMENTS = [
    "/concordia/",
    "/sidecars/concordia/",
    "/bridge/",
    "/composition/",
  ];
  const FORBIDDEN_BARE_PACKAGES = [
    "concordia",
    "concordia-protocol",
    "@concordia/",
    "verascore",
  ];

  function resolveImport(fromFile: string, spec: string): string | null {
    if (!spec.startsWith(".") && !isAbsolute(spec)) return null;
    const base = spec.startsWith(".") ? join(dirname(fromFile), spec) : spec;
    const candidates = [
      base,
      base.replace(/\.js$/, ".ts"),
      base.replace(/\.js$/, ".tsx"),
      base + ".ts",
      base + ".tsx",
      join(base, "index.ts"),
    ];
    for (const c of candidates) {
      if (existsSync(c) && statSync(c).isFile()) return normalize(c);
    }
    return null;
  }

  function extractImports(source: string): string[] {
    const out: string[] = [];
    const reImport = /import\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g;
    const reExport = /export\s+(?:[\s\S]+?)\s+from\s+["']([^"']+)["']/g;
    for (const m of source.matchAll(reImport)) out.push(m[1]!);
    for (const m of source.matchAll(reExport)) out.push(m[1]!);
    return out;
  }

  it("the entire coordination import graph is free of Concordia/Verascore/bridge/composition references", () => {
    const visited = new Set<string>();
    const queue: string[] = [normalize(ENTRY)];
    const violations: Array<{ file: string; specifier: string }> = [];

    while (queue.length > 0) {
      const file = queue.shift()!;
      if (visited.has(file)) continue;
      visited.add(file);
      const source = readFileSync(file, "utf8");
      for (const spec of extractImports(source)) {
        for (const pkg of FORBIDDEN_BARE_PACKAGES) {
          if (spec === pkg || spec.startsWith(`${pkg}/`)) {
            violations.push({ file: relative(SRC_ROOT, file), specifier: spec });
          }
        }
        const resolved = resolveImport(file, spec);
        if (resolved) {
          const norm = resolved.replace(/\\/g, "/");
          for (const frag of FORBIDDEN_PATH_FRAGMENTS) {
            if (norm.includes(frag)) {
              violations.push({
                file: relative(SRC_ROOT, file),
                specifier: spec,
              });
            }
          }
          if (!visited.has(resolved)) queue.push(resolved);
        }
      }
    }

    expect(violations).toEqual([]);
  });
});
