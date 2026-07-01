/**
 * Tunability UX: promote-to-standing-rule + plain-English view route suite.
 *
 * EXPLICIT SECURITY GATES (mirrors the dashboard token-gate contract in
 * test/dashboard/v1_1/queue-approve-token-gate.test.ts):
 *
 *  1. A valid promote (compile "auto-allow <op>" -> activate) creates an
 *     ACTIVATED standing rule through the REAL EnglishPolicyActivator, not
 *     a stub: the live policy gains the operation on the Tier-3 always-allow
 *     list and an `english_policy_activated` audit event is emitted.
 *  2. An UNAUTHENTICATED promote (and a WRONG-bearer promote) is REJECTED at
 *     the operator-credential chokepoint (403) and mutates nothing, even
 *     with loopback auto-auth ON. Position on loopback is not authority.
 *  3. A posture-WEAKENING promote (moving a Tier-1 always-approve operation
 *     down to Tier-3 always-allow) is REFUSED by the #805 config-downgrade
 *     gate (`assertNoPrincipalPolicyDowngrade`); the live policy is
 *     unchanged and a `english_policy_write_refused` audit event fires. It
 *     is never silently applied.
 *  4. The plain-English GET /api/policy/current view is operator-bearer-
 *     gated the same way (agent-opaque, AGENTS.md hard rule 7).
 *
 * The route wiring under test is the SAME handleEnglishPolicyRoute the
 * dashboard mounts at /api/policy/*; the dashboard promote button issues
 * exactly these two requests via the bearer-carrying policyApi().
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { AuditLog, type AuditEntry } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { EnglishPolicyCompiler } from "../../src/policy-engine/english-policy-compiler.js";
import {
  EnglishPolicyActivator,
  PolicyActivationStore,
} from "../../src/policy-engine/english-policy-activator.js";
import {
  ENGLISH_POLICY_API_PREFIX,
  EnglishPolicyDraftStore,
  handleEnglishPolicyRoute,
} from "../../src/policy-engine/english-policy-routes.js";

const FORTRESS = "fortress_promote";
const OPERATOR = "operator_promote";
const TOKEN = "operator-bearer-secret";

/**
 * A live policy where `state_export` is NOT in Tier-1, so promoting a
 * NON-forced op ("read_the_almanac") is a clean posture-preserving add.
 * The base for the posture-weakening test uses DEFAULT_POLICY unchanged so
 * `state_export` genuinely sits in Tier-1 and the downgrade gate can fire.
 */
function policyWithoutStateExport(): PrincipalPolicy {
  const policy = JSON.parse(JSON.stringify(DEFAULT_POLICY)) as PrincipalPolicy;
  policy.tier1_always_approve = policy.tier1_always_approve.filter(
    (op) => op !== "state_export",
  );
  return policy;
}

interface Rig {
  base: string;
  auditLog: AuditLog;
  livePolicy: { current: PrincipalPolicy };
  close: () => Promise<void>;
}

async function startRig(opts?: { policy?: PrincipalPolicy }): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new PolicyActivationStore({ storage, masterKey, fortressId: FORTRESS });
  const livePolicy = { current: opts?.policy ?? policyWithoutStateExport() };
  const activator = new EnglishPolicyActivator({
    store,
    auditLog,
    fortressId: FORTRESS,
    readPolicy: async () => livePolicy.current,
    writePolicy: async (p) => {
      livePolicy.current = p;
    },
  });
  const compiler = new EnglishPolicyCompiler({
    auditLog,
    fortressId: FORTRESS,
    selector: null,
  });
  const draftStore = new EnglishPolicyDraftStore();

  const server: Server = createServer(async (req, res) => {
    // loopback auto-auth ON: a co-resident caller. The operator-credential
    // chokepoint on the sensitive routes must STILL require the bearer.
    const handled = await handleEnglishPolicyRoute(
      {
        authConfig: { loopbackAutoAuth: true, authToken: TOKEN },
        compiler,
        store: draftStore,
        activator,
        defaultOperatorId: OPERATOR,
      },
      req,
      res,
    );
    if (!handled) res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    auditLog,
    livePolicy,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function auditOps(auditLog: AuditLog): Promise<string[]> {
  const result = await auditLog.query({ layer: "l2", limit: 200 });
  return result.entries.map((e: AuditEntry) => e.operation);
}

/**
 * The two-step promote the dashboard issues: compile then activate. When
 * `overrideDowngrade` is set, the activate carries the explicit audited
 * override the client sends after the operator confirms a posture relaxation.
 */
async function promote(
  base: string,
  englishText: string,
  headers: Record<string, string>,
  overrideDowngrade = false,
): Promise<{ status: number; draftId?: string; body: unknown }> {
  const compileRes = await fetch(`${base}${ENGLISH_POLICY_API_PREFIX}/compile`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ english_text: englishText }),
  });
  const compileBody = (await compileRes.json()) as {
    data?: { draft?: { draft_id?: string } };
  };
  const draftId = compileBody.data?.draft?.draft_id;
  if (!draftId) {
    return { status: compileRes.status, body: compileBody };
  }
  const activateRes = await fetch(
    `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${encodeURIComponent(draftId)}/activate` +
      (overrideDowngrade ? "?override_downgrade=true" : ""),
    { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: "{}" },
  );
  return { status: activateRes.status, draftId, body: await activateRes.json() };
}

const OPERATOR_HEADERS = { Authorization: `Bearer ${TOKEN}` };

describe("tunability promote: a valid non-weakening promote creates an activated standing rule via the REAL activator", () => {
  it("compile 'require approval for <op>' -> activate lands the op on Tier-1 and emits an activation audit event", async () => {
    // Promoting an approval into a TIGHTENING standing rule (always route
    // this to me) is posture-preserving, so the #805 gate passes cleanly
    // with no override.
    const rig = await startRig();
    try {
      expect(rig.livePolicy.current.tier1_always_approve).not.toContain("send_the_newsletter");

      const result = await promote(rig.base, "require approval for send_the_newsletter", OPERATOR_HEADERS);
      expect(result.status).toBe(200);
      expect((result.body as { data: { status: string } }).data.status).toBe("activated");

      // The REAL activator mutated the live policy (no stub).
      expect(rig.livePolicy.current.tier1_always_approve).toContain("send_the_newsletter");

      // The promotion emitted a real activation audit event.
      const ops = await auditOps(rig.auditLog);
      expect(ops).toContain("english_policy_activated");
    } finally {
      await rig.close();
    }
  });
});

describe("tunability promote: auth chokepoint (#823-style) rejects tokenless / wrong-bearer promotes", () => {
  it("rejects a TOKENLESS activate with 403 even with loopback auto-auth on, and mutates nothing", async () => {
    const rig = await startRig();
    try {
      // Compile with the operator bearer so a draft exists, then attempt a
      // TOKENLESS activate: the mutation must be refused at the chokepoint.
      const compileRes = await fetch(`${rig.base}${ENGLISH_POLICY_API_PREFIX}/compile`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...OPERATOR_HEADERS },
        body: JSON.stringify({ english_text: "auto-allow read_the_almanac" }),
      });
      const draftId = ((await compileRes.json()) as { data: { draft: { draft_id: string } } })
        .data.draft.draft_id;

      const activateRes = await fetch(
        `${rig.base}${ENGLISH_POLICY_API_PREFIX}/drafts/${encodeURIComponent(draftId)}/activate`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
      );
      expect(activateRes.status).toBe(403);
      const body = (await activateRes.json()) as { error: string };
      expect(body.error).toBe("operator_auth_required");
      expect(rig.livePolicy.current.tier3_always_allow).not.toContain("read_the_almanac");
    } finally {
      await rig.close();
    }
  });

  it("rejects a WRONG-bearer activate with 403 (the token is actually checked), and mutates nothing", async () => {
    const rig = await startRig();
    try {
      const compileRes = await fetch(`${rig.base}${ENGLISH_POLICY_API_PREFIX}/compile`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...OPERATOR_HEADERS },
        body: JSON.stringify({ english_text: "auto-allow read_the_almanac" }),
      });
      const draftId = ((await compileRes.json()) as { data: { draft: { draft_id: string } } })
        .data.draft.draft_id;

      const activateRes = await fetch(
        `${rig.base}${ENGLISH_POLICY_API_PREFIX}/drafts/${encodeURIComponent(draftId)}/activate`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer not-the-operator-token" },
          body: "{}",
        },
      );
      expect(activateRes.status).toBe(403);
      expect(rig.livePolicy.current.tier3_always_allow).not.toContain("read_the_almanac");
    } finally {
      await rig.close();
    }
  });
});

describe("tunability promote: the #805 config-downgrade gate refuses a posture-weakening promote", () => {
  it("an 'auto-allow <op>' promote (which relaxes protection) is REFUSED by default and audited, never silently applied", async () => {
    // Moving ANY operation onto the Tier-3 always-allow list relaxes
    // enforcement (agents no longer route it to the operator), which the
    // #805 gate treats as a downgrade and refuses without an explicit
    // override.
    const rig = await startRig();
    try {
      expect(rig.livePolicy.current.tier3_always_allow).not.toContain("read_the_almanac");

      const result = await promote(rig.base, "auto-allow read_the_almanac", OPERATOR_HEADERS);
      // Activation is refused (409 from the route mapping for a downgrade).
      expect(result.status).toBe(409);

      // The live policy is UNCHANGED: nothing was moved to always-allow.
      expect(rig.livePolicy.current.tier3_always_allow).not.toContain("read_the_almanac");

      // The refusal is audited, not silent; no activation event fires.
      const ops = await auditOps(rig.auditLog);
      expect(ops).toContain("english_policy_write_refused");
      expect(ops).not.toContain("english_policy_activated");
    } finally {
      await rig.close();
    }
  });

  it("the SAME weakening promote WITH the explicit override is applied AND audited as a forced downgrade (never silent)", async () => {
    // The operator confirmed the relaxation; the client re-sends with
    // override_downgrade=true. The gate does NOT silently yield: it applies
    // the change AND records policy_force_downgrade_used naming the weakened
    // field. This is the "refused OR forced through the audited override"
    // contract.
    const rig = await startRig();
    try {
      const result = await promote(
        rig.base,
        "auto-allow read_the_almanac",
        OPERATOR_HEADERS,
        true,
      );
      expect(result.status).toBe(200);
      expect((result.body as { data: { status: string } }).data.status).toBe("activated");

      // The rule landed only because the operator forced it.
      expect(rig.livePolicy.current.tier3_always_allow).toContain("read_the_almanac");

      // The forced downgrade is explicitly audited (not a silent apply).
      const ops = await auditOps(rig.auditLog);
      expect(ops).toContain("policy_force_downgrade_used");
      expect(ops).toContain("english_policy_activated");
    } finally {
      await rig.close();
    }
  });

  it("a FORCED downgrade for a hard-forced Tier-1 op still cannot smuggle it into Tier-3 (enforceForcedTiers holds)", async () => {
    // Even with the operator override, a forced Tier-1 operation
    // (state_export) is stripped from Tier-3 by enforceForcedTiers, so the
    // override cannot defeat the non-relaxable floor.
    const rig = await startRig({
      policy: JSON.parse(JSON.stringify(DEFAULT_POLICY)) as PrincipalPolicy,
    });
    try {
      expect(rig.livePolicy.current.tier1_always_approve).toContain("state_export");
      await promote(rig.base, "auto-allow state_export", OPERATOR_HEADERS, true);
      // state_export never lands in Tier-3 and stays Tier-1.
      expect(rig.livePolicy.current.tier3_always_allow).not.toContain("state_export");
      expect(rig.livePolicy.current.tier1_always_approve).toContain("state_export");
    } finally {
      await rig.close();
    }
  });
});

describe("tunability plain-English view: GET /api/policy/current is operator-bearer-gated (agent-opaque)", () => {
  it("returns the live policy in plain English WITH the operator bearer", async () => {
    const rig = await startRig();
    try {
      const res = await fetch(`${rig.base}${ENGLISH_POLICY_API_PREFIX}/current`, {
        headers: OPERATOR_HEADERS,
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { view: { lines: Array<{ section: string; text: string }> } };
      };
      expect(Array.isArray(body.data.view.lines)).toBe(true);
      expect(body.data.view.lines.length).toBeGreaterThan(0);
      // Plain English, not raw manifest tokens.
      const joined = body.data.view.lines.map((l) => l.text).join(" ");
      expect(joined).toMatch(/approval|allow/i);
      expect(joined).not.toContain("tier1_always_approve");
    } finally {
      await rig.close();
    }
  });

  it("rejects a TOKENLESS GET /current with 403 even with loopback auto-auth on (agent cannot read policy)", async () => {
    const rig = await startRig();
    try {
      const res = await fetch(`${rig.base}${ENGLISH_POLICY_API_PREFIX}/current`);
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("operator_auth_required");
    } finally {
      await rig.close();
    }
  });
});
