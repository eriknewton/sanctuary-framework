/**
 * Verascore publishing asks the operator first.
 *
 * CAPABILITY. Under the default Principal Policy, `reputation_publish` (the
 * tool that sends a signed sovereignty report to Verascore) is a Tier 1
 * operation: the gate holds every call for operator approval, so data leaves
 * the machine only with explicit, confirmed operator intent (AGENTS.md
 * MUST-NEVER #1). This is a privacy default; the tool's name, schema and
 * signing behavior are unchanged.
 *
 * WHAT THIS FILE PINS (AGENTS.md rule 4, wired consumer):
 *   1. A fresh install: the policy file Sanctuary writes on first boot, read
 *      back through the real loader, places `reputation_publish` in Tier 1,
 *      and the real `ApprovalGate` classifies it Tier 1 on a first session
 *      and on an established one.
 *   2. The real composition root (`createSanctuaryServer`, real `tools/call`):
 *      a publish is held for operator approval; when the operator declines,
 *      nothing is sent; when the operator approves, exactly one publish goes
 *      out.
 *   3. Operator policy precedence: an existing policy file that explicitly
 *      lists `reputation_publish` under Tier 3 keeps it at Tier 3, because an
 *      explicit operator policy wins over the shipped default.
 *   4. A loaded policy that names `reputation_publish` in neither list no
 *      longer inherits auto-allow from the defaults merge, so every publish
 *      waits for the operator in every session. The tier NUMBER differs by
 *      session (the first session routes it through the Tier 2 anomaly
 *      detector, later sessions through the Tier 1 unclassified safe
 *      default) but the behavior does not: both paths reach the same
 *      operator approval request, and nothing is sent until it is approved.
 *      This is asserted through the real gate (`evaluate`) and the real
 *      composition root, not through the dry-run classifier alone.
 *
 * Must match the `reputation_publish` entry in
 * `DEFAULT_POLICY.tier1_always_approve` (src/principal-policy/loader.ts).
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createSanctuaryServer } from "../../src/index.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import {
  generateDefaultPolicyYaml,
  loadPrincipalPolicy,
  parsePolicy,
  principalPolicyPath,
} from "../../src/principal-policy/loader.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
  PrincipalPolicy,
} from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const OP = "reputation_publish";

let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
let originalFetch: typeof fetch;

beforeEach(async () => {
  // The real boot path writes config and the policy file under HOME, so HOME
  // moves to a throwaway directory; the operator's machine is not a fixture.
  fortressHome = await createTempHome("sanctuary-reputation-publish-tier");
  originalFetch = globalThis.fetch;
});

afterEach(async () => {
  globalThis.fetch = originalFetch;
  await fortressHome.cleanup();
});

/** Classify `operation` with the real gate on a first and an established session. */
async function classifyBothSessions(
  policy: PrincipalPolicy,
  operation: string,
): Promise<{ first: number; established: number }> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const channel = new CallbackApprovalChannel(async () => {
    throw new Error("dry-run classification must never reach the approval channel");
  });
  const firstSession = new BaselineTracker(storage, masterKey);
  await firstSession.load();
  const first = new ApprovalGate(policy, firstSession, channel, auditLog).classifyRiskTier(
    operation,
    {},
  );
  await firstSession.save();
  const establishedSession = new BaselineTracker(storage, masterKey);
  await establishedSession.load();
  const established = new ApprovalGate(
    policy,
    establishedSession,
    channel,
    auditLog,
  ).classifyRiskTier(operation, {});
  return { first, established };
}

/** Move one operation between the two list blocks of a rendered policy YAML. */
function moveOpToTier3(yaml: string, op: string): string {
  const withoutTier1 = yaml.replace(new RegExp(`^  - ${op}\\n`, "m"), "");
  return withoutTier1.replace(/^tier3_always_allow:\n/m, `tier3_always_allow:\n  - ${op}\n`);
}

function removeOp(yaml: string, op: string): string {
  return yaml.replace(new RegExp(`^  - ${op}\\n`, "gm"), "");
}

async function writePolicyFile(yaml: string): Promise<string> {
  await mkdir(fortressHome.defaultFortressPath, { recursive: true, mode: 0o700 });
  const path = principalPolicyPath(fortressHome.defaultFortressPath);
  await writeFile(path, yaml, { mode: 0o600 });
  return path;
}

async function callServerTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ content: Array<{ type: string; text: string }> }> {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(
    { method: "tools/call" as const, params: { name, arguments: args } },
    {},
  );
}

/** Switch a rendered policy to the embedding-host callback channel, nothing else. */
function withCallbackChannel(yaml: string): string {
  return yaml.replace(/approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback");
}

/**
 * Drive the REAL gate's `evaluate` (not the dry-run classifier) for one
 * publish, with a scripted operator. Returns what the operator was asked and
 * whether the gate let the call through.
 */
async function evaluateWithOperator(
  policy: PrincipalPolicy,
  session: "first" | "established",
  decision: ApprovalResponse["decision"],
): Promise<{ asked: ApprovalRequest[]; allowed: boolean }> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const asked: ApprovalRequest[] = [];
  const channel = new CallbackApprovalChannel(async (request) => {
    asked.push(request);
    return { decision, decided_at: new Date().toISOString(), decided_by: "human" };
  });
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();
  if (session === "established") {
    // Persist and reload: the tracker's own definition of a later session.
    await baseline.save();
    const established = new BaselineTracker(storage, masterKey);
    await established.load();
    expect(established.isFirstSession).toBe(false);
    const gate = new ApprovalGate(policy, established, channel, auditLog);
    return { asked, allowed: (await gate.evaluate(OP, { type: "shr" })).allowed };
  }
  expect(baseline.isFirstSession).toBe(true);
  const gate = new ApprovalGate(policy, baseline, channel, auditLog);
  return { asked, allowed: (await gate.evaluate(OP, { type: "shr" })).allowed };
}

/**
 * Boot the real server with the shipped default policy, switched only to the
 * embedding-host callback channel so the test can play the operator. Every
 * tier list is the default one, byte for byte.
 */
async function bootWithOperator(
  decision: ApprovalResponse["decision"],
  policyYaml: string = generateDefaultPolicyYaml(),
) {
  await writePolicyFile(withCallbackChannel(policyYaml));
  const requests: ApprovalRequest[] = [];
  const { server } = await createSanctuaryServer({
    storage: new MemoryStorage(),
    passphrase: TEST_PASSPHRASE,
    approvalCallback: async (request) => {
      requests.push(request);
      return {
        decision,
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    },
  });
  const published: string[] = [];
  globalThis.fetch = (async (url: string | URL) => {
    published.push(String(url));
    return {
      ok: true,
      status: 200,
      json: async () => ({ success: true }),
    } as unknown as Response;
  }) as typeof fetch;
  await callServerTool(server, "identity_create", { label: "publish-consent" });
  return { server, requests, published };
}

describe("reputation_publish requires operator approval under the default policy", () => {
  it("fresh install: the policy file Sanctuary writes puts it in Tier 1, and the gate agrees on both sessions", async () => {
    // A fresh fortress directory with no policy file: the first-boot branch
    // writes the default (it never creates the fortress directory itself).
    await mkdir(fortressHome.defaultFortressPath, { recursive: true, mode: 0o700 });
    const loaded = await loadPrincipalPolicy(fortressHome.defaultFortressPath);
    expect(loaded.tier1_always_approve).toContain(OP);
    expect(loaded.tier3_always_allow).not.toContain(OP);

    // The file written on first boot is what every later boot reads.
    const written = parsePolicy(
      await readFile(principalPolicyPath(fortressHome.defaultFortressPath), "utf-8"),
    );
    expect(written.tier1_always_approve).toContain(OP);
    expect(written.tier3_always_allow).not.toContain(OP);

    expect(await classifyBothSessions(written, OP)).toEqual({ first: 1, established: 1 });
  });

  it("real composition root: the publish is held for the operator, and a decline sends nothing", async () => {
    const { server, requests, published } = await bootWithOperator("deny");

    await callServerTool(server, OP, { type: "shr" });

    const held = requests.filter((r) => r.operation.endsWith(OP));
    expect(held.length, "the gate must ask the operator before publishing").toBe(1);
    expect(held[0]!.tier).toBe(1);
    expect(published, "a declined publish must not reach the network").toEqual([]);
  });

  it("real composition root: an approved publish sends exactly one request", async () => {
    const { server, requests, published } = await bootWithOperator("approve");

    await callServerTool(server, OP, { type: "shr" });

    expect(requests.filter((r) => r.operation.endsWith(OP)).length).toBe(1);
    expect(published.filter((url) => url.endsWith("/api/publish"))).toHaveLength(1);
  });

  it("an existing operator policy that lists it under Tier 3 keeps it at Tier 3 (operator policy wins)", async () => {
    // This is the shape of a policy file written by an earlier release, when
    // the shipped default auto-allowed publishing.
    await writePolicyFile(moveOpToTier3(generateDefaultPolicyYaml(), OP));

    const loaded = await loadPrincipalPolicy(fortressHome.defaultFortressPath);
    expect(loaded.tier3_always_allow).toContain(OP);
    expect(loaded.tier1_always_approve).not.toContain(OP);
    expect(await classifyBothSessions(loaded, OP)).toEqual({ first: 3, established: 3 });
  });

  it("a loaded policy that names it in neither list: the first-session publish waits for the operator (real composition root)", async () => {
    const neitherTier = removeOp(generateDefaultPolicyYaml(), OP);
    const loaded = parsePolicy(neitherTier);
    expect(loaded.tier1_always_approve).not.toContain(OP);
    expect(
      loaded.tier3_always_allow,
      "the defaults merge must not hand it auto-allow",
    ).not.toContain(OP);

    // A fresh boot is a first session; the gate routes the unlisted publish
    // through the anomaly tier, which still asks the operator.
    const declined = await bootWithOperator("deny", neitherTier);
    await callServerTool(declined.server, OP, { type: "shr" });
    expect(declined.requests.filter((r) => r.operation.endsWith(OP))).toHaveLength(1);
    expect(declined.published, "a declined publish must not reach the network").toEqual([]);

    const approved = await bootWithOperator("approve", neitherTier);
    await callServerTool(approved.server, OP, { type: "shr" });
    expect(approved.requests.filter((r) => r.operation.endsWith(OP))).toHaveLength(1);
    expect(approved.published.filter((url) => url.endsWith("/api/publish"))).toHaveLength(1);
  });

  it("a loaded policy that names it in neither list: the real gate asks the operator in every session shape", async () => {
    const neitherTier = removeOp(generateDefaultPolicyYaml(), OP);
    const scenarios: Array<{ label: string; policy: PrincipalPolicy; session: "first" | "established" }> = [
      { label: "first session", policy: parsePolicy(neitherTier), session: "first" },
      { label: "established session", policy: parsePolicy(neitherTier), session: "established" },
      {
        // An operator who switched first-session approval off must not turn
        // an unlisted publish into an auto-allow on the first session.
        label: "first session, first_session_policy: allow",
        policy: parsePolicy(
          neitherTier.replace(/first_session_policy: \w+/, "first_session_policy: allow"),
        ),
        session: "first",
      },
    ];
    for (const { label, policy, session } of scenarios) {
      expect(policy.tier3_always_allow, label).not.toContain(OP);
      for (const decision of ["deny", "approve"] as const) {
        const { asked, allowed } = await evaluateWithOperator(policy, session, decision);
        expect(asked.map((r) => r.operation), `${label}/${decision}: operator asked`).toEqual([OP]);
        expect(allowed, `${label}/${decision}: gate decision follows the operator`).toBe(
          decision === "approve",
        );
      }
    }
  });
});
