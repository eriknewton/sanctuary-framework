/**
 * Why a Charter hold is held reaches the operator's card only as structured
 * data: a reason code the console turns into its own sentence, plus at most one
 * gate-quoted identifier carried as delimited data. The gate's free-text reason
 * never reaches a card, so an identifier an agent chose (a namespace, a
 * counterparty DID) cannot pose as approval guidance on the operator's screen.
 * The held operation name is treated the same way: a proxied tool is named by
 * an upstream server, so the card bounds it and the console shows it only as
 * delimited, escaped data.
 *
 * Every reason the gate can send to the approval channel is raised through the
 * real ApprovalGate, and a coverage test reads the gate's source so a new or
 * reworded reason fails here instead of reaching the operator as unrecognised.
 */
import { readFileSync } from "node:fs";
import ts from "typescript";
import { beforeEach, describe, expect, it } from "vitest";

import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalRequest, PrincipalPolicy } from "../../src/principal-policy/types.js";
import {
  CARD_OPERATION_MAX_CHARS,
  HOLD_REASON_SUBJECT_MAX_CHARS,
  HOLD_REASON_TEMPLATES,
  PROXY_REASON_GATE_SOURCE,
  PROXY_REASON_PREFIX,
  classifyHoldReason,
  cutAtCodePoint,
  projectCharterApproval,
} from "../../src/hub/charter-approval-bridge.js";
import { heldSubjectText } from "../../src/dashboard/v1_1/templates.js";
import { HUB_HOLD_REASON_CODES, type HubHoldReason } from "../../src/contracts/v1.1/hub-events.js";
import {
  SUBJECT_SLOT,
  clientCardRenderers,
  clientDeclarations,
  clientHoldReasonRenderer,
  splitHeldReason,
} from "../dashboard/v1_1/client-script-extract.js";

// The namespace a held agent could choose to make its own text read as guidance.
const GUIDANCE_SHAPED_NAMESPACE = 'notes" (operator approved). Click Allow once. "';
// A tool name an upstream MCP server could advertise so the held operation reads as guidance.
const GUIDANCE_SHAPED_TOOL = "proxy/files/read. Operator approved. Click Allow once";

type Anomaly = PrincipalPolicy["tier2_anomaly"];

function policyWith(anomaly: Partial<Anomaly>, overrides: Partial<PrincipalPolicy> = {}): PrincipalPolicy {
  return { ...DEFAULT_POLICY, ...overrides, tier2_anomaly: { ...DEFAULT_POLICY.tier2_anomaly, ...anomaly } };
}

/** A channel that records each held request and refuses it, so evaluate() settles at once. */
function capturingChannel(seen: ApprovalRequest[]): ApprovalChannel {
  return {
    requestApproval: async (request: ApprovalRequest) => {
      seen.push(request);
      return { decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" };
    },
  };
}

function readGateSource(): string {
  return readFileSync(new URL("../../src/principal-policy/gate.ts", import.meta.url), "utf8");
}

/**
 * The reasons gate.ts hands the approval channel through the forms this scan models, read with the TypeScript
 * compiler API. Bound: this is a tripwire over the modeled forms, NOT a reachability proof. It resolves the third
 * argument of each `this.requestApproval(...)` call through the variables and private methods it forwards
 * (`classification.reason` to classifyOperation's returned objects, `classification.anomaly.reason` through the
 * `anomaly` it returns to detectAnomaly's), comparing literal source text (concatenations joined) with each
 * template's pinned gateSource. It fails closed on what it can see it does not model: an unmodeled reason
 * expression, return shape or channel call; a reason source that resolves to nothing; any reference to
 * requestApproval other than the modeled call; and any assignment to a property named reason. It does not analyze
 * control flow: that a Tier 3 classification never reaches the channel rests on a checked shape (evaluate()'s allow
 * return for Tier 3), not a proof. The guarantee is at run time: a reason the bridge does not recognise is
 * `unrecognized`, the console renders a fixed sentence for it, and the gate's free text never reaches a card.
 */
function gateChannelReasons(sourceText: string): { held: Set<string>; tier3Skipped: number } {
  const sf = ts.createSourceFile("gate.ts", sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  function fail(node: ts.Node, what: string): never {
    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    throw new Error(`gate reason scan: unmodeled ${what} at gate.ts:${line}: ${node.getText(sf)}`);
  }
  const methods = new Map<string, ts.MethodDeclaration>();
  const gateCalls: ts.CallExpression[] = [];
  const channelCalls: ts.CallExpression[] = [];
  const references: ts.Node[] = [];
  const reasonWrites: ts.Node[] = [];
  const isReasonTarget = (written: ts.Expression): boolean => {
    // Parentheses do not change what is written, so `(x.reason) = ...` is the same write as `x.reason = ...`.
    let target = written;
    while (ts.isParenthesizedExpression(target)) target = target.expression;
    return (
      (ts.isPropertyAccessExpression(target) && target.name.text === "reason") ||
      (ts.isElementAccessExpression(target) && ts.isStringLiteralLike(target.argumentExpression) && target.argumentExpression.text === "reason")
    );
  };
  const visit = (node: ts.Node): void => {
    if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) methods.set(node.name.text, node);
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "requestApproval") {
      (node.expression.expression.kind === ts.SyntaxKind.ThisKeyword ? gateCalls : channelCalls).push(node);
    }
    if ((ts.isIdentifier(node) || ts.isStringLiteralLike(node)) && node.text === "requestApproval") references.push(node);
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      isReasonTarget(node.left)
    ) {
      reasonWrites.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  // A reason written after the object is built is invisible to the resolution below, so any such write fails.
  for (const write of reasonWrites) fail(write, "reason assignment");
  // The only modeled references: the private method's own name, and the callee of a call (`this.requestApproval(...)`
  // or the channel call checked below). An alias, element access, destructuring or the method passed as a value fails.
  for (const reference of references) {
    const parent = reference.parent;
    const declaresMethod = ts.isMethodDeclaration(parent) && parent.name === reference;
    const callee =
      ts.isPropertyAccessExpression(parent) && parent.name === reference && ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
    if (!declaresMethod && !callee) fail(reference, "requestApproval reference");
  }
  const enclosingMethod = (node: ts.Node): ts.MethodDeclaration => {
    for (let at: ts.Node | undefined = node.parent; at; at = at.parent) if (ts.isMethodDeclaration(at)) return at;
    return fail(node, "call outside a method");
  };
  const methodName = (method: ts.MethodDeclaration): string => (ts.isIdentifier(method.name) ? method.name.text : "");
  // The channel is reached only from requestApproval itself, so its arguments are the whole reachable set.
  for (const call of channelCalls) {
    if (call.expression.getText(sf) !== "this.channel.requestApproval" || methodName(enclosingMethod(call)) !== "requestApproval") {
      fail(call, "channel call");
    }
  }

  const isFunctionLike = (node: ts.Node) =>
    ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node);
  const declaredInitializer = (name: ts.Identifier, scope: ts.MethodDeclaration): ts.Expression => {
    const found: ts.Expression[] = [];
    const find = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name.text && node.initializer) found.push(node.initializer);
      ts.forEachChild(node, find);
    };
    find(scope);
    return found.length === 1 ? found[0]! : fail(name, "reason variable");
  };
  const returnedObjects = (method: ts.MethodDeclaration): ts.ObjectLiteralExpression[] => {
    const objects: ts.ObjectLiteralExpression[] = [];
    const find = (node: ts.Node): void => {
      if (node !== method && isFunctionLike(node)) return;
      if (ts.isReturnStatement(node)) {
        const value = node.expression;
        if (value && ts.isObjectLiteralExpression(value)) objects.push(value);
        else if (!value || value.kind !== ts.SyntaxKind.NullKeyword) fail(node, "reason source return");
      }
      ts.forEachChild(node, find);
    };
    find(method);
    return objects;
  };
  const property = (object: ts.ObjectLiteralExpression, name: string): ts.Expression | null => {
    for (const p of object.properties) {
      if (ts.isSpreadAssignment(p)) fail(p, "reason object spread");
      if (p.name && ts.isIdentifier(p.name) && p.name.text === name) {
        if (ts.isPropertyAssignment(p)) return p.initializer;
        if (ts.isShorthandPropertyAssignment(p)) return p.name;
        fail(p, "reason object property");
      }
    }
    return null;
  };
  type Source = { object: ts.ObjectLiteralExpression; scope: ts.MethodDeclaration };
  const objectsOf = (expr: ts.Expression, scope: ts.MethodDeclaration): Source[] => {
    if (ts.isIdentifier(expr)) return objectsOf(declaredInitializer(expr, scope), scope);
    if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression) && expr.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const method = methods.get(expr.expression.name.text);
      if (method) return returnedObjects(method).map((object) => ({ object, scope: method }));
    }
    if (ts.isPropertyAccessExpression(expr)) {
      return objectsOf(expr.expression, scope).flatMap((source) => {
        const value = property(source.object, expr.name.text);
        return value === null ? [] : objectsOf(value, source.scope);
      });
    }
    return fail(expr, "reason source");
  };
  const literalText = (expr: ts.Expression): string | null => {
    if (ts.isParenthesizedExpression(expr)) return literalText(expr.expression);
    if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr) || ts.isTemplateExpression(expr)) return expr.getText(sf).slice(1, -1);
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = literalText(expr.left);
      const right = literalText(expr.right);
      return left !== null && right !== null ? left + right : fail(expr, "reason concatenation");
    }
    return null;
  };

  const held = new Set<string>();
  let tier3Skipped = 0;
  const collect = (expr: ts.Expression, scope: ts.MethodDeclaration): void => {
    const literal = literalText(expr);
    if (literal !== null) {
      held.add(literal);
      return;
    }
    if (ts.isIdentifier(expr)) return collect(declaredInitializer(expr, scope), scope);
    if (ts.isPropertyAccessExpression(expr) && expr.name.text === "reason") {
      const sources = objectsOf(expr.expression, scope);
      // An empty resolution would add nothing and pass, so a source that names no returned object fails.
      if (sources.length === 0) fail(expr, "reason source did not resolve");
      for (const source of sources) {
        const tier = property(source.object, "tier");
        if (tier !== null && !ts.isNumericLiteral(tier)) fail(tier, "reason tier");
        if (tier !== null && (tier as ts.NumericLiteral).text === "3") {
          tier3Skipped++;
          continue;
        }
        const reason = property(source.object, "reason");
        if (reason === null) fail(source.object, "reason object without a reason");
        collect(reason!, source.scope);
      }
      return;
    }
    fail(expr, "reason expression");
  };
  for (const call of gateCalls) {
    const reason = call.arguments[2];
    if (!reason) fail(call, "reason argument");
    collect(reason!, enclosingMethod(call));
  }
  if (tier3Skipped > 0) {
    // A Tier 3 classification never reaches the channel only because evaluate() returns an allow result for it
    // before any call that forwards classification.reason; if that return moves, the skip above is unsound.
    const evaluate = methods.get("evaluate");
    let guarded = false;
    const find = (node: ts.Node): void => {
      if (ts.isIfStatement(node) && node.expression.getText(sf) === "classification.tier === 3" && ts.isBlock(node.thenStatement)) {
        const last = node.thenStatement.statements.at(-1);
        const allowed = last && ts.isReturnStatement(last) && last.expression && ts.isObjectLiteralExpression(last.expression)
          ? property(last.expression, "allowed") : null;
        if (allowed && allowed.kind === ts.SyntaxKind.TrueKeyword) guarded = true;
      }
      ts.forEachChild(node, find);
    };
    if (evaluate) find(evaluate);
    if (!guarded) throw new Error("gate reason scan: unmodeled Tier 3 path: no allow return for classification.tier === 3 in evaluate()");
  }
  return { held, tier3Skipped };
}

/** The gate reasons no bridge template pins, and the pinned gate sources the gate no longer sends. */
function uncoveredGateReasons(held: Set<string>): { uncovered: string[]; unsent: string[] } {
  // The proxy wrapper is pinned whole (the classifier strips its prefix and classifies the wrapped reason); every
  // other reason is one template's gateSource.
  const pinned = new Set([...HOLD_REASON_TEMPLATES.map((t) => t.gateSource), PROXY_REASON_GATE_SOURCE]);
  return {
    uncovered: [...held].filter((r) => !pinned.has(r)).sort(),
    unsent: [...pinned].filter((r) => !held.has(r)).sort(),
  };
}

/** The project's whole-word check: no word outside a held-subject element came from the held call. */
function expectConsoleWordsOnly(prose: string): void {
  expect(prose).not.toMatch(/Operator approved|operator approved|Click Allow once/);
}

describe("structured hold reasons", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
  });

  /** Raise one call through the real gate and return the request it held last, classified. */
  async function heldThroughGate(
    policy: PrincipalPolicy,
    toolName: string,
    args: Record<string, unknown>,
    setup?: (gate: ApprovalGate) => Promise<void> | void,
  ): Promise<{ request: ApprovalRequest; reason: HubHoldReason }> {
    const seen: ApprovalRequest[] = [];
    const gate = new ApprovalGate(
      policy,
      new BaselineTracker(storage, masterKey),
      capturingChannel(seen),
      new AuditLog(storage, masterKey),
    );
    await setup?.(gate);
    await gate.evaluate(toolName, args);
    const request = seen.at(-1);
    expect(request, `${toolName} was held`).toBeDefined();
    return {
      request: request!,
      reason: classifyHoldReason({
        operation: request!.operation,
        reason: request!.reason,
        context: request!.context,
      }),
    };
  }

  it("keeps the reason codes in full-set parity across the contract, the bridge templates and the console sentences", () => {
    const contract = HUB_HOLD_REASON_CODES.filter((code) => code !== "unrecognized").sort();
    expect(HOLD_REASON_TEMPLATES.map((t) => t.code).sort()).toEqual(contract);
    const { HOLD_REASON_SENTENCES } = clientDeclarations<{ HOLD_REASON_SENTENCES: Record<string, unknown> }>(
      ["HOLD_REASON_SENTENCES"],
      ["HOLD_REASON_SENTENCES"],
    );
    expect(Object.keys(HOLD_REASON_SENTENCES).sort()).toEqual(contract);
  });

  it("covers every reason the gate source can send to the approval channel", () => {
    // Computed, not listed: gateChannelReasons reads gate.ts with the compiler and resolves the reason argument of
    // every requestApproval call. Each must be one bridge template's pinned gateSource (the proxy wrapper is the
    // prefix the classifier strips). A new or reworded gate reason fails here.
    const { held, tier3Skipped } = gateChannelReasons(readGateSource());
    // classifyOperation's Tier 3 result is forwarded only past evaluate()'s Tier 3 return, which the scan checks.
    expect(tier3Skipped).toBeGreaterThan(0);
    expect(PROXY_REASON_GATE_SOURCE.startsWith(PROXY_REASON_PREFIX)).toBe(true);
    expect(uncoveredGateReasons(held)).toEqual({ uncovered: [], unsent: [] });
  });

  it("the gate reason coverage fails on a new reason in any literal form and refuses a form it does not model", () => {
    const source = readGateSource();
    // A new reason passed straight to requestApproval, in each literal form the gate could use.
    const evaluateAnchor = "    const classification = this.classifyOperation(toolName, args);\n";
    expect(source.split(evaluateAnchor)).toHaveLength(2);
    const withDirectReason = (reason: string) =>
      source.replace(evaluateAnchor, `    if (args.mutation) return this.requestApproval(operation, 2, ${reason}, {});\n${evaluateAnchor}`);
    const direct: Array<[string, string]> = [
      ["'A single-quoted new reason'", "A single-quoted new reason"],
      ['"A double-quoted new reason"', "A double-quoted new reason"],
      ["`A template new reason for ${operation}`", "A template new reason for ${operation}"],
      ["`A concatenated ` + 'new reason'", "A concatenated new reason"],
    ];
    for (const [form, text] of direct) {
      expect(uncoveredGateReasons(gateChannelReasons(withDirectReason(form)).held).uncovered, form).toEqual([text]);
    }
    // A new reason the gate forwards: a detectAnomaly result reaches the channel through classification.anomaly.
    const anomalyAnchor = "  ): { reason: string; context: Record<string, unknown>; commit?: () => void } | null {\n";
    expect(source.split(anomalyAnchor)).toHaveLength(2);
    const forwarded = source.replace(anomalyAnchor, `${anomalyAnchor}    if (args.mutation) return { reason: 'A forwarded new reason', context: {} };\n`);
    expect(uncoveredGateReasons(gateChannelReasons(forwarded).held).uncovered).toEqual(["A forwarded new reason"]);
    // A reason form the scan does not model fails loudly instead of being skipped.
    expect(() => gateChannelReasons(withDirectReason("reasonFor(operation)"))).toThrow(/unmodeled reason/);
    expect(() => gateChannelReasons(withDirectReason("`Prefix ` + suffix"))).toThrow(/unmodeled reason/);
    // A reason source that resolves to no returned object fails instead of adding nothing.
    expect(() => gateChannelReasons(withDirectReason("classification.missing.reason"))).toThrow(/reason source did not resolve/);
    // Any reference to requestApproval other than the modeled call fails: element access, an alias, destructuring,
    // the method passed as a value, and a bound copy.
    for (const reference of [
      `this["requestApproval"](operation, 2, "x", {})`,
      "const ask = this.requestApproval",
      "const { requestApproval } = this",
      "void [this.requestApproval]",
      "this.requestApproval.bind(this)",
    ]) {
      expect(() => gateChannelReasons(source.replace(evaluateAnchor, `    if (args.mutation) ${reference};\n${evaluateAnchor}`)), reference).toThrow(
        /requestApproval reference/,
      );
    }
    // Any assignment to a property named reason fails, whatever it assigns and however the property is named.
    for (const write of [
      `classification.reason = "Rewritten later"`,
      `classification["reason"] += " later"`,
      `(classification.reason) = "new reason"`,
      `(classification["reason"]) += "new reason"`,
    ]) {
      const rewritten = source.replace(evaluateAnchor, `${evaluateAnchor}    if (args.mutation) ${write};\n`);
      expect(() => gateChannelReasons(rewritten), write).toThrow(/reason assignment/);
    }
    // A channel reached other than through requestApproval fails loudly too.
    expect(() =>
      gateChannelReasons(source.replace(evaluateAnchor, `    if (args.mutation) await this.channel.requestApproval(request);\n${evaluateAnchor}`)),
    ).toThrow(/channel call/);
  });

  it("recognises every reason the real gate writes, and keeps only the quoted identifier", async () => {
    const noFirstSession = policyWith({ first_session_policy: "log" });
    // identity_sign is Tier 1 in every policy the loader builds, so the signing-rate reason is reached only by a
    // policy that lists it elsewhere; the gate itself still writes it.
    const signingPolicy = policyWith(
      { first_session_policy: "log", max_signs_per_minute: 2 },
      {
        tier1_always_approve: DEFAULT_POLICY.tier1_always_approve.filter((op) => op !== "identity_sign"),
        tier3_always_allow: [...DEFAULT_POLICY.tier3_always_allow, "identity_sign"],
      },
    );
    const cases: Array<{
      expected: HubHoldReason;
      policy: PrincipalPolicy;
      tool: string;
      args: Record<string, unknown>;
      setup?: (gate: ApprovalGate) => Promise<void> | void;
    }> = [
      { expected: { code: "tier1_policy" }, policy: DEFAULT_POLICY, tool: "state_export", args: {} },
      { expected: { code: "tier1_forced" }, policy: DEFAULT_POLICY, tool: "memory_delete", args: {} },
      {
        expected: { code: "tier1_secret_waiver" },
        policy: DEFAULT_POLICY,
        tool: "memory_ingest",
        args: { allow_files: ["notes.txt"] },
      },
      {
        expected: { code: "tier1_unclassified" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", new_counterparty: "log" }),
        tool: "made_up_tool",
        args: {},
      },
      { expected: { code: "first_session" }, policy: DEFAULT_POLICY, tool: "made_up_tool", args: {} },
      {
        expected: { code: "first_namespace_access", subject: "customer-notes" },
        policy: noFirstSession,
        tool: "state_write",
        args: { namespace: "customer-notes", key: "k", value: "v" },
      },
      {
        expected: { code: "first_counterparty", subject: "did:key:z6MkCounterparty" },
        policy: noFirstSession,
        tool: "handshake_initiate",
        args: { counterparty_did: "did:key:z6MkCounterparty" },
      },
      {
        expected: { code: "bulk_read", subject: "ledger" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", bulk_read_threshold: 2 }),
        tool: "state_read",
        args: { namespace: "ledger", key: "k" },
        // Two reads fill the threshold; the third, below, is the bulk read.
        setup: async (gate) => {
          await gate.evaluate("state_read", { namespace: "ledger", key: "k" });
          await gate.evaluate("state_read", { namespace: "ledger", key: "k" });
        },
      },
      {
        expected: { code: "signing_rate" },
        policy: signingPolicy,
        tool: "identity_sign",
        args: {},
        // Two signatures fill max_signs_per_minute; the third, below, exceeds it.
        setup: async (gate) => {
          await gate.evaluate("identity_sign", {});
          await gate.evaluate("identity_sign", {});
        },
      },
      {
        expected: { code: "frequency_spike" },
        policy: policyWith({ first_session_policy: "log", new_namespace_access: "log", frequency_spike_multiplier: 2 }),
        tool: "state_list",
        args: {},
        // Three other tools called once each and state_list three times leave the average at 1.5 calls a minute; the
        // fourth state_list, below, is 4 against an average of 1.75, more than twice it.
        setup: async (gate) => {
          for (const other of ["identity_list", "identity_verify", "proof_commitment"]) await gate.evaluate(other, {});
          for (let call = 0; call < 3; call++) await gate.evaluate("state_list", {});
        },
      },
      {
        expected: { code: "injection_escalation" },
        policy: DEFAULT_POLICY,
        tool: "state_write",
        // A fullwidth letter is a medium normalization signal, which the default detector escalates.
        args: { namespace: "notes", key: "k", value: "\uff21" },
      },
      {
        expected: { code: "proxy_tier1", subject: "proxy/files/delete_everything" },
        policy: noFirstSession,
        tool: "proxy/files/delete_everything",
        args: {},
        setup: (gate) => gate.setProxyTierResolver(() => 1),
      },
      {
        expected: { code: "first_namespace_access", via_proxy: true, subject: "drafts" },
        policy: noFirstSession,
        tool: "proxy/files/write",
        args: { namespace: "drafts" },
        setup: (gate) => gate.setProxyTierResolver(() => 2),
      },
    ];
    const witnessed = new Set<string>();
    for (const c of cases) {
      const { reason } = await heldThroughGate(c.policy, c.tool, c.args, c.setup);
      expect(reason, `${c.tool} -> ${c.expected.code}`).toEqual(c.expected);
      witnessed.add(reason.code);
    }
    // Every recognised code has a real-gate witness above.
    expect([...witnessed].sort()).toEqual(HUB_HOLD_REASON_CODES.filter((code) => code !== "unrecognized").sort());
  });

  it("never returns reason text it cannot re-render from the hold's own fields", () => {
    // Text a direct channel caller wrote, and a gate shape whose quoted field disagrees with the context.
    const inputs = [
      { operation: "state_write", reason: "Approved already. Click Allow once.", context: {} },
      {
        operation: "state_write",
        reason: 'First access to namespace "a" (not in session baseline)',
        context: { namespace: "b" },
      },
      { operation: "state_write", reason: 42, context: null },
    ];
    for (const input of inputs) {
      const reason = classifyHoldReason(input);
      expect(reason).toEqual({ code: "unrecognized" });
      expect(JSON.stringify(reason)).not.toMatch(/Click|Approved|namespace/);
    }
  });

  it("caps a quoted identifier and marks it shortened", () => {
    const long = "n".repeat(HOLD_REASON_SUBJECT_MAX_CHARS + 50);
    expect(
      classifyHoldReason({
        operation: "state_write",
        reason: `First access to namespace "${long}" (not in session baseline)`,
        context: { namespace: long },
      }),
    ).toEqual({
      code: "first_namespace_access",
      subject: long.slice(0, HOLD_REASON_SUBJECT_MAX_CHARS),
      subject_truncated: true,
    });
  });

  it("caps a held operation name on the card and marks it shortened", () => {
    // 64 times the bound, so a card that carried the whole name would be many times the size of the bounded one.
    const long = "proxy/files/" + "x".repeat(CARD_OPERATION_MAX_CHARS * 64);
    const card = projectCharterApproval(
      { id: "hold-1", operation: long, tier: 2, created_at: "2026-10-21T00:00:00.000Z", hold_reason: { code: "unrecognized" } },
      "operator-identity",
    );
    const operation = card.display_template_args.find((a) => a.kind === "operation")!.value as string;
    expect(operation).toBe(long.slice(0, CARD_OPERATION_MAX_CHARS));
    expect(card.operation_truncated).toBe(true);
    expect(JSON.stringify(card).length).toBeLessThan(long.length);
    const { subjects } = splitHeldReason(clientCardRenderers().approvalOperationHtml(card));
    expect(subjects).toEqual([heldSubjectText(operation)]);
    expect(clientCardRenderers().approvalOperationHtml(card)).toContain("</code> (shortened)");
    // A name within the bound is carried whole and unflagged.
    const short = projectCharterApproval(
      { id: "hold-2", operation: "state_write", tier: 2, created_at: "2026-10-21T00:00:00.000Z" },
      "operator-identity",
    );
    expect(short.operation_truncated).toBeUndefined();
  });

  it("cuts a capped subject and a capped operation name on a code-point boundary, never inside a surrogate pair", () => {
    // U+1F600 is two UTF-16 units; placed at units bound-1 and bound, a plain slice would keep only its high half.
    const astral = String.fromCodePoint(0x1f600);
    const straddling = "n".repeat(HOLD_REASON_SUBJECT_MAX_CHARS - 1) + astral + "tail";
    const LONE_SURROGATE = /\p{Cs}/u;
    expect(LONE_SURROGATE.test(straddling.slice(0, HOLD_REASON_SUBJECT_MAX_CHARS))).toBe(true);
    const reason = classifyHoldReason({
      operation: "state_write",
      reason: `First access to namespace "${straddling}" (not in session baseline)`,
      context: { namespace: straddling },
    });
    expect(reason).toEqual({ code: "first_namespace_access", subject: "n".repeat(HOLD_REASON_SUBJECT_MAX_CHARS - 1), subject_truncated: true });
    const operationName = "p".repeat(CARD_OPERATION_MAX_CHARS - 1) + astral + "tail";
    const card = projectCharterApproval(
      { id: "hold-astral", operation: operationName, tier: 2, created_at: "2026-10-21T00:00:00.000Z", hold_reason: { code: "unrecognized" } },
      "operator-identity",
    );
    const operation = card.display_template_args.find((a) => a.kind === "operation")!.value as string;
    expect(operation).toBe("p".repeat(CARD_OPERATION_MAX_CHARS - 1));
    expect(LONE_SURROGATE.test(operation)).toBe(false);
    expect(card.operation_truncated).toBe(true);
    // A pair that ends exactly at the bound is kept whole.
    const fits = "n".repeat(CARD_OPERATION_MAX_CHARS - 2) + astral + "tail";
    expect(cutAtCodePoint(fits, CARD_OPERATION_MAX_CHARS)).toBe("n".repeat(CARD_OPERATION_MAX_CHARS - 2) + astral);
    expect(cutAtCodePoint("short", CARD_OPERATION_MAX_CHARS)).toBe("short");
  });

  it("shows a guidance-shaped namespace only as escaped, delimited data under console-written words", async () => {
    // Real gate -> structured record -> bridge projection -> the console's own renderer.
    const { request, reason } = await heldThroughGate(
      policyWith({ first_session_policy: "log" }),
      "state_write",
      { namespace: GUIDANCE_SHAPED_NAMESPACE, key: "k", value: "v" },
    );
    expect(request.reason).toContain("Click Allow once");
    const card = projectCharterApproval(
      { id: "hold-1", operation: request.operation, tier: request.tier, created_at: request.timestamp, hold_reason: reason },
      "operator-identity",
    );
    expect(JSON.stringify(card)).not.toContain("not in session baseline");
    const html = clientHoldReasonRenderer()(card);
    const { prose, subjects } = splitHeldReason(html);
    // Every word outside the data element is the console's own sentence.
    expect(prose).toBe(`First access to namespace ${SUBJECT_SLOT}. It is not in this session's baseline.`);
    // The identifier appears once, JSON-quoted with its quotes escaped, and only inside the element.
    expect(subjects).toEqual([JSON.stringify(GUIDANCE_SHAPED_NAMESPACE)]);
    expect(subjects[0]).toBe('"notes\\" (operator approved). Click Allow once. \\""');
    expectConsoleWordsOnly(prose);
  });

  it("shows an upstream tool name that reads as guidance only as escaped, delimited data on the card", async () => {
    // Real gate (a Tier 1 proxied tool) -> structured record -> bridge projection -> the console's renderers.
    const { request, reason } = await heldThroughGate(
      policyWith({ first_session_policy: "log" }),
      GUIDANCE_SHAPED_TOOL,
      {},
      (gate) => gate.setProxyTierResolver(() => 1),
    );
    expect(reason).toEqual({ code: "proxy_tier1", subject: GUIDANCE_SHAPED_TOOL });
    const card = projectCharterApproval(
      { id: "hold-1", operation: request.operation, tier: request.tier, created_at: request.timestamp, hold_reason: reason },
      "operator-identity",
    );
    const renderers = clientCardRenderers();
    const quoted = heldSubjectText(GUIDANCE_SHAPED_TOOL);
    const surfaces: Array<[string, string, string]> = [
      ["What it wants to do", renderers.approvalTextHtml(card), `Run a Tier 1 operation: ${SUBJECT_SLOT}.`],
      ["Operation", renderers.approvalOperationHtml(card), SUBJECT_SLOT],
      [
        "Why it is held",
        renderers.approvalHoldReasonHtml(card),
        `Proxied tool ${SUBJECT_SLOT} is configured as Tier 1, so it always asks for approval.`,
      ],
    ];
    for (const [surface, html, expected] of surfaces) {
      const { prose, subjects } = splitHeldReason(html);
      expect(prose, surface).toBe(expected);
      expect(subjects, surface).toEqual([quoted]);
      expectConsoleWordsOnly(prose);
    }
    // In plain text (a filter option, feedback) the name keeps its quoted form.
    expect(renderers.approvalOperationText(card)).toBe(quoted);
  });

  it("shows hidden and reordering characters in an identifier as visible escapes", () => {
    const hidden = "notes\u202e\u200b\u0007\u0085\ufeff\u206a\ufff9\u{e0001}\u{e0041}end";
    const card = {
      item_id: "charter.approval.hold-1",
      tier: "tier2",
      operation_category: "other",
      display_template_id: "approval_pending.tier2.other",
      display_template_args: [{ kind: "operation", value: `proxy/${hidden}` }],
      hold_reason: { code: "first_namespace_access", subject: hidden },
    };
    const renderers = clientCardRenderers();
    const shown = "notes\\u202e\\u200b\\u0007\\u0085\\ufeff\\u206a\\ufff9\\u{e0001}\\u{e0041}end";
    expect(splitHeldReason(renderers.approvalHoldReasonHtml(card)).subjects).toEqual([`"${shown}"`]);
    expect(splitHeldReason(renderers.approvalOperationHtml(card)).subjects).toEqual([`"proxy/${shown}"`]);
    expect(splitHeldReason(renderers.approvalTextHtml(card)).subjects).toEqual([`"proxy/${shown}"`]);
    for (const html of [renderers.approvalHoldReasonHtml(card), renderers.approvalOperationHtml(card), renderers.approvalTextHtml(card)]) {
      expect(html).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
    }
  });

  it("falls back to a fixed sentence naming the tier and operation for an unrecognised reason", () => {
    const html = clientHoldReasonRenderer()({
      item_id: "charter.approval.hold-1",
      tier: "tier2",
      operation_category: "other",
      display_template_args: [{ kind: "operation", value: "state_write" }],
      hold_reason: { code: "unrecognized" },
    });
    const { prose, subjects } = splitHeldReason(html);
    expect(prose).toBe(`Held under the operator policy (Tier 2): ${SUBJECT_SLOT}`);
    expect(subjects).toEqual(['"state_write"']);
  });
});
