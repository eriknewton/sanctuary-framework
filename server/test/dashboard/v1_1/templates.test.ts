/**
 * Sanctuary v1.1 Dashboard — Template Registry tests.
 *
 * Covers:
 *  - Required test 5: unknown template id renders safe diagnostic fallback,
 *    does NOT throw.
 *  - Coverage assertion: every Tier 1 operation_category, every privacy
 *    event kind, every blocked_egress reason class has a registered entry.
 */
// fail-before-exempt: slice 6a anchors the approved pending-removal sentence exactly; this inherited sentence already passes on the base, as does mirror parity.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  heldSubjectText,
  renderTemplate,
  listRegisteredTemplateIds,
} from "../../../src/dashboard/v1_1/templates.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import {
  SUBJECT_SLOT,
  clientDeclarations,
  decodeHtmlText,
  extractClientDeclaration,
  splitHeldReason,
} from "./client-script-extract.js";
import { STATUS_MAPPING } from "../../../src/dashboard/v1_1/status-mapping.js";
import type { HubDisplayTemplateArg } from "../../../src/contracts/v1.1/hub-events.js";
import {
  OPERATION_NAME_CATEGORIES,
  projectCharterApproval,
} from "../../../src/hub/charter-approval-bridge.js";

/**
 * Extracts the key set of the client's `TEMPLATES` mirror map by
 * EVALUATING the map literal from the embedded client script (the client
 * is plain TS-as-string; there is no importable client TEMPLATES export).
 * Evaluating the real object literal, rather than regex-matching entry
 * spellings, means any entry syntax that parses contributes its key, so a
 * differently-written entry cannot evade the parity check. Rendering tests
 * invoke those arrow functions through the client's own `arg` helper, sliced
 * from the same embedded script; slicing failures throw rather than returning
 * an empty set (fail-loud, never a vacuous pass).
 */
function extractClientTemplateIds(): string[] {
  return Object.keys(extractClientTemplates()).sort();
}

type ClientArgHelpers = {
  arg: (args: Array<{ kind: string; value: unknown }>, kind: string, fallback?: string) => string;
  hasArgValue: (args: unknown, kind: string) => boolean;
  agentOr: (args: unknown, neutral: string) => string;
  heldOperationSentence: (args: unknown, tier: string) => string;
  heldOperationSentenceHtml: (args: unknown, tier: string, truncated: boolean) => string;
  heldSubjectText: (value: unknown) => string;
  HELD_OPERATION_TEMPLATE_TIERS: Record<string, string>;
};

// The console's escaping helpers the template helpers call, sliced from the same script.
const CLIENT_ESCAPE_DECLARATIONS = [
  "escHtml",
  "HELD_SUBJECT_HIDDEN_CHARS",
  "LAST_FOUR_DIGIT_ESCAPE_CODE_POINT",
  "heldSubjectText",
  "heldSubjectHtml",
];

/**
 * The client's template helpers (`arg` and the helpers declared after it, up to
 * the TEMPLATES map), sliced from the embedded script and evaluated together so
 * the mirrored templates call the client's own code.
 */
function extractClientHelpers(): ClientArgHelpers {
  const script = getClientScript();
  const marker = "function arg(args, kind, fallback) {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client arg helper not found in embedded script");
  }
  const endMarker = "\n\n// Cross-file contract:";
  const end = script.indexOf(endMarker, start);
  if (end === -1) {
    throw new Error("client arg helper close brace not found");
  }
  const fnText = script.slice(start, end);
  const escaping = CLIENT_ESCAPE_DECLARATIONS.map(extractClientDeclaration).join("\n");
  return new Function(
    `"use strict"; ${escaping}\n${fnText}; return { arg, hasArgValue, agentOr, heldOperationSentence, heldOperationSentenceHtml, heldSubjectText, HELD_OPERATION_TEMPLATE_TIERS };`,
  )() as ClientArgHelpers;
}

/** The client's own shortTime, which its activity.lifecycle mirror calls. */
function extractClientShortTime(): (iso: string) => string {
  return clientDeclarations<{ shortTime: (iso: string) => string }>(["shortTime"], ["shortTime"]).shortTime;
}

/** The console's Operation label for a card (client approvalOperation), run from the embedded script. */
function extractClientApprovalOperation(): (item: unknown) => string {
  return clientDeclarations<{ approvalOperation: (item: unknown) => string }>(
    ["approvalArg", "approvalOperation"],
    ["approvalOperation"],
  ).approvalOperation;
}

function extractClientTemplates(): Record<string, (args: unknown[]) => string> {
  const script = getClientScript();
  const marker = "const TEMPLATES = {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client TEMPLATES map not found in embedded script");
  }
  const end = script.indexOf("\n};", start);
  if (end === -1) {
    throw new Error("client TEMPLATES map close brace not found");
  }
  // Reconstruct the full object literal and evaluate it. The block text
  // between the marker and the close brace is the literal's body.
  const objectLiteral =
    "{" + script.slice(start + marker.length, end) + "\n}";
  const helpers = extractClientHelpers();
  const evaluated = new Function(
    "arg",
    "hasArgValue",
    "agentOr",
    "heldOperationSentence",
    "shortTime",
    `"use strict"; return (${objectLiteral});`,
  )(helpers.arg, helpers.hasArgValue, helpers.agentOr, helpers.heldOperationSentence, extractClientShortTime()) as Record<
    string,
    (args: unknown[]) => string
  >;
  if (Object.keys(evaluated).length === 0) {
    throw new Error("client TEMPLATES map evaluated to an empty object");
  }
  return evaluated;
}

function extractClientStatusMap(): Record<string, { label: string; glyph: string }> {
  const script = getClientScript();
  const marker = "const STATUS_MAP = {";
  const start = script.indexOf(marker);
  if (start === -1) {
    throw new Error("client STATUS_MAP not found in embedded script");
  }
  const end = script.indexOf("\n};", start);
  if (end === -1) {
    throw new Error("client STATUS_MAP close brace not found");
  }
  const objectLiteral =
    "{" + script.slice(start + marker.length, end) + "\n}";
  const evaluated = new Function(`"use strict"; return (${objectLiteral});`)() as
    Record<string, { label: string; glyph: string }>;
  if (Object.keys(evaluated).length === 0) {
    throw new Error("client STATUS_MAP evaluated to an empty object");
  }
  return evaluated;
}

describe("v1.1 dashboard template registry", () => {
  it("renders a known template with typed args", () => {
    const out = renderTemplate(
      "approval_pending.tier1.lockdown",
      [{ kind: "agent_id", value: "agent-alpha" }],
    );
    expect(out).toContain("agent-alpha");
    expect(out.toLowerCase()).toContain("network access");
  });

  it("returns a diagnostic fallback for an unknown template id (no throw)", () => {
    expect(() => {
      const out = renderTemplate("approval_pending.tier1.fictional", []);
      expect(out).toBe("[unrecognized template: approval_pending.tier1.fictional]");
    }).not.toThrow();
  });

  it("registers entries for every Tier 1 operation_category", () => {
    const required = [
      "state_export",
      "state_import",
      "state_delete",
      "identity_rotate",
      "reputation_export",
      "reputation_import",
      "sanctuary_export_identity_bundle",
      "exit_bundle_export",
      "exit_bundle_import",
      "exit_bundle_rekey",
      "policy_change",
      "lockdown",
      "fortress_lockdown",
      "unwrap",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const op of required) {
      expect(ids).toContain(`approval_pending.tier1.${op}`);
    }
  });

  it("registers entries for every privacy event kind", () => {
    const kinds = ["filtered", "allowed", "denied", "error", "rehydrated"];
    const ids = listRegisteredTemplateIds();
    for (const k of kinds) expect(ids).toContain(`privacy_event.${k}`);
  });

  it("registers entries for every blocked_egress reason class", () => {
    const reasons = [
      "egress_policy_deny",
      "budget_exceeded",
      "privacy_fail_closed",
      "privacy_deny_rule",
      "lockdown_active",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const r of reasons) expect(ids).toContain(`blocked_egress.${r}`);
  });

  it("registers entries for every recovery_class", () => {
    const classes = [
      "passphrase_reset",
      "keychain_rebind",
      "config_backup_restore",
      "exit_drill",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const c of classes) expect(ids).toContain(`recovery_prompt.${c}`);
  });

  it("registers entries for every activity feed category", () => {
    const cats = [
      "policy_decision",
      "approval",
      "denial",
      "egress",
      "privacy",
      "handoff",
      "lifecycle",
      "config",
      "other",
    ];
    const ids = listRegisteredTemplateIds();
    for (const c of cats) expect(ids).toContain(`activity.${c}`);
  });

  it("registers entries for every lockdown activity operation this build emits", () => {
    const ops = [
      "agent_lockdown_engaged",
      "agent_lockdown_partial",
      "agent_lockdown_refused",
      "fortress_lockdown_engaged",
      "fortress_lockdown_partial",
      "fortress_lockdown_failed",
      "fortress_lockdown_no_agents",
    ];
    for (const op of ops) {
      const templateId = `activity.lifecycle.${op}`;
      const out = renderTemplate(templateId, [
        { kind: "agent_id", value: "agent-alpha" },
        { kind: "iso8601", value: "2026-08-08T00:00:00.000Z" },
      ]);
      expect(out).not.toContain("[unrecognized template");
    }
  });

  it("does not interpolate unknown args into the fallback string", () => {
    // Args are NOT echoed into the fallback (defense-in-depth for any arg
    // shape that might carry sensitive content via a future broken
    // backend).
    const out = renderTemplate("totally.fake.id", [
      { kind: "agent_id", value: "secret-agent-xyz" },
    ]);
    expect(out).not.toContain("secret-agent-xyz");
  });

  it("keeps the client TEMPLATES mirror (client.ts) in full-set parity with the server registry (IC-24)", () => {
    // Full-set equality in BOTH directions: a server template with no
    // client mirror falls through to "[unrecognized template: ...]" on a
    // live operator-facing approval or activity card (the IC-24 shape);
    // a client-only orphan is dead code masquerading as a live template.
    // A test that only samples a handful of ids (as the rest of this file
    // deliberately does, per rule 5 in AGENTS.md) cannot catch a single
    // missing entry in a 60-entry registry; only a full-set diff can.
    const serverIds = listRegisteredTemplateIds();
    const clientIds = extractClientTemplateIds();

    const missingFromClient = serverIds.filter((id) => !clientIds.includes(id));
    const orphanedInClient = clientIds.filter((id) => !serverIds.includes(id));

    expect(
      missingFromClient,
      `template ids registered on the server but missing from the client mirror: ${missingFromClient.join(", ")}`,
    ).toEqual([]);
    expect(
      orphanedInClient,
      `template ids in the client mirror with no server registry entry: ${orphanedInClient.join(", ")}`,
    ).toEqual([]);
  });

  it("keeps every mirrored client template and status label in parity with the server tables", () => {
    // Full-set equality (AGENTS.md rule 5): the two catalogs carry the same id
    // set, and every id renders the same text on both sides for an empty arg
    // list and for each sample list, so no drifted sibling can hide behind a
    // passing first entry. The client mirror has no render context and always
    // writes the past-tense activity wording, so it is compared with the
    // server's activity surface.
    const clientTemplates = extractClientTemplates();
    const serverIds = listRegisteredTemplateIds();
    expect(Object.keys(clientTemplates).sort()).toEqual(serverIds);
    const ARG_SAMPLES: HubDisplayTemplateArg[][] = [
      [],
      [
        { kind: "agent_id", value: "agent-alpha" },
        { kind: "identity_id", value: "identity-beta" },
        { kind: "operation", value: "state_write" },
      ],
      [
        { kind: "agent_id", value: "agent-alpha" },
        { kind: "channel_template_id", value: "channel-beta" },
        { kind: "destination_category", value: "tool-api" },
        { kind: "policy_id", value: "policy-delta" },
        { kind: "iso8601", value: "2026-10-21T14:36:00.000Z" },
        { kind: "tier", value: "tier2" },
      ],
    ];
    const drifted: string[] = [];
    for (const id of serverIds) {
      for (const args of ARG_SAMPLES) {
        const client = clientTemplates[id]!(args);
        const server = renderTemplate(id, args, { surface: "activity" });
        if (client !== server) drifted.push(`${id} with ${args.length} args: client "${client}" server "${server}"`);
      }
    }
    expect(drifted).toEqual([]);

    const clientStatus = extractClientStatusMap();
    const serverStatusKeys = Object.keys(STATUS_MAPPING).sort();
    const clientStatusKeys = Object.keys(clientStatus).sort();
    const missingFromClientStatus = serverStatusKeys.filter((key) => !clientStatusKeys.includes(key));
    const clientOnlyStatusKeys = clientStatusKeys.filter((key) => !serverStatusKeys.includes(key));
    const KNOWN_CLIENT_ONLY_STATUS_KEYS: string[] = [];
    expect(
      missingFromClientStatus,
      `status keys registered on the server but missing from the client mirror: ${missingFromClientStatus.join(", ")}`,
    ).toEqual([]);
    expect(
      clientOnlyStatusKeys,
      `status keys in the client mirror with no server status table entry: ${clientOnlyStatusKeys.join(", ")}`,
    ).toEqual(KNOWN_CLIENT_ONLY_STATUS_KEYS);
    const statusDrift = (Object.keys(STATUS_MAPPING) as Array<keyof typeof STATUS_MAPPING>)
      .filter((key) => clientStatus[key]?.label !== STATUS_MAPPING[key].label || clientStatus[key]?.glyph !== STATUS_MAPPING[key].glyph)
      .map((key) => ({ key, client: clientStatus[key], server: STATUS_MAPPING[key] }));
    // Known drift: the client labels an active agent "Protected" where the
    // server table says "Running". Resolving which word the evidence supports
    // is a separate change; a new drifted key fails this test.
    expect(statusDrift.map((row) => row.key)).toEqual(["active"]);
  });

  it("renders the fortress lockdown approval template with consequences", () => {
    const out = renderTemplate("approval_pending.tier1.fortress_lockdown", []);
    expect(out).toContain("Lockdown approval pending");
    expect(out).toContain("revokes network access");
    expect(out).not.toContain("writes are blocked");
    expect(out).not.toContain("[unrecognized template");
  });
});

it("anchors the approved pending-removal sentence", () => {
  expect(renderTemplate("approval_pending.tier1.unwrap", [{ kind: "agent_id", value: "agent-alpha" }])).toBe("Request to remove protection from agent agent-alpha. This build refuses unsupported removals before approval is queued.");
});

// A configured requester with a distinctive id, so any sentence that names it is caught.
const CHARTER_REQUESTER = "agent:claude-code:fortress-requester-a";
// Placeholders an audience reads as a bug; no approval card may carry one.
const CARD_PLACEHOLDERS = ["(unknown)", "(no agent)"];
// An operation with no category of its own, which the bridge files as "other": the demo's first write to a new
// namespace is one.
const UNCATEGORIZED_OPERATION = "state_write";
// Why the gate held that call, as the queue record carries it (classifyHoldReason).
const NAMESPACE_HOLD_REASON = { code: "first_namespace_access", subject: "customer-notes" } as const;

/**
 * The exact sentence every Charter card renders, by operation, for Tier 1. A
 * card whose catalog sentence would default its target (TARGET_DEFAULTING_CATEGORIES
 * in server/src/hub/charter-approval-bridge.ts) and an uncategorized operation
 * use the catch-all, which names the operation and no target. Pinned whole so a
 * new or reworded sentence is read before it ships.
 */
const TIER1_CHARTER_SENTENCES: Record<string, string> = {
  state_export: "Export state from this fortress as a portable bundle.",
  state_import: "Import state into this fortress.",
  state_delete: "Delete stored state from this fortress. This is irreversible.",
  identity_rotate: 'Run a Tier 1 operation: "identity_rotate".',
  reputation_export: "Export a reputation bundle from this fortress.",
  reputation_import: "Import a reputation bundle into this fortress.",
  sanctuary_export_identity_bundle: 'Run a Tier 1 operation: "sanctuary_export_identity_bundle".',
  [UNCATEGORIZED_OPERATION]: `Run a Tier 1 operation: "${UNCATEGORIZED_OPERATION}".`,
};

it("renders every Charter card category at both tiers without a placeholder, the requester, or \"other\" as its operation, on server and client", () => {
  // Full-set (AGENTS.md rule 5): every category the bridge can emit, plus the
  // catch-all, is projected and rendered by both catalogs and labelled by the
  // console's own approvalOperation, so a later category whose sentence falls
  // back to a placeholder or a defaulted target cannot slip through.
  const clientTemplates = extractClientTemplates();
  const clientOperation = extractClientApprovalOperation();
  const operations = [...OPERATION_NAME_CATEGORIES, UNCATEGORIZED_OPERATION];
  expect(Object.keys(TIER1_CHARTER_SENTENCES).sort()).toEqual([...operations].sort());
  for (const operation of operations) {
    for (const tier of [1, 2] as const) {
      const card = projectCharterApproval(
        {
          id: "hold-1",
          operation,
          tier,
          created_at: "2026-10-21T00:00:00.000Z",
          requesting_agent_id: CHARTER_REQUESTER,
          hold_reason: NAMESPACE_HOLD_REASON,
        },
        "operator-identity",
      );
      const label = `${operation} tier ${tier}`;
      expect(card.agent_id, label).toBe(CHARTER_REQUESTER);
      expect(card.display_template_args.some((a) => a.kind === "agent_id"), label).toBe(false);
      // Why it is held rides on the card as structured data only.
      expect(card.hold_reason, label).toEqual(NAMESPACE_HOLD_REASON);
      // The console names the held operation, never the catch-all category.
      expect(clientOperation(card), label).toBe(operation);
      const client = clientTemplates[card.display_template_id];
      expect(client, `${card.display_template_id} has a client mirror`).toBeDefined();
      const expected =
        tier === 1 ? TIER1_CHARTER_SENTENCES[operation] : `Run a Tier 2 operation: "${operation}".`;
      for (const sentence of [
        renderTemplate(card.display_template_id, card.display_template_args),
        client!(card.display_template_args),
      ]) {
        expect(sentence, label).toBe(expected);
        expect(sentence, label).not.toContain(CHARTER_REQUESTER);
        for (const placeholder of CARD_PLACEHOLDERS) expect(sentence, label).not.toContain(placeholder);
        expect(sentence, label).not.toMatch(/\bother\b/);
      }
    }
  }
});

it("renders every approval_pending sentence identically on server and client, with no placeholder when the card names no target", () => {
  // Full-set over the catalog, not only the categories the bridge emits today:
  // a hub-enqueued card with a missing target must read as plain copy, and the
  // two renderers must agree on it word for word.
  const clientTemplates = extractClientTemplates();
  const ids = listRegisteredTemplateIds().filter((id) => id.startsWith("approval_pending."));
  expect(ids.length).toBeGreaterThan(0);
  const withTarget: HubDisplayTemplateArg[] = [
    { kind: "agent_id", value: "agent-alpha" },
    { kind: "identity_id", value: "identity-beta" },
    { kind: "operation", value: "state_write" },
  ];
  for (const id of ids) {
    expect(clientTemplates[id], `${id} has a client mirror`).toBeDefined();
    for (const args of [[], withTarget]) {
      const server = renderTemplate(id, args);
      expect(clientTemplates[id]!(args), `${id} with ${args.length} args`).toBe(server);
      expect(server.startsWith("["), id).toBe(false);
    }
    const empty = renderTemplate(id, []);
    for (const placeholder of CARD_PLACEHOLDERS) expect(empty, id).not.toContain(placeholder);
  }
});

it("registers every approval_pending template id a producer emits", () => {
  // The hub's task review card is the producer outside the Charter bridge; an
  // emitted id with no entry renders "[unrecognized template: ...]" on a live card.
  const hubSource = readFileSync(new URL("../../../src/hub/hub-service.ts", import.meta.url), "utf8");
  const emitted = [...hubSource.matchAll(/\$\{HUB_INBOX_TEMPLATE_NAMESPACES\.approval_pending\}\.([a-z0-9_]+\.[a-z0-9_]+)`/g)].map(
    (m) => `approval_pending.${m[1]}`,
  );
  expect(emitted).toContain("approval_pending.task.ready_for_review");
  const registered = new Set(listRegisteredTemplateIds());
  for (const id of emitted) expect(registered.has(id), id).toBe(true);
  expect(renderTemplate("approval_pending.task.ready_for_review", [{ kind: "agent_id", value: "agent-alpha" }])).toBe(
    "Agent agent-alpha marked a task ready for review. Allow completes it; Deny returns it to work.",
  );
});

/** Every code point, in chunks small enough for one string each, skipping only the surrogate block. */
function codePointChunks(): string[] {
  // 0x10ffff is the last Unicode code point; 0xd800..0xdfff are surrogate halves, which cannot stand alone in a
  // well-formed string and are covered by the lone-surrogate case below.
  const LAST_CODE_POINT = 0x10ffff;
  const SURROGATE_FIRST = 0xd800;
  const SURROGATE_LAST = 0xdfff;
  // 4096 code points per chunk keeps each string small; the size has no other meaning.
  const CHUNK = 4096;
  const chunks: string[] = [];
  for (let start = 0; start <= LAST_CODE_POINT; start += CHUNK) {
    let text = "";
    for (let cp = start; cp < Math.min(start + CHUNK, LAST_CODE_POINT + 1); cp++) {
      if (cp >= SURROGATE_FIRST && cp <= SURROGATE_LAST) continue;
      text += String.fromCodePoint(cp);
    }
    chunks.push(text);
  }
  return chunks;
}

it("escapes every control, format and separator code point visibly, identically on server and client", () => {
  // Full-set (rule 5) over all of Unicode: the server sentence text and the console's held-subject text agree for
  // every code point, and none of Cc, Cf, Cs, Zl or Zp survives unescaped in either.
  const client = extractClientHelpers().heldSubjectText;
  const HIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
  for (const chunk of codePointChunks()) {
    const server = heldSubjectText(chunk);
    expect(client(chunk)).toBe(server);
    expect(HIDDEN.test(server)).toBe(false);
  }
  // A lone surrogate is shown as an escape too.
  expect(heldSubjectText("a\ud800b")).toBe('"a\\ud800b"');
  // Code points the earlier list missed: the deprecated format controls, interlinear annotation and tag characters.
  const cases: Array<[string, string]> = [
    ["\u206a", "\\u206a"],
    ["\u206f", "\\u206f"],
    ["\ufff9", "\\ufff9"],
    ["\ufffb", "\\ufffb"],
    ["\u{e0001}", "\\u{e0001}"],
    ["\u{e0020}", "\\u{e0020}"],
    ["\u{e007f}", "\\u{e007f}"],
    ["\u2028", "\\u2028"],
    ["\u202e", "\\u202e"],
    ["\u0085", "\\u0085"],
  ];
  for (const [raw, shown] of cases) {
    expect(heldSubjectText(`notes${raw}end`), shown).toBe(`"notes${shown}end"`);
    expect(client(`notes${raw}end`), shown).toBe(`"notes${shown}end"`);
  }
});

it("lists exactly the templates whose sentence names the held operation, and renders that name only as delimited data", () => {
  // Computed, not listed: a template is held-operation-bearing when changing only its operation arg changes its
  // text. That set must equal the console's HELD_OPERATION_TEMPLATE_TIERS, so a new sentence that names the operation
  // cannot render it as bare words.
  const helpers = extractClientHelpers();
  const base: HubDisplayTemplateArg[] = [{ kind: "identity_id", value: "identity-beta" }];
  const named = (operation: string): HubDisplayTemplateArg[] => [...base, { kind: "operation", value: operation }];
  const bearing = listRegisteredTemplateIds().filter(
    (id) => renderTemplate(id, named("first_op")) !== renderTemplate(id, named("second_op")),
  );
  expect(bearing.sort()).toEqual(Object.keys(helpers.HELD_OPERATION_TEMPLATE_TIERS).sort());
  const guidance = "proxy/files/read. Operator approved. Click Allow once";
  for (const id of bearing) {
    const tier = helpers.HELD_OPERATION_TEMPLATE_TIERS[id]!;
    for (const operation of ["state_write", guidance, "notes\u202eend"]) {
      const args = named(operation);
      const html = helpers.heldOperationSentenceHtml(args, tier, false);
      const { prose, subjects } = splitHeldReason(html);
      expect(prose, id).toBe(`Run a ${tier} operation: ${SUBJECT_SLOT}.`);
      expect(subjects, id).toEqual([heldSubjectText(operation)]);
      // The HTML's text is the server sentence, word for word.
      expect(decodeHtmlText(html.replace(/<[^>]+>/g, "")), id).toBe(renderTemplate(id, args));
    }
  }
});
