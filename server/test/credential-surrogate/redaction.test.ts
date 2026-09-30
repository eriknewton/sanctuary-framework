/**
 * Tests for sink-level placeholder redaction.
 *
 * WHY THIS EXISTS. A placeholder is a live bearer surrogate for its generation:
 * whatever can read one can ask the gate to spend the real credential on the
 * bound destination. The agent controls several strings that reach an event sink
 * verbatim, the CONNECT authority most directly, so redaction runs at the sink
 * and covers every event kind, including ones added later by an author who did
 * not think about it.
 */

import { describe, expect, it } from "vitest";

import { mintSurrogatePlaceholder } from "../../src/credential-surrogate/placeholder.js";
import {
  SURROGATE_PLACEHOLDER_REDACTION,
  redactSurrogatePlaceholders,
  redactSurrogatePlaceholdersInString,
} from "../../src/credential-surrogate/redaction.js";

describe("string redaction", () => {
  it("replaces a bare placeholder", () => {
    const p = mintSurrogatePlaceholder();
    expect(redactSurrogatePlaceholdersInString(p)).toBe(SURROGATE_PLACEHOLDER_REDACTION);
  });

  it("replaces a placeholder embedded in a larger string and keeps the rest", () => {
    const p = mintSurrogatePlaceholder();
    expect(redactSurrogatePlaceholdersInString(`Bearer ${p}`)).toBe(
      `Bearer ${SURROGATE_PLACEHOLDER_REDACTION}`,
    );
  });

  it("replaces every occurrence, not just the first", () => {
    const a = mintSurrogatePlaceholder();
    const b = mintSurrogatePlaceholder();
    const out = redactSurrogatePlaceholdersInString(`${a} and ${b}`);
    expect(out).toBe(`${SURROGATE_PLACEHOLDER_REDACTION} and ${SURROGATE_PLACEHOLDER_REDACTION}`);
    expect(out).not.toContain(a);
    expect(out).not.toContain(b);
  });

  it("leaves a string with no placeholder untouched", () => {
    expect(redactSurrogatePlaceholdersInString("api.openai.com:443")).toBe("api.openai.com:443");
  });
});

describe("event redaction", () => {
  it("redacts a CONNECT authority, the field the agent controls most directly", () => {
    const p = mintSurrogatePlaceholder();
    const event = { kind: "egress_connect", authority: `${p}:443`, decision: "deny" };
    const out = redactSurrogatePlaceholders(event);
    expect(out.authority).toBe(`${SURROGATE_PLACEHOLDER_REDACTION}:443`);
    expect(JSON.stringify(out)).not.toContain(p);
  });

  it("redacts at any depth and inside arrays", () => {
    const p = mintSurrogatePlaceholder();
    const event = {
      kind: "gate_error",
      nested: { deeper: { authority: p }, list: [`saw ${p}`, "clean"] },
    };
    expect(JSON.stringify(redactSurrogatePlaceholders(event))).not.toContain(p);
  });

  it("leaves non-string fields as they are", () => {
    const event = { kind: "surrogate_swap", binding: 3, bytes: 128, ok: true, expires_at: null };
    expect(redactSurrogatePlaceholders(event)).toEqual(event);
  });

  it("does not mutate the event it was given", () => {
    const p = mintSurrogatePlaceholder();
    const event = { authority: p };
    const out = redactSurrogatePlaceholders(event);
    expect(event.authority).toBe(p);
    expect(out.authority).toBe(SURROGATE_PLACEHOLDER_REDACTION);
  });

  it("terminates on a self-referencing object, so a log write cannot hang", () => {
    const p = mintSurrogatePlaceholder();
    const event: Record<string, unknown> = { authority: p };
    event.self = event;
    const out = redactSurrogatePlaceholders(event) as Record<string, unknown>;
    expect(out.authority).toBe(SURROGATE_PLACEHOLDER_REDACTION);
    expect(out.self).toBe(out);
  });
});
