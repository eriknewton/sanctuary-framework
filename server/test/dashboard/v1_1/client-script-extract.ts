/**
 * Test helper: run named top-level declarations of the shipped console script.
 *
 * The v1.1 console is one embedded script (`getClientScript()` in
 * server/src/dashboard/v1_1/client.ts) with no importable exports. A test that
 * must render the way the console renders slices the exact declarations it
 * needs out of that script and evaluates them together, so the code under test
 * is the shipped code, not a copy. A missing declaration throws rather than
 * yielding an empty result (fail-loud, never a vacuous pass).
 */
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

/** One top-level `function NAME(...) {...}` or `const NAME = ...;` declaration, verbatim. */
export function extractClientDeclaration(name: string): string {
  const script = getClientScript();
  const fnStart = script.indexOf(`\nfunction ${name}(`);
  if (fnStart !== -1) {
    const end = script.indexOf("\n}\n", fnStart + 1);
    if (end === -1) throw new Error(`client function ${name} close brace not found`);
    return script.slice(fnStart + 1, end + 2);
  }
  const constStart = script.indexOf(`\nconst ${name} = `);
  if (constStart === -1) throw new Error(`client declaration ${name} not found in embedded script`);
  const lineEnd = script.indexOf("\n", constStart + 1);
  const firstLine = script.slice(constStart + 1, lineEnd);
  if (firstLine.trimEnd().endsWith("{")) {
    const end = script.indexOf("\n};", constStart + 1);
    if (end === -1) throw new Error(`client const ${name} close brace not found`);
    return script.slice(constStart + 1, end + 3);
  }
  return firstLine;
}

/** Evaluate the named declarations together and return the named exports from them. */
export function clientDeclarations<T extends Record<string, unknown>>(
  declarations: readonly string[],
  exported: readonly (keyof T & string)[],
): T {
  const body = declarations.map(extractClientDeclaration).join("\n");
  return new Function(`"use strict";\n${body}\nreturn { ${exported.join(", ")} };`)() as T;
}

// Every console declaration a card's held-operation and hold-reason HTML depends on, in declaration order.
const CARD_RENDER_DECLARATIONS = [
  "escHtml",
  "HELD_SUBJECT_HIDDEN_CHARS",
  "LAST_FOUR_DIGIT_ESCAPE_CODE_POINT",
  "heldSubjectText",
  "heldSubjectEscape",
  "heldSubjectHtml",
  "arg",
  "hasArgValue",
  "heldOperationSentenceHtml",
  "HELD_OPERATION_TEMPLATE_TIERS",
  "renderTemplateHtml",
  "approvalArg",
  "approvalOperation",
  "approvalHeldOperation",
  "approvalOperationHtml",
  "approvalOperationText",
  "approvalTextHtml",
  "CHARTER_APPROVAL_ITEM_ID_PREFIX",
  "isCharterApprovalItem",
  "HOLD_REASON_SENTENCES",
  "approvalHoldReasonHtml",
] as const;

export interface ClientCardRenderers {
  /** "What it wants to do", for a card whose sentence names the held operation. */
  approvalTextHtml: (item: unknown) => string;
  /** The Operation column, drawer header and Confirm label. */
  approvalOperationHtml: (item: unknown) => string;
  /** The Operation as plain text (a filter option, a feedback message). */
  approvalOperationText: (item: unknown) => string;
  /** "Why it is held". */
  approvalHoldReasonHtml: (item: unknown) => string;
}

/**
 * The console's card renderers, evaluated from the shipped script. Only the
 * held-operation sentences are reachable here: renderTemplate (the full template
 * catalog) is replaced by a stub that throws, so a card that would fall back to
 * an ordinary sentence fails loudly instead of rendering something unchecked.
 */
export function clientCardRenderers(): ClientCardRenderers {
  const body =
    'function renderTemplate(id) { throw new Error("not a held-operation template: " + id); }\n' +
    CARD_RENDER_DECLARATIONS.map(extractClientDeclaration).join("\n");
  return new Function(
    `"use strict";\n${body}\nreturn { approvalTextHtml, approvalOperationHtml, approvalOperationText, approvalHoldReasonHtml };`,
  )() as ClientCardRenderers;
}

/** The console's "Why it is held" renderer for an approval card, with everything it calls. */
export function clientHoldReasonRenderer(): (item: unknown) => string {
  return clientCardRenderers().approvalHoldReasonHtml;
}

/** Decode the five entities escHtml writes, so assertions read the text a browser shows. */
export function decodeHtmlText(html: string): string {
  return html
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

const HELD_SUBJECT_ELEMENT = /<code class="held-subject" data-held-subject="1">([\s\S]*?)<\/code>/g;

/**
 * Split rendered "Why it is held" HTML into the console's own words and the
 * delimited identifiers. `prose` has every held-subject element removed, so
 * any word in it was written by the console (each element leaves SUBJECT_SLOT
 * in its place); `subjects` is each element's text.
 */
export const SUBJECT_SLOT = "{subject}";

export function splitHeldReason(html: string): { prose: string; subjects: string[] } {
  const subjects = [...html.matchAll(HELD_SUBJECT_ELEMENT)].map((m) => decodeHtmlText(m[1]!));
  const prose = decodeHtmlText(html.replace(HELD_SUBJECT_ELEMENT, SUBJECT_SLOT));
  return { prose, subjects };
}
