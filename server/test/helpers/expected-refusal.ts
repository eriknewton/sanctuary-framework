/**
 * The one refusal a registered tool's non-success outcome reaches the agent
 * as, written out literally so a witness compares the wire result against a
 * fixed expectation instead of against the implementation under test.
 *
 * Must match REFUSAL_TEXT in server/src/agent-native/safety-base.ts. The
 * parity test in test/agent-native/refusal-literal-parity.test.ts asserts that
 * expectedRefusal() deep-equals refusalResult().
 */

const EXPECTED_REFUSAL_BODY = Object.freeze({
  denied: true,
  message: "This action is not available in the current context.",
  remediation_class: "request_review",
  retry_after: null,
  audit_ref: "audit:refusal",
  discovery_hint:
    "Do not repeat this call as it is. Change the request, or tell your operator what you were trying to do. "
    + "To find the sanctioned Sanctuary tool for a need, call sanctuary_help with your intent, "
    + "or sanctuary_capabilities for the catalog.",
} as const);

/** Compact serialization, in the body's field order. */
export const EXPECTED_REFUSAL_TEXT: string = JSON.stringify(EXPECTED_REFUSAL_BODY);

/** The parsed refusal body. */
export function expectedRefusalBody(): typeof EXPECTED_REFUSAL_BODY {
  return EXPECTED_REFUSAL_BODY;
}

/** The complete MCP result: one text item and isError, with no other key. */
export function expectedRefusal(): { content: Array<{ type: "text"; text: string }>; isError: true } {
  return { content: [{ type: "text", text: EXPECTED_REFUSAL_TEXT }], isError: true };
}
