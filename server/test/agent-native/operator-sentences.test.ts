/** The operator sentences a session with no confirmed identity carries, and the unconfirmed default-binding note, are frozen text. */
import { expect, it } from "vitest";
import { UNBOUND_OPERATOR_ACTION, UNCONFIRMED_OPERATOR_ACTION } from "../../src/agent-native/capabilities-catalog.js";
import { SOLE_BINDING_UNCONFIRMED_NOTE } from "../../src/config.js";

it("the two operator sentences equal their frozen text", () => {
  expect(UNBOUND_OPERATOR_ACTION).toBe("This session has no Sanctuary identity. Tell your operator; they can enable default binding with sanctuary session-binding enable or name an identity with SANCTUARY_SESSION_IDENTITY_ID, then restart this server.");
  expect(UNCONFIRMED_OPERATOR_ACTION).toBe("This session's identity could not be confirmed. Tell your operator and restart this server.");
});

it("the unconfirmed default-binding note equals its frozen text", () => {
  expect(SOLE_BINDING_UNCONFIRMED_NOTE).toBe("  Note: default session binding could not be confirmed; check with `sanctuary session-binding status`.");
});
