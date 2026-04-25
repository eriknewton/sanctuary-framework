/**
 * Sanctuary v1.1 Dashboard — Privacy panel safety tests.
 *
 * Covers:
 *  - Required test 4: PrivacyAuditPayload renders only safe metadata.
 *    raw_path, raw_value, source bytes are NOT in the DOM. content_hash
 *    visible only as opaque hex.
 *  - Required test 11: magic-string-wire-byte privacy test. Fixture
 *    privacy event with magic redacted value; assert magic value never
 *    appears in dashboard output. Mirrors the PR #71 pattern.
 *
 * Implementation: lift the renderPrivacyPage closure out of the client
 * script and exercise it against a fake state object.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

/**
 * Lift `renderPrivacyPage` and the helpers it needs into a sandbox so
 * we can call it against a synthetic state. We strip the boot tail of
 * the client (fetch/SSE wire-up) so nothing tries to call window.fetch
 * inside the test runner.
 */
function liftPrivacyRenderer(): {
  render: (state: unknown) => string;
} {
  const src = getClientScript();
  // Lift the chunk from the start through the end of the
  // renderPrivacyPage definition. Stop before the boot-time API calls.
  let beforeBoot = src.slice(0, src.indexOf("// ── Render: coordination"));
  // The client declares `const state = {...}` at module top. Rewriting
  // to `var state` lets the test fixture reassign it via the wrapper
  // below. This is test-only sandboxing; production code stays const.
  beforeBoot = beforeBoot.replace(/const\s+state\s*=/, "var state =");
  // Provide a tiny shim for `state` and the global helpers; redefine
  // `state` inside the wrapper to point at our fixture.
  const wrapper = `
    var document = { getElementById: () => null };
    var window = { matchMedia: () => null };
    var sessionStorage = { getItem: () => null, setItem: () => null };
    var location = { hash: "", host: "test" };
    ${beforeBoot}
    return function (s) { state = s; return renderPrivacyPage(); };
  `;
  // eslint-disable-next-line no-new-func
  const factory = new Function(wrapper) as () => (s: unknown) => string;
  return { render: factory() };
}

const MAGIC = "MAGIC_PRIVACY_REDACTED_xQ7K9zL3";

describe("v1.1 dashboard privacy panel safety", () => {
  const { render } = liftPrivacyRenderer();

  function fakeState(extras: object = {}): object {
    return {
      route: "privacy",
      agents: [],
      inbox: [],
      activity: [],
      policies: [],
      privacyEvents: [],
      handoffEvents: [],
      topbarPills: {},
      tier1: { lockdown: { state: "idle", inboxItemId: null } },
      exitDrill: { step: 1, inboxItemId: null, bundleResult: null },
      selectedAgentId: null,
      chatActiveAgentId: null,
      seenEventIds: new Set(),
      sidebarCollapsed: false,
      ...extras,
    };
  }

  it("renders only safe metadata fields from PrivacyAuditPayload", () => {
    const html = render(
      fakeState({
        privacyEvents: [
          {
            entry_id: "e-1",
            emitted_at: "2026-04-25T10:00:00.000Z",
            agent_id: "agent-x",
            category: "privacy",
            payload: {
              kind: "filtered",
              destination_category: "inference",
              outbound_payload_hash:
                "abc123def4567890aabbccddeeff00112233445566778899aabbccddeeff0011",
              field_decisions: [
                {
                  field_path: "$0",
                  detector_class: "person",
                  action: "redact",
                  content_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                  hash_alg: "hmac-sha256-fortress-keyed-v1",
                  placeholder_label: "PERSON_1",
                },
              ],
            },
          },
        ],
      }),
    );
    expect(html).toContain("filtered");
    expect(html).toContain("inference");
    expect(html).toContain("hash:");
    // No raw_value, raw_path. Even the placeholder-vault label
    // PERSON_1 may appear as it's safe metadata.
    expect(html).not.toMatch(/raw_value/i);
    expect(html).not.toMatch(/raw_path/i);
  });

  it("magic redacted value never appears in the rendered HTML", () => {
    const html = render(
      fakeState({
        privacyEvents: [
          {
            entry_id: "e-1",
            emitted_at: "2026-04-25T10:00:00.000Z",
            agent_id: "agent-x",
            category: "privacy",
            payload: {
              kind: "filtered",
              destination_category: "inference",
              // The privacy core never emits raw values, but a faulty
              // backend might. The dashboard surface MUST NOT render
              // it even if present in the payload.
              raw_value: MAGIC,
              outbound_payload_hash:
                "abc123def4567890aabbccddeeff00112233445566778899aabbccddeeff0011",
            },
          },
        ],
      }),
    );
    expect(html).not.toContain(MAGIC);
  });

  it("content_hash renders only as opaque truncated hex with tooltip", () => {
    const html = render(
      fakeState({
        privacyEvents: [
          {
            entry_id: "e-1",
            emitted_at: "2026-04-25T10:00:00.000Z",
            agent_id: "agent-x",
            category: "privacy",
            payload: {
              kind: "allowed",
              destination_category: "inference",
              outbound_payload_hash:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
          },
        ],
      }),
    );
    // Opaque-hex truncation: short prefix + ellipsis ("...").
    expect(html).toContain("0123456789ab...");
    // Tooltip framing: "Local fingerprint, not the value".
    expect(html).toContain("Local fingerprint, not the value");
  });
});
