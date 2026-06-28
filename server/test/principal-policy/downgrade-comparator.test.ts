import { describe, expect, it } from "vitest";

import {
  DEFAULT_POLICY,
  detectPrincipalPolicyDowngrades,
} from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";

describe("Principal Policy downgrade comparator", () => {
  it("blocks disabling approval redirect", () => {
    const previous = policy({
      approval_redirect: { enabled: true, mode: "replace" },
    });
    const next = policy({
      approval_redirect: { enabled: false, mode: "replace" },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_redirect.enabled",
          reason: "approval_redirect_disabled",
        }),
      ]),
    );
  });

  it("blocks approval redirect mode downgrade from replace to notify", () => {
    const previous = policy({
      approval_redirect: { enabled: true, mode: "replace" },
    });
    const next = policy({
      approval_redirect: { enabled: true, mode: "notify" },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_redirect.mode",
          reason: "approval_redirect_mode_downgrade",
        }),
      ]),
    );
  });

  it("blocks approval channel type changes", () => {
    const previous = policy({
      approval_channel: { type: "stderr", timeout_seconds: 300 },
    });
    const next = policy({
      approval_channel: { type: "callback", timeout_seconds: 300 },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_channel.type",
          reason: "approval_channel_type_changed",
        }),
      ]),
    );
  });

  it("blocks approval channel timeout increases", () => {
    const previous = policy({
      approval_channel: { type: "stderr", timeout_seconds: 300 },
    });
    const next = policy({
      approval_channel: { type: "stderr", timeout_seconds: 600 },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_channel.timeout_seconds",
          reason: "approval_channel_timeout_increase",
        }),
      ]),
    );
  });

  it("blocks webhook target changes without exposing the target", () => {
    const previous = policy({
      approval_channel: {
        type: "webhook",
        timeout_seconds: 300,
        webhook_url: "https://approvals.invalid/a",
        webhook_secret: "secret-a",
      },
    });
    const next = policy({
      approval_channel: {
        type: "webhook",
        timeout_seconds: 300,
        webhook_url: "https://approvals.invalid/b",
        webhook_secret: "secret-a",
      },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_channel.webhook_url",
          reason: "approval_webhook_target_changed",
          previous: "configured",
          next: "changed",
        }),
      ]),
    );
  });

  it("blocks webhook secret removal or change without exposing the secret", () => {
    const previous = policy({
      approval_channel: {
        type: "webhook",
        timeout_seconds: 300,
        webhook_url: "https://approvals.invalid/hook",
        webhook_secret: "secret-a",
      },
    });
    const next = policy({
      approval_channel: {
        type: "webhook",
        timeout_seconds: 300,
        webhook_url: "https://approvals.invalid/hook",
        webhook_secret: "secret-b",
      },
    });

    expect(detectPrincipalPolicyDowngrades(previous, next)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          field: "approval_channel.webhook_secret",
          reason: "approval_webhook_secret_weakened",
          previous: "configured",
          next: "changed",
        }),
      ]),
    );
  });
});

function policy(overrides: Partial<PrincipalPolicy>): PrincipalPolicy {
  return {
    ...structuredClone(DEFAULT_POLICY),
    ...overrides,
  };
}
