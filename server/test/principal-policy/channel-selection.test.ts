import { describe, expect, it } from "vitest";
import { defaultConfig, type SanctuaryConfig } from "../../src/config.js";
import {
  CallbackApprovalChannel,
  StderrApprovalChannel,
  type ApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import {
  selectApprovalChannelByPolicy,
  type ApprovalChannelSelectionFactories,
} from "../../src/principal-policy/channel-selection.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { WebhookApprovalChannel } from "../../src/principal-policy/webhook.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";

describe("IC-14 policy-driven approval channel selection", () => {
  it("uses stderr when policy selects stderr, even when dashboard config is enabled", () => {
    const config = configWith({
      dashboard: { enabled: true, port: 4567, auto_open: false },
    });
    const selection = selectApprovalChannelByPolicy({
      config,
      policy: policyWithChannel("stderr"),
    });
    expect(selection.type).toBe("stderr");
    expect(selection.channel).toBeInstanceOf(StderrApprovalChannel);
  });

  it("uses webhook when policy selects webhook, with config params winning over legacy policy params", () => {
    const config = configWith({
      dashboard: { enabled: true, port: 4567, auto_open: false },
      webhook: {
        url: "https://config.example/approval",
        secret: "config-secret",
        callback_port: 4568,
      },
    });
    const selection = selectApprovalChannelByPolicy({
      config,
      policy: policyWithChannel("webhook", {
        webhook_url: "https://legacy.example/approval",
        webhook_secret: "legacy-secret",
      }),
    });
    expect(selection.type).toBe("webhook");
    expect(selection.channel).toBeInstanceOf(WebhookApprovalChannel);
    const internalConfig = selection.channel as unknown as {
      config: { webhook_url: string; webhook_secret: string };
    };
    expect(internalConfig.config.webhook_url).toBe("https://config.example/approval");
    expect(internalConfig.config.webhook_secret).toBe("config-secret");
  });

  it("uses dashboard when policy selects dashboard, even when the legacy enabled flag is false", () => {
    const config = configWith({
      dashboard: { enabled: false, port: 4567, auto_open: false },
    });
    const selection = selectApprovalChannelByPolicy({
      config,
      policy: policyWithChannel("dashboard"),
    });
    expect(selection.type).toBe("dashboard");
    expect(selection.channel).toBeInstanceOf(DashboardApprovalChannel);
  });

  it("uses callback when policy selects callback and the embedding caller supplies one", () => {
    const selection = selectApprovalChannelByPolicy({
      config: configWith({}),
      policy: policyWithChannel("callback"),
      approvalCallback: async () => ({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      }),
    });
    expect(selection.type).toBe("callback");
    expect(selection.channel).toBeInstanceOf(CallbackApprovalChannel);
  });

  it("fails closed for webhook policy selection without url+secret instead of falling back to stderr", () => {
    expect(() =>
      selectApprovalChannelByPolicy({
        config: configWith({}),
        policy: policyWithChannel("webhook"),
      }),
    ).toThrow(/approval_channel\.type=webhook.*webhook URL and secret/s);
  });

  it("fails closed for callback policy selection without an embedding callback", () => {
    expect(() =>
      selectApprovalChannelByPolicy({
        config: configWith({}),
        policy: policyWithChannel("callback"),
      }),
    ).toThrow(/approval_channel\.type=callback.*approvalCallback/s);
  });

  it("fails closed when the policy-selected dashboard cannot start", async () => {
    const selection = selectApprovalChannelByPolicy({
      config: configWith({ dashboard: { port: 4567 } }),
      policy: policyWithChannel("dashboard"),
      factories: failingFactories("dashboard failed"),
    });
    if (selection.type !== "dashboard") {
      throw new Error(`expected dashboard selection, got ${selection.type}`);
    }
    await expect(selection.start()).rejects.toThrow(
      /approval_channel\.type=dashboard.*could not start.*dashboard failed/s,
    );
  });

  it("fails closed when the policy-selected webhook callback listener cannot start", async () => {
    const selection = selectApprovalChannelByPolicy({
      config: configWith({
        webhook: {
          url: "https://config.example/approval",
          secret: "config-secret",
          callback_port: 4568,
        },
      }),
      policy: policyWithChannel("webhook"),
      factories: failingFactories("webhook failed"),
    });
    if (selection.type !== "webhook") {
      throw new Error(`expected webhook selection, got ${selection.type}`);
    }
    await expect(selection.start()).rejects.toThrow(
      /approval_channel\.type=webhook.*callback listener could not start.*webhook failed/s,
    );
  });
});

function policyWithChannel(
  type: PrincipalPolicy["approval_channel"]["type"],
  channelOverrides: Partial<PrincipalPolicy["approval_channel"]> = {},
): PrincipalPolicy {
  return {
    ...DEFAULT_POLICY,
    approval_channel: {
      ...DEFAULT_POLICY.approval_channel,
      ...channelOverrides,
      type,
    },
  };
}

function configWith(overrides: {
  dashboard?: Partial<SanctuaryConfig["dashboard"]>;
  webhook?: Partial<SanctuaryConfig["webhook"]>;
}): SanctuaryConfig {
  const config = defaultConfig();
  return {
    ...config,
    dashboard: {
      ...config.dashboard,
      ...overrides.dashboard,
    },
    webhook: {
      ...config.webhook,
      ...overrides.webhook,
    },
  };
}

function failingFactories(message: string): ApprovalChannelSelectionFactories {
  const channel: ApprovalChannel & { start: () => Promise<void> } = {
    async requestApproval() {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "channel_failure",
      };
    },
    async start() {
      throw new Error(message);
    },
  };
  return {
    dashboard: () => channel as unknown as DashboardApprovalChannel,
    webhook: () => channel as unknown as WebhookApprovalChannel,
  };
}
