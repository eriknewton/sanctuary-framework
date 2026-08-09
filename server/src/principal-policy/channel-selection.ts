import { randomBytes } from "node:crypto";
import type { SanctuaryConfig } from "../config.js";
import {
  CallbackApprovalChannel,
  StderrApprovalChannel,
  type ApprovalChannel,
} from "./approval-channel.js";
import { DashboardApprovalChannel } from "./dashboard.js";
import { WebhookApprovalChannel } from "./webhook.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
  PrincipalPolicy,
} from "./types.js";

type DashboardChannelConfig = ConstructorParameters<
  typeof DashboardApprovalChannel
>[0];
type WebhookChannelConfig = ConstructorParameters<typeof WebhookApprovalChannel>[0];

export interface ApprovalChannelSelectionFactories {
  dashboard?: (config: DashboardChannelConfig) => DashboardApprovalChannel;
  webhook?: (config: WebhookChannelConfig) => WebhookApprovalChannel;
  stderr?: (config: PrincipalPolicy["approval_channel"]) => StderrApprovalChannel;
  callback?: (
    callback: (request: ApprovalRequest) => Promise<ApprovalResponse>,
  ) => CallbackApprovalChannel;
}

export type SelectedApprovalChannel =
  | {
      type: "dashboard";
      channel: DashboardApprovalChannel;
      start: () => Promise<void>;
    }
  | {
      type: "webhook";
      channel: WebhookApprovalChannel;
      start: () => Promise<void>;
    }
  | {
      type: "stderr";
      channel: ApprovalChannel;
    }
  | {
      type: "callback";
      channel: ApprovalChannel;
    };

export interface SelectApprovalChannelOptions {
  config: SanctuaryConfig;
  policy: PrincipalPolicy;
  approvalCallback?: (request: ApprovalRequest) => Promise<ApprovalResponse>;
  factories?: ApprovalChannelSelectionFactories;
}

/**
 * Must match ApprovalChannelConfig.type in principal-policy/types.ts. The
 * policy's approval_channel.type is authoritative at boot: config supplies
 * connection parameters only, and a selected but unconstructable channel fails
 * closed instead of degrading to a different approval path.
 */
export function selectApprovalChannelByPolicy(
  opts: SelectApprovalChannelOptions,
): SelectedApprovalChannel {
  const { config, policy } = opts;
  const factories = opts.factories ?? {};
  switch (policy.approval_channel.type) {
    case "dashboard": {
      const authToken =
        config.dashboard.auth_token === "auto"
          ? randomBytes(32).toString("hex")
          : config.dashboard.auth_token;
      const dashboard = (factories.dashboard ?? defaultDashboardFactory)({
        port: config.dashboard.port,
        host: config.dashboard.host,
        timeout_seconds: policy.approval_channel.timeout_seconds,
        // SEC-002: auto_deny removed - timeout always denies.
        auth_token: authToken,
        tls: config.dashboard.tls,
        auto_open: config.dashboard.auto_open,
        allow_plaintext_remote: config.dashboard.allow_plaintext_remote,
      });
      return {
        type: "dashboard",
        channel: dashboard,
        start: async () => {
          try {
            await dashboard.start();
          } catch (err) {
            throw new Error(
              `Sanctuary cannot start: principal policy selects approval_channel.type=dashboard, ` +
                `but the dashboard approval server could not start at ` +
                `${config.dashboard.host}:${config.dashboard.port}: ` +
                `${err instanceof Error ? err.message : String(err)}`,
              { cause: err },
            );
          }
        },
      };
    }
    case "webhook": {
      const configWebhookUrl = configuredString(config.webhook.url);
      const configWebhookSecret = configuredString(config.webhook.secret);
      const policyWebhookUrl = configuredString(policy.approval_channel.webhook_url);
      const policyWebhookSecret = configuredString(
        policy.approval_channel.webhook_secret,
      );
      // Parameter precedence: config.webhook supplies the live connection
      // parameters and wins over the legacy policy webhook fields when both
      // sources contain a complete url+secret pair. The policy field is retained
      // only for back-compat with existing on-disk policies.
      const useConfigWebhook =
        configWebhookUrl !== undefined && configWebhookSecret !== undefined;
      const usePolicyWebhook =
        policyWebhookUrl !== undefined && policyWebhookSecret !== undefined;
      if (!useConfigWebhook && !usePolicyWebhook) {
        throw new Error(
          "Sanctuary cannot start: principal policy selects " +
            "approval_channel.type=webhook, but no complete webhook URL and " +
            "secret are configured. Set config.webhook.url and " +
            "config.webhook.secret, or the legacy policy.approval_channel." +
            "webhook_url and webhook_secret fields.",
        );
      }
      const webhook = (factories.webhook ?? defaultWebhookFactory)({
        webhook_url: useConfigWebhook ? configWebhookUrl : policyWebhookUrl,
        webhook_secret: useConfigWebhook
          ? configWebhookSecret
          : policyWebhookSecret,
        callback_port: config.webhook.callback_port,
        callback_host: config.webhook.callback_host,
        timeout_seconds: policy.approval_channel.timeout_seconds,
        // SEC-002: auto_deny removed - timeout always denies.
      } as WebhookChannelConfig);
      return {
        type: "webhook",
        channel: webhook,
        start: async () => {
          try {
            await webhook.start();
          } catch (err) {
            throw new Error(
              `Sanctuary cannot start: principal policy selects approval_channel.type=webhook, ` +
                `but the webhook callback listener could not start at ` +
                `${config.webhook.callback_host}:${config.webhook.callback_port}: ` +
                `${err instanceof Error ? err.message : String(err)}`,
              { cause: err },
            );
          }
        },
      };
    }
    case "callback":
      if (!opts.approvalCallback) {
        throw new Error(
          "Sanctuary cannot start: principal policy selects " +
            "approval_channel.type=callback, but createSanctuaryServer was not " +
            "given an approvalCallback implementation.",
        );
      }
      return {
        type: "callback",
        channel: (factories.callback ?? defaultCallbackFactory)(
          opts.approvalCallback,
        ),
      };
    case "stderr":
      return {
        type: "stderr",
        channel: (factories.stderr ?? defaultStderrFactory)(
          policy.approval_channel,
        ),
      };
  }
}

function configuredString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : undefined;
}

function defaultDashboardFactory(
  config: DashboardChannelConfig,
): DashboardApprovalChannel {
  return new DashboardApprovalChannel(config);
}

function defaultWebhookFactory(config: WebhookChannelConfig): WebhookApprovalChannel {
  return new WebhookApprovalChannel(config);
}

function defaultStderrFactory(
  config: PrincipalPolicy["approval_channel"],
): StderrApprovalChannel {
  return new StderrApprovalChannel(config);
}

function defaultCallbackFactory(
  callback: (request: ApprovalRequest) => Promise<ApprovalResponse>,
): CallbackApprovalChannel {
  return new CallbackApprovalChannel(callback);
}
