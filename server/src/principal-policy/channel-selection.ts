import { randomBytes } from "node:crypto";
import { createServer as createNetProbeServer } from "node:net";
import type { SanctuaryConfig } from "../config.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
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

/**
 * A163 (fix round 1, 2026-09-27): bind-and-close probe for an explicitly
 * requested dashboard, called from `createSanctuaryServer` (index.ts)
 * immediately after `loadConfig`, BEFORE any fortress write (the storage-dir
 * mkdir, `establishMaster`'s custody envelope). This never constructs a
 * `DashboardApprovalChannel` and never leaves a listener behind either way:
 * the probe's own server is closed on both the success and the error path
 * before this function's promise settles. Kept in this module (not index.ts)
 * so it is not part of `src/index.ts`'s re-exported public surface (the
 * `public-surface-snapshot` structure test freezes that surface's exported
 * NAMES; this is boot-internal wiring, not a package consumer's API).
 */
export async function refuseIfDashboardPortUnavailable(
  host: string,
  port: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const probe = createNetProbeServer();
    probe.once("error", (err: NodeJS.ErrnoException) => {
      probe.close(() => {
        reject(
          new Error(
            `Sanctuary cannot start: the dashboard was explicitly requested ` +
              `(--dashboard), but the dashboard port ${port} is already in ` +
              `use: ${err.message}`,
          ),
        );
      });
    });
    probe.listen(port, host, () => {
      probe.close(() => resolve());
    });
  });
}

/**
 * A163 race path (fix round 1, Claude-3/Claude-4/Grok-2): called from
 * `createSanctuaryServer` (index.ts) ONLY when `explicitDashboardRequested`
 * is true and the real dashboard bind still lost to EADDRINUSE despite
 * `refuseIfDashboardPortUnavailable` seeing the port free -- i.e. another
 * process won the port in the window between the probe and the real
 * `start()`. Custody already exists on this path (the preflight above is
 * what keeps a VIRGIN fortress from reaching here at all), so unlike the
 * preflight's plain throw, this records the SAME `dashboard_bind_unavailable`
 * audit row the #1458 degrade path writes -- an operator's own fortress
 * trail must show why the process it just started is gone -- and stops the
 * `DashboardApprovalChannel` `start()` already constructed: its constructor
 * starts an un-`unref`'d 60s session-cleanup interval (`dashboard.ts`'s
 * `sessionCleanupTimer`) unconditionally, before any bind attempt, and only
 * `stop()` clears it. index.ts's boot-failure `catch` releases the
 * master-key write barrier but never reaches this channel, so `stop()` must
 * happen here, before the returned Error is thrown.
 */
export async function refuseDashboardBindRace(
  dashboard: DashboardApprovalChannel,
  auditLog: AuditLog,
  storagePath: string,
  port: number,
): Promise<Error> {
  await auditLog.appendCritical({
    layer: "l2",
    operation: "dashboard_bind_unavailable",
    identity_id: fortressIdFromStoragePath(storagePath),
    result: "failure",
    details: {
      port,
    },
  });
  await dashboard.stop();
  return new Error(
    `Sanctuary cannot start: the dashboard was explicitly requested ` +
      `(--dashboard), but the dashboard port ${port} is already in use.`,
  );
}

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
            // F5 (dashboard-bind-degrade, 2026-09-24): request the SAME
            // EADDRINUSE classification `DashboardApprovalChannel.start`
            // already gives the supervised LaunchAgent boot (dashboard.ts,
            // `exitCleanOnAddrInUse`), AGENTS rule 5, one source. This
            // ONLY changes what a busy port does inside `start()` (resolve
            // with `addrInUse()` true instead of reject); it does not
            // itself decide what a busy port means for the caller.
            //
            // This selector is reached by EVERY `createSanctuaryServer`
            // caller, not only the daily-fortress MCP stdio boot: the CLI's
            // stdio path (including an operator's explicit `sanctuary
            // --dashboard`, cli.ts), the evidence-pack CLI (evidence-pack/
            // cli.ts), and the EU AI Act compliance CLI (compliance/
            // eu_ai_act/cli.ts) all construct the server through this same
            // function. On a busy dashboard port, all of them either
            // degrade to deny-all or refuse startup, decided by the
            // `explicitDashboardRequested` boot option (A163, 2026-09-27
            // fix round 1; must match its doc comment in index.ts) --
            // a boot-local flag set ONLY by cli.ts's `--dashboard` argv
            // parse, never derived from `config.dashboard.enabled` or
            // `SANCTUARY_DASHBOARD_ENABLED`, both of which persist past this
            // process. An operator who did NOT explicitly ask for the
            // dashboard this boot gets the deny-all degrade (#1458); one who
            // did gets a startup refusal naming the port (pre-flighted before
            // any fortress write, or at this `addrInUse()` check on a lost
            // race), matching every other dashboard bind failure. The
            // `addrInUse()` check and this decision live in the shared
            // `createSanctuaryServer` body (`index.ts`), so every one of
            // those callers gets the same behavior.
            //
            // `silentAddrInUse: true`: the supervised-path stderr line this
            // same EADDRINUSE branch prints ("standing down (single-
            // owner)") describes standing DOWN, which this process does
            // not do -- it keeps serving MCP tools. Suppress that one line
            // here so only the caller's own, accurate message prints; the
            // supervised LaunchAgent path (dashboard-standalone.ts) never
            // passes this flag, so its message is unchanged.
            //
            // The standalone dashboard boot (dashboard-standalone.ts) and
            // the supervised LaunchAgent path call `DashboardApprovalChannel`
            // directly and never go through this selector, so they are
            // unaffected by this change.
            await dashboard.start({
              exitCleanOnAddrInUse: true,
              silentAddrInUse: true,
            });
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
