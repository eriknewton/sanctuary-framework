import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  chmod,
  mkdir,
  mkdtemp,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";

import {
  parseTelegramLivenessProbeConfig,
  readTelegramLivenessProbeConfigFromFortress,
  resolveTelegramLivenessProbeConfigPath,
  runTelegramLivenessProbe,
  verifyTelegramAgentLivenessFromFortress,
  type TelegramLivenessProbeAuditSink,
  type TelegramLivenessProbeConfig,
} from "../../../src/castle-wall/provision/liveness-probe.js";
import { readFileCustodyWithStats } from "../../../src/storage/custody-fs.js";

const PROBE_TOKEN = "123456:PROBE_TOKEN";
const AGENT_TOKEN = "999999:AGENT_TOKEN";
const CHAT_ID = "-100100100";
const EXPECTED_SENDER_ID = 42_424_242;
const NONCE = "nonce-roundtrip-123";
const NONCE_HASH8 = createHash("sha256").update(NONCE).digest("hex").slice(0, 8);
const EXPECTED_REQUEST_ID = `telegram:700:nonce8:${NONCE_HASH8}`;

const BASE_CONFIG: TelegramLivenessProbeConfig = {
  botToken: PROBE_TOKEN,
  chatId: CHAT_ID,
  expectedSenderId: EXPECTED_SENDER_ID,
  timeoutMs: 30,
  pollIntervalMs: 10,
  maxDrainBatches: 3,
};

interface TelegramMockCall {
  token: string;
  method: "sendMessage" | "getUpdates";
  body: Record<string, unknown>;
}

type MockUpdate = Record<string, unknown>;
type UpdateBatch = MockUpdate[] | ((api: MockTelegramBotApi) => MockUpdate[]);

class MockTelegramBotApi {
  readonly calls: TelegramMockCall[] = [];
  getUpdatesQueue: UpdateBatch[] = [];
  sendResponse:
    | undefined
    | {
        status: number;
        body: Record<string, unknown>;
      };
  lastSentMessageId: number | undefined;
  private nextMessageId = 700;
  baseUrl = "https://mock.telegram.local";

  async start(): Promise<void> {
    // In-process test double: preserves Bot API request/response semantics
    // without requiring sandbox permission to bind a localhost socket.
  }

  async stop(): Promise<void> {
    // No process or socket state to tear down.
  }

  async fetch(input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> {
    const url = new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url);
    const match = /^\/bot([^/]+)\/(sendMessage|getUpdates)$/.exec(url.pathname);
    if (!match) {
      return jsonResponse(404, { ok: false, description: "not found" });
    }
    const token = decodeURIComponent(match[1]!);
    const method = match[2] as "sendMessage" | "getUpdates";
    const body = init?.body === undefined || init.body === null
      ? {}
      : JSON.parse(String(init.body)) as Record<string, unknown>;
    this.calls.push({ token, method, body });
    if (method === "sendMessage") {
      if (this.sendResponse !== undefined) {
        return jsonResponse(this.sendResponse.status, this.sendResponse.body);
      }
      this.lastSentMessageId = this.nextMessageId;
      this.nextMessageId += 1;
      return jsonResponse(200, {
        ok: true,
        result: {
          message_id: this.lastSentMessageId,
          date: 1_785_600_000,
          chat: { id: body.chat_id, type: "group" },
          text: body.text,
        },
      });
    }
    const next = this.getUpdatesQueue.shift();
    const updates = typeof next === "function" ? next(this) : next ?? [];
    return jsonResponse(200, { ok: true, result: updates });
  }
}

const runningApis: MockTelegramBotApi[] = [];

afterEach(async () => {
  await Promise.all(runningApis.splice(0).map((api) => api.stop()));
});

async function makeApi(): Promise<MockTelegramBotApi> {
  const api = new MockTelegramBotApi();
  await api.start();
  runningApis.push(api);
  return api;
}

function fakeOps(api?: MockTelegramBotApi) {
  let now = 1_000;
  return {
    fetch: (api === undefined ? globalThis.fetch : api.fetch.bind(api)) as typeof fetch,
    nowMs: () => now,
    sleepMs: async (ms: number) => {
      now += ms;
    },
    randomNonce: () => NONCE,
  };
}

async function trustedFortressCustodyBase(): Promise<void> {
  return undefined;
}

function replyUpdate(
  api: MockTelegramBotApi,
  opts: {
    updateId?: number;
    fromId?: number;
    chatId?: string;
    text?: string;
    replyToMessageId?: number;
    messageId?: number;
  } = {},
): MockUpdate {
  return {
    update_id: opts.updateId ?? 9_001,
    message: {
      message_id: opts.messageId ?? 8_001,
      date: 1_785_600_001,
      from: { id: opts.fromId ?? EXPECTED_SENDER_ID, is_bot: true },
      chat: { id: opts.chatId ?? CHAT_ID, type: "group" },
      text: opts.text ?? `pong ${NONCE}`,
      reply_to_message: { message_id: opts.replyToMessageId ?? api.lastSentMessageId },
    },
  };
}

function staleUpdate(updateId: number): MockUpdate {
  return {
    update_id: updateId,
    message: {
      message_id: updateId + 10,
      date: 1_785_500_000,
      from: { id: EXPECTED_SENDER_ID },
      chat: { id: CHAT_ID, type: "group" },
      text: `old ${NONCE}`,
    },
  };
}

function makeAudit(): {
  audit: TelegramLivenessProbeAuditSink;
  entries: Array<{
    layer: string;
    operation: string;
    identityId: string;
    details: Record<string, unknown>;
    result: string | undefined;
  }>;
} {
  const entries: Array<{
    layer: string;
    operation: string;
    identityId: string;
    details: Record<string, unknown>;
    result: string | undefined;
  }> = [];
  return {
    entries,
    audit: {
      append: async (layer, operation, identityId, details, result) => {
        entries.push({ layer, operation, identityId, details, result });
      },
    },
  };
}

describe("Telegram liveness probe over mock Bot API", () => {
  it("verifies a full confined Telegram round trip and audits only redacted identifiers", async () => {
    const api = await makeApi();
    const audit = makeAudit();
    api.getUpdatesQueue = [
      [],
      (server) => [replyUpdate(server)],
    ];

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
      audit: audit.audit,
      auditIdentityId: "hermes",
    });

    expect(result).toEqual({
      kind: "round_trip",
      roundTrip: {
        channel: "telegram",
        requestId: EXPECTED_REQUEST_ID,
        responseId: "telegram:8001",
      },
    });
    expect(JSON.stringify(result)).not.toContain(NONCE);
    expect(api.calls.map((call) => call.method)).toEqual(["getUpdates", "sendMessage", "getUpdates"]);
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]).toMatchObject({
      layer: "l2",
      operation: "cos_liveness_probe",
      identityId: "hermes",
      result: "success",
    });
    const serializedAudit = JSON.stringify(audit.entries[0]!.details);
    expect(serializedAudit).not.toContain(PROBE_TOKEN);
    expect(serializedAudit).not.toContain(CHAT_ID);
    expect(audit.entries[0]!.details).toMatchObject({
      channel: "telegram",
      outcome: "verified",
      token_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      chat_id_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      expected_sender_id_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      nonce_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      request_id_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      response_id_sha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
  });

  it("maps send failure to network_unavailable/send_failed", async () => {
    const api = await makeApi();
    const audit = makeAudit();
    api.getUpdatesQueue = [[]];
    api.sendResponse = {
      status: 500,
      body: { ok: false, description: "upstream down" },
    };

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
      audit: audit.audit,
    });

    expect(result).toEqual({ kind: "unverified", reason: "network_unavailable", detail: "send_failed" });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({ outcome: "unverified", detail: "send_failed" });
  });

  it("maps sent-but-no-reply timeout to provider_failed/send_ok_no_reply", async () => {
    const api = await makeApi();
    const audit = makeAudit();
    api.getUpdatesQueue = [[]];

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
      audit: audit.audit,
    });

    expect(result).toEqual({ kind: "unverified", reason: "provider_failed", detail: "send_ok_no_reply" });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({ reason: "provider_failed", detail: "send_ok_no_reply" });
  });

  it("never verifies a nonce-bearing reply from the wrong sender", async () => {
    const api = await makeApi();
    api.getUpdatesQueue = [
      [],
      (server) => [replyUpdate(server, { fromId: 111, text: `pong ${NONCE}` })],
    ];

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
    });

    expect(result).toEqual({ kind: "unverified", reason: "provider_failed", detail: "reply_wrong_sender" });
  });

  it("never verifies a correlated reply from the expected sender without the nonce", async () => {
    const api = await makeApi();
    api.getUpdatesQueue = [
      [],
      (server) => [replyUpdate(server, { text: "pong without the probe value" })],
    ];

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
    });

    expect(result).toEqual({ kind: "unverified", reason: "provider_failed", detail: "reply_no_nonce" });
  });

  it("maps Telegram 429 to provider_failed/rate_limited", async () => {
    const api = await makeApi();
    const audit = makeAudit();
    api.getUpdatesQueue = [[]];
    api.sendResponse = {
      status: 429,
      body: { ok: false, error_code: 429, description: "Too Many Requests", parameters: { retry_after: 1 } },
    };

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
      audit: audit.audit,
    });

    expect(result).toEqual({ kind: "unverified", reason: "provider_failed", detail: "rate_limited" });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({ detail: "rate_limited" });
  });

  it("fails with stale_update_backlog when the pre-send drain never reaches an empty batch", async () => {
    const api = await makeApi();
    api.getUpdatesQueue = [[staleUpdate(1)], [staleUpdate(2)]];

    const result = await runTelegramLivenessProbe({
      config: { ...BASE_CONFIG, maxDrainBatches: 1 },
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
    });

    expect(result).toEqual({ kind: "unverified", reason: "provider_failed", detail: "stale_update_backlog" });
    expect(api.calls.map((call) => call.method)).toEqual(["getUpdates", "getUpdates"]);
  });

  it("drains stale updates before sending and then verifies a fresh reply", async () => {
    const api = await makeApi();
    api.getUpdatesQueue = [
      [staleUpdate(100)],
      [],
      (server) => [replyUpdate(server, { updateId: 101 })],
    ];

    const result = await runTelegramLivenessProbe({
      config: BASE_CONFIG,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
    });

    expect(result.kind).toBe("round_trip");
    expect(api.calls.map((call) => call.method)).toEqual([
      "getUpdates",
      "getUpdates",
      "sendMessage",
      "getUpdates",
    ]);
    expect(api.calls[1]!.body).toMatchObject({ offset: 101 });
  });

  it("never calls getUpdates with an agent bot token even if a caller supplies one", async () => {
    const api = await makeApi();
    api.getUpdatesQueue = [
      [],
      (server) => [replyUpdate(server)],
    ];
    const configWithAgentToken = {
      ...BASE_CONFIG,
      agent_bot_token: AGENT_TOKEN,
    } as TelegramLivenessProbeConfig & { agent_bot_token: string };

    const result = await runTelegramLivenessProbe({
      config: configWithAgentToken,
      apiBaseUrl: api.baseUrl,
      ops: fakeOps(api),
    });

    expect(result.kind).toBe("round_trip");
    const getUpdatesTokens = api.calls
      .filter((call) => call.method === "getUpdates")
      .map((call) => call.token);
    expect(getUpdatesTokens).toEqual([PROBE_TOKEN, PROBE_TOKEN]);
    expect(getUpdatesTokens).not.toContain(AGENT_TOKEN);
  });
});

describe("Telegram liveness probe config", () => {
  it("resolves the credential file outside state and outside .hermes", () => {
    const fortress = "/tmp/sanctuary-fortress";
    const path = resolveTelegramLivenessProbeConfigPath(fortress);
    expect(path).toBe(join(fortress, "config", "liveness-probe", "telegram.json"));
    expect(path).not.toContain("/state/");
    expect(path).not.toContain("/.hermes/");
  });

  it("reads only an operator-owned 0600 config file", async () => {
    const read = await readTelegramLivenessProbeConfigFromFortress({
      fortressPath: "/tmp/f",
      expectedOwnerUid: 501,
      fs: {
        verifyFortressCustodyBase: trustedFortressCustodyBase,
        readFileCustodyWithStats: async () => ({
          data: JSON.stringify({
            bot_token: PROBE_TOKEN,
            chat_id: CHAT_ID,
            expected_sender_id: EXPECTED_SENDER_ID,
          }),
          stats: { mode: 0o100600, uid: 501, isFile: () => true },
        }),
      },
    });

    expect(read.kind).toBe("configured");
    expect(read.kind === "configured" ? read.config : undefined).toMatchObject({
      botToken: PROBE_TOKEN,
      chatId: CHAT_ID,
      expectedSenderId: EXPECTED_SENDER_ID,
      timeoutMs: 90_000,
    });
  });

  it("rejects a config file with group-readable mode", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-liveness-mode-"));
    try {
      const fortress = join(tmp, "fortress");
      const configDir = join(fortress, "config", "liveness-probe");
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(fortress, 0o700);
      await chmod(join(fortress, "config"), 0o700);
      await chmod(configDir, 0o700);
      await writeFile(
        resolveTelegramLivenessProbeConfigPath(fortress),
        JSON.stringify({
          bot_token: PROBE_TOKEN,
          chat_id: CHAT_ID,
          expected_sender_id: EXPECTED_SENDER_ID,
        }),
        { mode: 0o600 },
      );
      await chmod(resolveTelegramLivenessProbeConfigPath(fortress), 0o640);

      await expect(
        readTelegramLivenessProbeConfigFromFortress({
          fortressPath: fortress,
          expectedOwnerUid: process.getuid?.(),
        }),
      ).rejects.toMatchObject({ code: "config_unreadable" });
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it("threads descriptor-first custody options into injected config reads", async () => {
    await expect(
      readTelegramLivenessProbeConfigFromFortress({
        fortressPath: "/tmp/f",
        expectedOwnerUid: 501,
        fs: {
          verifyFortressCustodyBase: trustedFortressCustodyBase,
          readFileCustodyWithStats: async (_path, options) => {
            expect(options.uid).toBe(501);
            expect(options.mode).toEqual({ exact: 0o600 });
            expect(options.parent).toEqual({
              uid: 501,
              mode: { rejectGroupOrOtherWrite: true },
            });
            expect(options.verifyPathIdentity).toBe(true);
            throw Object.assign(new Error("mode rejected"), { code: "EACCES" });
          },
        },
      }),
    ).rejects.toMatchObject({ code: "config_unreadable" });
  });

  it("sanitizes malformed config content across returned errors and audit-adjacent state", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-liveness-malformed-"));
    const distinctiveSecret = "LIVENESS_CONFIG_SECRET_SHOULD_NOT_PRINT_6f278e";
    const audit = makeAudit();
    let message = "";
    const fortress = join(tmp, "fortress");
    const configPath = resolveTelegramLivenessProbeConfigPath(fortress);

    try {
      const configDir = join(fortress, "config", "liveness-probe");
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(fortress, 0o700);
      await chmod(join(fortress, "config"), 0o700);
      await chmod(configDir, 0o700);
      await writeFile(configPath, distinctiveSecret, { mode: 0o600 });

      await verifyTelegramAgentLivenessFromFortress({
        fortressPath: fortress,
        expectedOwnerUid: process.getuid?.(),
        audit: audit.audit,
      });
    } catch (err) {
      message = (err as Error).message;
      expect(err).toMatchObject({ code: "config_malformed" });
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }

    expect(message).toBe("config_malformed");
    expect(message).not.toContain(distinctiveSecret);
    expect(message).not.toContain(configPath);
    expect(message).not.toContain("telegram.json");
    expect(message).not.toMatch(/Unexpected token|not valid JSON|JSON\.parse/i);
    expect(JSON.stringify(audit.entries)).not.toContain(distinctiveSecret);
    expect(JSON.stringify(audit.entries)).not.toContain(configPath);
    expect(JSON.stringify(audit.entries)).not.toContain("telegram.json");
  });

  it("sanitizes unreadable config errors without rendering underlying fs detail", async () => {
    const distinctiveSecret = "LIVENESS_READ_SECRET_SHOULD_NOT_PRINT_a4d0a0";

    await expect(
      readTelegramLivenessProbeConfigFromFortress({
        fortressPath: "/tmp/f",
        fs: {
          verifyFortressCustodyBase: trustedFortressCustodyBase,
          readFileCustodyWithStats: async () => {
            throw new Error(`EACCES while reading ${distinctiveSecret}`);
          },
        },
      }),
    ).rejects.toSatisfy((err: unknown) => {
      const error = err as Error & { code?: string };
      expect(error.code).toBe("config_unreadable");
      expect(error.message).toBe("config_unreadable");
      expect(error.message).not.toContain(distinctiveSecret);
      expect(error.message).not.toContain("telegram.json");
      expect(error.message).not.toContain("EACCES");
      return true;
    });
  });

  it("refuses a non-private fortress base before parsing the config file", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-liveness-base-"));
    try {
      const fortress = join(tmp, "fortress");
      const configDir = join(fortress, "config", "liveness-probe");
      const configPath = resolveTelegramLivenessProbeConfigPath(fortress);
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(fortress, 0o755);
      await chmod(join(fortress, "config"), 0o700);
      await chmod(configDir, 0o700);
      await writeFile(configPath, "not-json-secret", { mode: 0o600 });

      await expect(
        readTelegramLivenessProbeConfigFromFortress({
          fortressPath: fortress,
          expectedOwnerUid: process.getuid?.(),
        }),
      ).rejects.toSatisfy((err: unknown) => {
        const error = err as Error & { code?: string };
        expect(error.code).toBe("config_unreadable");
        expect(error.message).toBe("config_unreadable");
        expect(error.message).not.toContain(configPath);
        expect(error.message).not.toContain("telegram.json");
        expect(error.message).not.toContain("not-json-secret");
        return true;
      });
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it("rejects a post-custody symlink swap instead of reading the swapped token file", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-liveness-toctou-"));
    try {
      const fortress = join(tmp, "fortress");
      const configDir = join(fortress, "config", "liveness-probe");
      const configPath = resolveTelegramLivenessProbeConfigPath(fortress);
      const originalPath = join(configDir, "telegram.json.original");
      const attackerPath = join(tmp, "attacker-token.json");
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(join(fortress, "config"), 0o700);
      await chmod(configDir, 0o700);
      await writeFile(
        configPath,
        JSON.stringify({
          bot_token: PROBE_TOKEN,
          chat_id: CHAT_ID,
          expected_sender_id: EXPECTED_SENDER_ID,
        }),
        { mode: 0o600 },
      );
      await writeFile(
        attackerPath,
        JSON.stringify({
          bot_token: "123456:ATTACKER_TOKEN",
          chat_id: CHAT_ID,
          expected_sender_id: EXPECTED_SENDER_ID,
        }),
        { mode: 0o600 },
      );
      let swapped = false;
      const swapToSymlink = async () => {
        if (swapped) return;
        swapped = true;
        await rename(configPath, originalPath);
        await symlink(attackerPath, configPath);
      };

      await expect(
        readTelegramLivenessProbeConfigFromFortress({
          fortressPath: fortress,
          expectedOwnerUid: process.getuid?.(),
          fs: {
            verifyFortressCustodyBase: trustedFortressCustodyBase,
            readFileCustodyWithStats: async (path, options) =>
              readFileCustodyWithStats(path, {
                ...options,
                onDescriptorVerified: async (info) => {
                  await swapToSymlink();
                  await options.onDescriptorVerified?.(info);
                },
              }),
          } as unknown as Parameters<typeof readTelegramLivenessProbeConfigFromFortress>[0]["fs"],
        }),
      ).rejects.toMatchObject({ code: "config_unreadable" });
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it("refuses a config whose parent directory is agent-writable", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-liveness-parent-"));
    try {
      const fortress = join(tmp, "fortress");
      const configDir = join(fortress, "config", "liveness-probe");
      const configPath = resolveTelegramLivenessProbeConfigPath(fortress);
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(fortress, 0o700);
      await chmod(join(fortress, "config"), 0o700);
      await chmod(configDir, 0o777);
      await writeFile(
        configPath,
        JSON.stringify({
          bot_token: PROBE_TOKEN,
          chat_id: CHAT_ID,
          expected_sender_id: EXPECTED_SENDER_ID,
        }),
        { mode: 0o600 },
      );

      await expect(
        readTelegramLivenessProbeConfigFromFortress({
          fortressPath: fortress,
          expectedOwnerUid: process.getuid?.(),
        }),
      ).rejects.toMatchObject({ code: "config_unreadable" });
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it("keeps absent config as the no-prober path", async () => {
    const enoent = Object.assign(new Error("missing"), { code: "ENOENT" });
    const result = await verifyTelegramAgentLivenessFromFortress({
      fortressPath: "/tmp/f",
      configFs: {
        verifyFortressCustodyBase: trustedFortressCustodyBase,
        readFileCustodyWithStats: async () => {
          throw enoent;
        },
      },
    });

    expect(result).toBeUndefined();
  });

  it("sanitizes direct parser errors for auto-provision callers that render thrown detail", () => {
    const distinctiveSecret = "LIVENESS_PARSE_SECRET_SHOULD_NOT_RENDER_287bb0";

    const configPath = "/tmp/f/config/liveness-probe/telegram.json";
    expect(() => parseTelegramLivenessProbeConfig(distinctiveSecret, configPath))
      .toThrowError(/config_malformed/);
    try {
      parseTelegramLivenessProbeConfig(distinctiveSecret, configPath);
    } catch (err) {
      const message = (err as Error).message;
      expect(err).toMatchObject({ code: "config_malformed" });
      expect(message).toBe("config_malformed");
      expect(message).not.toContain(distinctiveSecret);
      expect(message).not.toContain(configPath);
      expect(message).not.toContain("telegram.json");
      expect(message).not.toMatch(/Unexpected token|not valid JSON|JSON\.parse/i);
    }
  });
});

function jsonResponse(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
