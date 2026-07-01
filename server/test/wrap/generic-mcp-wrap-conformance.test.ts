import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { Buffer } from "node:buffer";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import {
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  wrapMasterWithPassphrase,
  wrapMasterWithRecoveryKey,
  writeCustodyEnvelope,
} from "../../src/core/master-custody.js";
import { readPersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";
import { SANCTUARY_VERSION } from "../../src/config.js";

/**
 * The published-version MCP entry the wrap writes (v1.6.1 install-path
 * hardening, F2): version-pinned, explicit `sanctuary` bin, `-y` for the
 * non-interactive spawn.
 */
const PINNED_SANCTUARY_ARGS = [
  "-y",
  "-p",
  `@sanctuary-framework/mcp-server@${SANCTUARY_VERSION}`,
  "sanctuary",
];

const PASSPHRASE_SECRET = "codex-fixture-passphrase-secret-2026-06-22";
const AGENT_PRIVATE_KEY_SECRET =
  "codex-fixture-agent-private-key-ed25519-seed-never-persist";
const TRANSIENT_KEY_SECRET =
  "codex-fixture-transient-session-key-never-persist";
const MASTER_KEY_BYTES = Buffer.from("codex-master-secret-sentinel-32!");
const RECOVERY_KEY_BYTES = Buffer.from("codex-recovery-secret-sentinel!!");

type TerminalWrite = {
  stream: "stdout" | "stderr";
  data: Buffer;
};

describe("generic MCP wrap conformance", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;
  let originalDashboardToken: string | undefined;
  let originalDashboardEnabled: string | undefined;
  let originalAgentPrivateKey: string | undefined;
  let originalTransientKey: string | undefined;
  let stdoutWriteSpy: ReturnType<typeof vi.spyOn> | undefined;
  let stderrWriteSpy: ReturnType<typeof vi.spyOn> | undefined;
  let terminalWrites: TerminalWrite[];

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-generic-mcp-"));

    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    originalDashboardToken = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    originalDashboardEnabled = process.env.SANCTUARY_DASHBOARD_ENABLED;
    originalAgentPrivateKey = process.env.SANCTUARY_TEST_AGENT_PRIVATE_KEY;
    originalTransientKey = process.env.SANCTUARY_TEST_TRANSIENT_KEY;

    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    process.env.SANCTUARY_TEST_AGENT_PRIVATE_KEY = AGENT_PRIVATE_KEY_SECRET;
    process.env.SANCTUARY_TEST_TRANSIENT_KEY = TRANSIENT_KEY_SECRET;

    terminalWrites = [];
    stdoutWriteSpy = spyOnTerminalStream(process.stdout, "stdout", terminalWrites);
    stderrWriteSpy = spyOnTerminalStream(process.stderr, "stderr", terminalWrites);
    await seedCustody(process.env.SANCTUARY_STORAGE_PATH);
  });

  afterEach(async () => {
    stdoutWriteSpy?.mockRestore();
    stderrWriteSpy?.mockRestore();
    stdoutWriteSpy = undefined;
    stderrWriteSpy = undefined;
    restoreEnv("HOME", originalHome);
    restoreEnv("SANCTUARY_STORAGE_PATH", originalStoragePath);
    restoreEnv("SANCTUARY_PASSPHRASE", originalPassphrase);
    restoreEnv("SANCTUARY_DASHBOARD_AUTH_TOKEN", originalDashboardToken);
    restoreEnv("SANCTUARY_DASHBOARD_ENABLED", originalDashboardEnabled);
    restoreEnv("SANCTUARY_TEST_AGENT_PRIVATE_KEY", originalAgentPrivateKey);
    restoreEnv("SANCTUARY_TEST_TRANSIENT_KEY", originalTransientKey);
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("wraps and unwraps an arbitrary multi-server mcpServers config without leaking sentinel secrets to disk or terminal output", async () => {
    const configPath = join(tmpHome, "synthetic-harness", "mcp.json");
    const original = {
      displayName: "Synthetic MCP Harness",
      mcpServers: {
        alpha: {
          command: "node",
          args: ["alpha-server.js", "--stdio"],
          env: { ALPHA_MODE: "fixture" },
        },
        beta: {
          url: "http://127.0.0.1:8787/sse",
        },
      },
      preferences: { color: "green" },
    };
    const originalJson = JSON.stringify(original, null, 2);
    await writeJsonFile(configPath, original);

    const deps = wrapDeps();
    await runWrap({ wrap: configPath, noDashboard: true, noOpen: true }, deps);

    expect(deps.installClaudeCodeAllowlist).not.toHaveBeenCalled();

    const wrapped = JSON.parse(await readFile(configPath, "utf-8")) as {
      displayName?: string;
      mcpServers?: Record<string, unknown>;
      preferences?: Record<string, unknown>;
    };
    expect(wrapped.displayName).toBe(original.displayName);
    expect(wrapped.preferences).toEqual(original.preferences);
    expect(Object.keys(wrapped.mcpServers ?? {})).toEqual([
      "alpha",
      "beta",
      "sanctuary",
    ]);
    expect(wrapped.mcpServers?.alpha).toEqual(original.mcpServers.alpha);
    expect(wrapped.mcpServers?.beta).toEqual(original.mcpServers.beta);
    expect(wrapped.mcpServers?.sanctuary).toEqual({
      command: "npx",
      args: PINNED_SANCTUARY_ARGS,
    });

    const profile = JSON.parse(
      await readFile(
        join(process.env.SANCTUARY_STORAGE_PATH!, "wrap-profile.json"),
        "utf-8",
      ),
    ) as {
      upstream_servers?: Array<{
        name: string;
        transport: Record<string, unknown>;
      }>;
    };
    expect(profile.upstream_servers?.map((server) => server.name)).toEqual([
      "alpha",
      "beta",
    ]);
    expect(profile.upstream_servers?.[0]?.transport).toMatchObject({
      type: "stdio",
      command: "node",
      args: ["alpha-server.js", "--stdio"],
      env: { ALPHA_MODE: "fixture" },
    });
    expect(profile.upstream_servers?.[1]?.transport).toMatchObject({
      type: "sse",
      url: "http://127.0.0.1:8787/sse",
    });

    const agents = readPersistedLocalAgents(process.env.SANCTUARY_STORAGE_PATH!);
    expect(agents).toHaveLength(1);
    expect(agents[0]?.harness).toBe("generic_mcp");

    const terminalOutputAfterWrap = capturedTerminalOutput(terminalWrites);
    expect(terminalOutputAfterWrap.byteLength).toBeGreaterThan(0);
    await expectNoSentinelLeaks(tmpHome, terminalOutputAfterWrap);

    await runWrap({ unwrap: true }, deps);
    const restored = await readFile(configPath, "utf-8");
    expect(restored).toBe(originalJson);
    await expectNoSentinelLeaks(tmpHome, capturedTerminalOutput(terminalWrites));
  });

  it("routes a minimal arbitrary flat mcpServers config through generic_mcp", async () => {
    const configPath = join(tmpHome, "minimal-harness", "mcp.json");
    await writeJsonFile(configPath, {
      mcpServers: {
        one: { command: "node", args: ["one.js"] },
      },
    });

    await runWrap({ wrap: configPath, noDashboard: true, noOpen: true }, wrapDeps());

    const wrapped = JSON.parse(await readFile(configPath, "utf-8")) as {
      mcpServers?: Record<string, unknown>;
    };
    expect(Object.keys(wrapped.mcpServers ?? {})).toEqual(["one", "sanctuary"]);
    expect(wrapped.mcpServers?.one).toEqual({
      command: "node",
      args: ["one.js"],
    });
    expect(wrapped.mcpServers?.sanctuary).toEqual({
      command: "npx",
      args: PINNED_SANCTUARY_ARGS,
    });
    expect(
      readPersistedLocalAgents(process.env.SANCTUARY_STORAGE_PATH!)[0]?.harness,
    ).toBe("generic_mcp");
  });

  it("installs Sanctuary as the sole entry for an empty arbitrary config", async () => {
    const configPath = join(tmpHome, "empty-harness", "settings.json");
    await writeJsonFile(configPath, {
      theme: "dark",
      window: { density: "compact" },
    });

    await runWrap({ wrap: configPath, noDashboard: true, noOpen: true }, wrapDeps());

    const wrapped = JSON.parse(await readFile(configPath, "utf-8")) as {
      theme?: string;
      window?: Record<string, unknown>;
      mcpServers?: Record<string, unknown>;
    };
    expect(wrapped.theme).toBe("dark");
    expect(wrapped.window).toEqual({ density: "compact" });
    expect(wrapped.mcpServers).toEqual({
      sanctuary: {
        command: "npx",
        args: PINNED_SANCTUARY_ARGS,
      },
    });
    expect(
      readPersistedLocalAgents(process.env.SANCTUARY_STORAGE_PATH!)[0]?.harness,
    ).toBe("generic_mcp");
  });
});

async function seedCustody(storagePath: string): Promise<void> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const now = () => new Date("2026-06-22T00:00:00.000Z");
  const passphraseWrap = await wrapMasterWithPassphrase(
    MASTER_KEY_BYTES,
    PASSPHRASE_SECRET,
    { verified: true, now },
  );
  const recoveryWrap = wrapMasterWithRecoveryKey(
    MASTER_KEY_BYTES,
    RECOVERY_KEY_BYTES,
    { verified: true, now },
  );
  await writeCustodyEnvelope(
    storage,
    {
      v: 1,
      install_mode: "headless",
      wraps: [passphraseWrap, recoveryWrap],
      created_at: now().toISOString(),
    },
    MASTER_KEY_BYTES,
  );
}

function wrapDeps(): RunWrapDeps & {
  installClaudeCodeAllowlist: ReturnType<typeof vi.fn>;
} {
  const installClaudeCodeAllowlist = vi.fn(async () => ({
    installedAt: join(process.env.HOME!, ".claude", "settings.json"),
    added: [],
    alreadyPresent: true,
  }));
  return {
    resolvePassphrase: async () => ({
      value: PASSPHRASE_SECRET,
      location: "fixture-keychain",
      source: "generated" as const,
    }),
    openBrowser: async () => {},
    installClaudeCodeAllowlist,
  };
}

async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(value, null, 2), "utf-8");
}

async function expectNoSentinelLeaks(
  root: string,
  terminalOutput: Buffer,
): Promise<void> {
  const files = await collectFiles(root);
  const needles = [
    ...encodedNeedles("passphrase", Buffer.from(PASSPHRASE_SECRET, "utf8")),
    ...encodedNeedles(
      "agent-private-key",
      Buffer.from(AGENT_PRIVATE_KEY_SECRET, "utf8"),
    ),
    ...encodedNeedles("transient-key", Buffer.from(TRANSIENT_KEY_SECRET, "utf8")),
    ...encodedNeedles("master-key", MASTER_KEY_BYTES),
    ...encodedNeedles("recovery-key", RECOVERY_KEY_BYTES),
  ];
  const leaks: string[] = [];
  for (const file of files) {
    const data = await readFile(file);
    scanNeedles(data, file, needles, leaks);
  }
  expect(terminalOutput.byteLength).toBeGreaterThan(0);
  scanNeedles(
    terminalOutput,
    "terminal stdout/stderr",
    needles,
    leaks,
  );
  expect(leaks).toEqual([]);
}

function scanNeedles(
  data: Buffer,
  location: string,
  needles: Array<{ label: string; value: Buffer }>,
  leaks: string[],
): void {
  for (const needle of needles) {
    if (data.indexOf(needle.value) !== -1) {
      leaks.push(`${needle.label} in ${location}`);
    }
  }
}

function encodedNeedles(label: string, bytes: Buffer): Array<{
  label: string;
  value: Buffer;
}> {
  const base64 = bytes.toString("base64");
  const base64url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  const hex = bytes.toString("hex");
  return [
    { label: `${label}:raw`, value: bytes },
    { label: `${label}:base64`, value: Buffer.from(base64, "utf8") },
    { label: `${label}:base64url`, value: Buffer.from(base64url, "utf8") },
    { label: `${label}:hex`, value: Buffer.from(hex, "utf8") },
    { label: `${label}:hex-uppercase`, value: Buffer.from(hex.toUpperCase(), "utf8") },
  ];
}

async function collectFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectFiles(path));
    } else if (entry.isFile()) {
      files.push(path);
    }
  }
  return files.sort();
}

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

function spyOnTerminalStream(
  stream: NodeJS.WriteStream,
  streamName: "stdout" | "stderr",
  writes: TerminalWrite[],
): ReturnType<typeof vi.spyOn> {
  return vi
    .spyOn(stream, "write")
    .mockImplementation(((
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void,
    ) => {
      writes.push({
        stream: streamName,
        data: terminalChunkToBuffer(chunk, encodingOrCallback),
      });
      const done =
        typeof encodingOrCallback === "function" ? encodingOrCallback : callback;
      done?.();
      return true;
    }) as typeof stream.write);
}

function terminalChunkToBuffer(
  chunk: string | Uint8Array,
  encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
): Buffer {
  if (typeof chunk !== "string") return Buffer.from(chunk);
  const encoding = typeof encodingOrCallback === "string"
    ? encodingOrCallback
    : "utf8";
  return Buffer.from(chunk, encoding);
}

function capturedTerminalOutput(writes: TerminalWrite[]): Buffer {
  return Buffer.concat(writes.map((write) => write.data));
}
