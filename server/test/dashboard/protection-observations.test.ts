/** Protection observations through the dashboard. */
import { afterEach, expect, it, vi } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createCognitiveTools, IdentityManager } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import * as cooperativeSource from "../../src/agent-native/cooperative-surface.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import * as healthSource from "../../src/principal-policy/feature-health.js";
import * as custodySource from "../../src/principal-policy/posture.js";
import { composeProtectionLayers, type ProtectionLayerRow } from "../../src/agent-native/protection-layers.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const observedAt = Date.parse("2026-11-05T12:00:00Z"); // Shared fixed evaluation instant.
const FIRST_CONTENT = 0; // The text response occupies the first content block.
const LAST_ROW = -1; // Inbound protection is the final inventory row.
const completedAt = new Date(observedAt).toISOString();
const guarantees = ["state_encrypted_at_rest", "approval_gate_mediated",
  "append_only_audit_for_critical_operations", "opaque_memory_namespace_handles"];
afterEach(() => vi.restoreAllMocks());

async function fixture() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  let binding: SessionBinding | undefined;
  const currentSessionBinding = () => binding;
  const primitives = createCognitiveTools(stateStore, storage, masterKey, "recovery-key", auditLog, { currentSessionBinding });
  await primitives.identityManager.load();
  const created = await primitives.tools.find(tool => tool.name === "identity_create")!.handler({ label: "observed-session" });
  const { identity_id } = JSON.parse(created.content[FIRST_CONTENT]!.text);
  binding = { identity_id, requester_identity_fingerprint: fingerprintIdentityId(identity_id) };
  const runtime = { identityManager: primitives.identityManager, stateStore, currentSessionBinding,
    responseScreen: { assertReady() {} } };
  const health = await healthSource.buildFeatureHealthPanel({ auditLog, originMachine: "local", protectionClaimSubject: null });
  health.window_end = completedAt;
  health.audit_integrity_ok = true;
  health.rows = health.rows.map(row => ({ ...row, audit_integrity_ok: true, status: "active" as const,
    last_evidence_at: completedAt, basis: "fresh_enforcement_evidence" as const }));
  const custody = await custodySource.buildCustodyExitPanel({ auditLog, originMachine: "local" });
  custody.audit_integrity_ok = true;
  vi.spyOn(Date, "now").mockReturnValue(observedAt);
  const healthRead = vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
  const custodyRead = vi.spyOn(custodySource, "buildCustodyExitPanel").mockResolvedValue(custody);
  const chain = await auditLog.getAuditChainVerdict();
  const chainRead = vi.spyOn(auditLog, "getAuditChainVerdict").mockRejectedValue(new Error("chain unavailable"));
  const makeTool = (sources = runtime) => createAgentNativeCooperativeTools({ ...primitives, ...sources,
    primitiveTools: primitives.tools, auditLog, storage,
    resolveBrokerProducerKey: async () => ({ keyB64url: null, observation: "absent" })
  }).tools.find(tool => tool.name === "sanctuary_active_protections")!;
  const readTool = async () => JSON.parse((await makeTool().handler({})).content[FIRST_CONTENT]!.text) as {
    layers: ProtectionLayerRow[]; summary: string; guarantees: string[]; audit_ref: string;
  };
  return { storage, masterKey, runtime, auditLog, health, custody, healthRead, custodyRead, chainRead, chain,
    makeTool, readTool, setBinding: (value: SessionBinding | undefined) => { binding = value; } };
}
function status(rows: ProtectionLayerRow[] | undefined, id: string) {
  return rows?.find(row => row.id === id)?.status;
}

import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { DEFAULT_POLICY, generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { createSanctuaryServer } from "../../src/index.js";
import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import { startDashboard } from "../../src/dashboard/index.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { buildUnwrappedRoster } from "../../src/principal-policy/posture.js";
import type { PosturePanelStore } from "../../src/principal-policy/panel-producer.js";
import type { PostureHome } from "../../src/principal-policy/posture-home-types.js";
import * as boundedRead from "../../src/dashboard/read-response.js";
import { getFreePort } from "../helpers/free-port.js";

const TOKEN = "protection-observation-test-token";
const EPHEMERAL_PORT = 0; // Ask the kernel to allocate an unused port.
const HTTP_OK = 200; // Successful HTTP response.
const HTTP_UNAUTHORIZED = 401; // Failed authenticated unlock.
const APPROVAL_SECONDS = 30; // Same local approval timeout as the existing HTTP fixture.
const auth = { Authorization: `Bearer ${TOKEN}` };
function urlOf(channel: DashboardApprovalChannel) {
  const address = (channel as unknown as { httpServer?: Server }).httpServer?.address() as AddressInfo | undefined;
  expect(address?.port, "dashboard listener").toEqual(expect.any(Number));
  return `http://127.0.0.1:${address?.port}`;
}
async function readHome(url: string) {
  const response = await fetch(`${url}/api/posture/home`, { headers: auth });
  return { status: response.status, home: await response.json() as PostureHome };
}
function dependencies(f: Awaited<ReturnType<typeof fixture>>, path: string) {
  return { policy: DEFAULT_POLICY, baseline: new BaselineTracker(f.storage, f.masterKey), auditLog: f.auditLog,
    storage: f.storage, sanctuaryConfig: { ...defaultConfig(), storage_path: path }, ...f.runtime };
}
async function channelFor(f: Awaited<ReturnType<typeof fixture>>, path: string) {
  const channel = new DashboardApprovalChannel({ port: EPHEMERAL_PORT, host: "127.0.0.1",
    timeout_seconds: APPROVAL_SECONDS, auth_token: TOKEN, auto_open: false });
  channel.setDependencies(dependencies(f, path));
  pinRoster(channel);
  await channel.start();
  return channel;
}
function pinRoster(channel: DashboardApprovalChannel) {
  const store = (channel as unknown as { panelStore: PosturePanelStore }).panelStore;
  const read = store.read.bind(store);
  // A fixed roster producer isolates dependency changes from the scanner's own audit append.
  vi.spyOn(store, "read").mockImplementation((id, sequence, produce, key) => read(id, sequence,
    id === "unwrapped" ? () => buildUnwrappedRoster({ originMachine: "local", wrappedAgents: [], detectedHarnesses: [] }) : produce, key));
}
function renderedRows(html: string, home: PostureHome) {
  const element = { innerHTML: "" };
  const document = { getElementById: (id: string) => id === "protection-layers" ? element : null };
  const esc = html.slice(html.indexOf("  function esc(s)"), html.indexOf('  // "Never fake green"'));
  const layers = html.slice(html.indexOf("  function renderProtectionLayers(rows)"), html.indexOf("  function renderFeatures(panel)"));
  const render = html.slice(html.indexOf("  function renderHome(home, approvals, findings)"), html.indexOf("  function renderPanelStatus(home)"));
  const noop = () => {};
  // Run the shipped home path and its real layer renderer against the element fixture.
  const renderHome = new Function("document", "noop", `
    const renderBanner = noop, renderAgents = noop, renderApprovals = noop, renderStory = noop,
      renderAnomalies = noop, renderWall = noop, renderFeatures = noop, renderCustodyExit = noop,
      renderQueryPrivacy = noop, renderPanelStatus = noop;
    ${esc}\n${layers}\n${render}\nreturn renderHome;
  `)(document, noop);
  renderHome(home);
  // Ampersand is unescaped last so an escaped entity such as "&amp;lt;" decodes once, to "&lt;", never to "<".
  const decode = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
  return Array.from(element.innerHTML.matchAll(/<span class="pill [^"]+">([^<]*)<\/span><span class="name">([^<]*)<\/span><span class="why">([^<]*)<\/span>/g),
    match => ({ name: decode(match[2]!), status: decode(match[1]!), basis: decode(match[3]!) })); // Capture groups follow status, name, basis in markup order.
}

it("dashboard composition carries runtime observations", async () => {
  const directory = await createTempHome("dashboard-observations");
  let channel: DashboardApprovalChannel | undefined;
  try {
    const f = await fixture();
    channel = await channelFor(f, directory.defaultFortressPath);
    const tool = await f.readTool();
    const response = await readHome(urlOf(channel));
    expect(response.status).toBe(HTTP_OK);
    expect(status(response.home.protection_layers, "identity"), "Identity status").toBe("on");
    expect(status(response.home.protection_layers, "encrypted_vault"), "Encrypted vault status").toBe("on");
    const html = await (await fetch(`${urlOf(channel)}/posture`, { headers: auth })).text();
    const rendered = renderedRows(html, response.home);
    expect(rendered, "rendered rows").toEqual(tool.layers.map(row => ({ name: row.name, status: row.status.replace("_", " "), basis: row.basis })));
    expect(response.home.protection_layers).toEqual(tool.layers);
    expect(rendered).toHaveLength(composeProtectionLayers({}).length);
    expect(tool.guarantees).toEqual(guarantees);
    expect(tool.summary.split("\n")).toEqual(tool.layers.map(row => `${row.name}: ${row.status.replace("_", " ")}`));
  } finally { await channel?.stop(); await directory.cleanup(); }
});

it("dashboard entry points preserve observation availability", async () => {
  const directory = await createTempHome("dashboard-entry-observations");
  const previous = new Map(["SANCTUARY_STORAGE_PATH", "SANCTUARY_SESSION_IDENTITY_ID", "SANCTUARY_DASHBOARD_PORT",
    "SANCTUARY_DASHBOARD_HOST", "SANCTUARY_DASHBOARD_AUTH_TOKEN", "SANCTUARY_PASSPHRASE"].map(key => [key, process.env[key]]));
  const channels: DashboardApprovalChannel[] = [];
  let app: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
  let secondary: Awaited<ReturnType<typeof startDashboard>> | undefined;
  let runningStandalone: Awaited<ReturnType<typeof startStandaloneDashboard>> | undefined;
  const start = DashboardApprovalChannel.prototype.start;
  vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(async function (this: DashboardApprovalChannel) {
    channels.push(this);
    await start.call(this);
  });
  try {
    const f = await fixture();
    // A raw backend alone cannot establish an encrypted consumer or a bound identity.
    const minimal = new DashboardApprovalChannel({ port: EPHEMERAL_PORT, host: "127.0.0.1",
      timeout_seconds: APPROVAL_SECONDS, auth_token: TOKEN, auto_open: false });
    const deps = dependencies(f, directory.defaultFortressPath);
    minimal.setDependencies({ policy: deps.policy, baseline: deps.baseline, auditLog: deps.auditLog,
      storage: deps.storage, sanctuaryConfig: deps.sanctuaryConfig });
    pinRoster(minimal);
    await minimal.start();
    let page = await readHome(urlOf(minimal));
    expect(status(page.home.protection_layers, "identity"), "unavailable identity").toBe("unknown");
    expect(status(page.home.protection_layers, "encrypted_vault"), "unavailable vault").toBe("unknown");
    minimal.setDependencies(deps);
    minimal.setDependencies({ policy: deps.policy, baseline: deps.baseline, auditLog: deps.auditLog });
    page = await readHome(urlOf(minimal));
    expect(status(page.home.protection_layers, "identity"), "partial attachment preserves identity").toBe("on");
    expect(status(page.home.protection_layers, "encrypted_vault"), "partial attachment preserves vault").toBe("on");
    const sequence = f.auditLog.currentInMemorySequence();
    const replacement = new IdentityManager(new MemoryStorage(), generateRandomKey());
    await replacement.load();
    minimal.setDependencies({ ...deps, identityManager: replacement });
    page = await readHome(urlOf(minimal));
    expect(status(page.home.protection_layers, "identity"), "replacement manager observes absence").toBe("off");
    minimal.setDependencies(deps);
    const missingId = "unloaded-session";
    f.setBinding({ identity_id: missingId, requester_identity_fingerprint: fingerprintIdentityId(missingId) });
    page = await readHome(urlOf(minimal));
    expect(status(page.home.protection_layers, "identity"), "changed bound subject").toBe("off");
    minimal.setDependencies({ ...deps, currentSessionBinding: () => undefined });
    page = await readHome(urlOf(minimal));
    expect(status(page.home.protection_layers, "identity"), "replaced binding resolver").toBe("unknown");
    expect(f.auditLog.currentInMemorySequence()).toBe(sequence);
    await minimal.stop();

    secondary = await startDashboard({ mode: "standalone", serverVersion: "test", port: EPHEMERAL_PORT,
      host: "127.0.0.1", authToken: TOKEN, auditLog: f.auditLog, identityManager: f.runtime.identityManager,
      stateStore: f.runtime.stateStore });
    page = await readHome(secondary.url);
    expect(status(page.home.protection_layers, "identity"), "unbound secondary identity").toBe("unknown");
    expect(status(page.home.protection_layers, "encrypted_vault"), "secondary constructed vault").toBe("on");
    await secondary.stop(); secondary = undefined;
    const bound = f.runtime.identityManager.getDefault()!.identity_id;
    secondary = await startDashboard({ mode: "co-located", serverVersion: "test", port: EPHEMERAL_PORT,
      host: "127.0.0.1", authToken: TOKEN, auditLog: f.auditLog, identityManager: f.runtime.identityManager,
      stateStore: f.runtime.stateStore, currentSessionBinding: () => ({ identity_id: bound,
        requester_identity_fingerprint: fingerprintIdentityId(bound) }) });
    page = await readHome(secondary.url);
    expect(status(page.home.protection_layers, "identity"), "bound secondary identity").toBe("on");
    await secondary.stop(); secondary = undefined;
    vi.restoreAllMocks();
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(async function (this: DashboardApprovalChannel) {
      channels.push(this); await start.call(this);
    });
    const attachments = vi.spyOn(DashboardApprovalChannel.prototype, "setDependencies");
    const constructions = vi.spyOn(cooperativeSource, "createAgentNativeCooperativeTools");
    const root = join(directory.home, "main-fortress");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "principal-policy.yaml"), generateDefaultPolicyYaml().replace("type: stderr", "type: dashboard"));
    process.env.SANCTUARY_STORAGE_PATH = root;
    // The configured dashboard port must be 1..65535, so the shared helper supplies one the kernel reported free.
    process.env.SANCTUARY_DASHBOARD_PORT = String(await getFreePort());
    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = TOKEN;
    process.env.SANCTUARY_SESSION_IDENTITY_ID = "observed-main-session";
    app = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
    const main = channels.at(LAST_ROW)!;
    const mainSources = attachments.mock.calls.find(([value]) => value.stateStore)?.[FIRST_CONTENT];
    const toolSources = constructions.mock.calls.at(LAST_ROW)?.[FIRST_CONTENT];
    expect(mainSources?.currentSessionBinding, "main bound resolver").toEqual(expect.any(Function));
    expect(mainSources?.stateStore, "main store source").toBeInstanceOf(StateStore);
    expect(mainSources?.responseScreen?.assertReady, "main screen source").toEqual(expect.any(Function));
    expect(mainSources?.currentSessionBinding, "same main session resolver").toBe(toolSources?.currentSessionBinding);
    expect(mainSources?.stateStore, "same main store").toBe(toolSources?.stateStore);
    expect(mainSources?.responseScreen, "same main screen").toBe(toolSources?.responseScreen);
    type ToolCallHandler = (request: unknown, extra: unknown) => Promise<{ content?: Array<{ text?: string }> } | undefined>;
    const handler = (app.server as unknown as { _requestHandlers: Map<string, ToolCallHandler> })._requestHandlers.get("tools/call");
    expect(handler, "main tool handler").toEqual(expect.any(Function));
    const call = async () => {
      const response = await handler?.({ method: "tools/call", params: { name: "sanctuary_active_protections", arguments: {} } }, {});
      return JSON.parse(response?.content?.[FIRST_CONTENT]?.text ?? "null");
    };
    const tool = await call();
    page = await readHome(urlOf(main));
    expect(status(page.home.protection_layers, "encrypted_vault"), "main constructed vault").toBe("on");
    expect(status(page.home.protection_layers, "identity"), "main bound lookup").toBe("off");
    expect(status(page.home.protection_layers, "identity")).toBe(status(tool?.layers, "identity"));
    delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    page = await readHome(urlOf(main));
    expect(status(page.home.protection_layers, "identity"), "main resolver follows session").toBe("unknown");
    expect((await call())?.denied).toBe(true);
    await app.cleanup(); app = undefined;

    const standaloneRoot = join(directory.home, "standalone-fortress");
    await mkdir(join(standaloneRoot, "state"), { recursive: true });
    const custody = await establishMaster({ storage: new FilesystemStorage(join(standaloneRoot, "state")),
      passphrase: TEST_PASSPHRASE, firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: standaloneRoot });
    await custody.masterWriteBarrier?.release();
    custody.masterKey.fill(0); // Erase the seed key with zero bytes.
    delete process.env.SANCTUARY_PASSPHRASE;
    let failLoad = true;
    const standalone = await startStandaloneDashboard({ storagePath: standaloneRoot, allowPark: true,
      host: "127.0.0.1", port: EPHEMERAL_PORT, distressPort: EPHEMERAL_PORT, authToken: TOKEN,
      discoveryOptions: { root: standaloneRoot, home: directory.home, env: {} },
      __testReadStoredPassphrase: async () => null,
      __testReadKeychainCustody: async () => ({ status: "not-found", service: "test-custody" }),
      __testFaultAfterLoads: () => { if (failLoad) throw new Error("load unavailable"); } });
    runningStandalone = standalone;
    expect(standalone.isParked(), "locked standalone").toBe(true);
    page = await readHome(urlOf(standalone));
    expect(page.home.protection_layers).toBeUndefined();
    const unlock = () => fetch(`${urlOf(standalone)}/api/unlock`, { method: "POST",
      headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ passphrase: TEST_PASSPHRASE }) });
    expect((await unlock()).status, "failed load").toBe(HTTP_UNAUTHORIZED);
    expect(standalone.isParked(), "failed load remains locked").toBe(true);
    page = await readHome(urlOf(standalone));
    expect(page.home.protection_layers).toBeUndefined();
    failLoad = false;
    expect((await unlock()).status, "successful unlock").toBe(HTTP_OK);
    page = await readHome(urlOf(standalone));
    expect(status(page.home.protection_layers, "encrypted_vault"), "standalone constructed vault").toBe("on");
    expect(status(page.home.protection_layers, "identity"), "unbound standalone identity").toBe("unknown");
    const taskStore = (standalone as unknown as { v11Bindings?: { hubService?: {
      taskService?: { deps?: { stateStore?: StateStore } } } } }).v11Bindings?.hubService?.taskService?.deps?.stateStore;
    expect(taskStore, "standalone TaskService store").toBeInstanceOf(StateStore);
    expect(attachments.mock.calls.at(LAST_ROW)?.[FIRST_CONTENT].stateStore, "same standalone store attached").toBe(taskStore);
    await standalone.stop(); runningStandalone = undefined;
  } finally {
    await secondary?.stop(); await app?.cleanup(); await runningStandalone?.stop();
    for (const channel of channels.reverse()) await channel.stop();
    for (const [key, value] of previous) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    await directory.cleanup();
  }
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

it("joined and streamed homes preserve qualified observations", async () => {
  const directory = await createTempHome("joined-observations");
  let channel: DashboardApprovalChannel | undefined;
  const pending: Promise<unknown>[] = [];
  const releases: Array<() => void> = [];
  const streamAbort = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const f = await fixture();
    channel = await channelFor(f, directory.defaultFortressPath);
    const initial = await readHome(urlOf(channel));
    expect(status(initial.home.protection_layers, "identity"), "joined Identity status").toBe("on");
    expect(status(initial.home.protection_layers, "encrypted_vault"), "joined Encrypted vault status").toBe("on");
    const originalRead = boundedRead.respondWithBoundedDashboardRead;
    let held = deferred<void>();
    let produced = deferred<PostureHome>();
    let joined = deferred<void>();
    let leader = true;
    releases.push(() => held.resolve());
    vi.spyOn(boundedRead, "respondWithBoundedDashboardRead").mockImplementation(options => {
      if (options.route !== "posture_home") return originalRead(options);
      if (!leader) {
        const response = originalRead(options);
        joined.resolve();
        return response;
      }
      leader = false;
      return originalRead({ ...options, produce: async signal => {
        const response = await options.produce(signal);
        produced.resolve(response.body as PostureHome);
        await held.promise;
        return response;
      } });
    });
    const leaderRequest = readHome(urlOf(channel)); pending.push(leaderRequest);
    const originalHome = await produced.promise;
    const originalRows = structuredClone(originalHome.protection_layers);
    await f.auditLog.appendCritical({ layer: "l2", operation: "cross_harness_approval_resolved", identity_id: "system", result: "success", details: {} });
    const staleAt = observedAt + custodySource.DEFAULT_ENFORCEMENT_FRESHNESS_MS + 1; // First millisecond beyond freshness.
    const followerRequest = readHome(urlOf(channel)); pending.push(followerRequest);
    await joined.promise;
    vi.spyOn(Date, "now").mockReturnValue(staleAt);
    held.resolve();
    const [first, follower] = await Promise.all([leaderRequest, followerRequest]);
    expect(status(follower.home.protection_layers, "identity"), "follower retains bound identity").toBe("on");
    expect(status(follower.home.protection_layers, "encrypted_vault"), "follower retains constructed vault").toBe("on");
    expect(status(follower.home.protection_layers, "approval_gates")).toBe("unknown");
    expect(status(follower.home.protection_layers, "exit")).toBe("unknown");
    expect(follower.home.panels?.custody_exit.state).toBe("stale");
    expect(first.home.protection_layers).toEqual(originalRows);
    expect(originalHome.protection_layers).toEqual(originalRows);
    f.healthRead.mockResolvedValue(follower.home.feature_health);
    // Start the tool read at the panel timestamp, then settle it at the follower's evaluation instant.
    vi.spyOn(Date, "now").mockReturnValue(observedAt);
    f.custodyRead.mockImplementation(async () => {
      vi.spyOn(Date, "now").mockReturnValue(staleAt);
      return follower.home.custody_exit;
    });
    const tool = await f.readTool();
    expect(Date.now(), "shared follower evaluation instant").toBe(staleAt);
    expect(status(tool.layers, "identity")).toBe("on");
    expect(status(tool.layers, "exit")).toBe("unknown");
    expect(follower.home.protection_layers).toEqual(tool.layers);

    vi.spyOn(Date, "now").mockReturnValue(observedAt);
    f.healthRead.mockResolvedValue(f.health); f.custodyRead.mockResolvedValue(f.custody);
    held = deferred<void>(); produced = deferred<PostureHome>(); joined = deferred<void>(); leader = true;
    const unchangedRequest = readHome(urlOf(channel)); pending.push(unchangedRequest);
    const beforeChange = await produced.promise;
    const beforeRows = structuredClone(beforeChange.protection_layers);
    const auditSequence = f.auditLog.currentInMemorySequence();
    const subject = "different-loaded-session";
    f.setBinding({ identity_id: subject, requester_identity_fingerprint: fingerprintIdentityId(subject) });
    const deps = dependencies(f, directory.defaultFortressPath);
    channel.setDependencies({ ...deps, responseScreen: { assertReady() { throw new Error("screen unavailable"); } } });
    const changedRequest = readHome(urlOf(channel)); pending.push(changedRequest);
    await joined.promise;
    held.resolve();
    const [unchanged, changed] = await Promise.all([unchangedRequest, changedRequest]);
    expect(f.auditLog.currentInMemorySequence()).toBe(auditSequence);
    expect(status(changed.home.protection_layers, "identity"), "same sequence observes new subject").toBe("off");
    expect(status(changed.home.protection_layers, "encrypted_vault")).toBe("on");
    expect(changed.home.protection_layers?.at(LAST_ROW)?.basis).toContain("screening readiness: off");
    expect(unchanged.home.protection_layers).toEqual(beforeRows);
    expect(beforeChange.protection_layers).toEqual(beforeRows);
    vi.mocked(boundedRead.respondWithBoundedDashboardRead).mockRestore();

    const response = await fetch(`${urlOf(channel)}/api/posture/stream`, { headers: auth, signal: streamAbort.signal });
    expect(response.status).toBe(HTTP_OK);
    reader = response.body?.getReader();
    expect(reader, "stream reader").toBeDefined();
    let buffer = "";
    const decoder = new TextDecoder();
    const nextHome = async () => {
      while (true) {
        const end = buffer.indexOf("\n\n");
        if (end >= 0) { // A nonnegative delimiter offset identifies a complete frame.
          const frame = buffer.slice(0, end); // Read from the start of the buffered frame.
          buffer = buffer.slice(end + "\n\n".length);
          if (frame.startsWith("event: home\n")) return JSON.parse(frame.slice(frame.indexOf("data: ") + "data: ".length)) as PostureHome;
        } else {
          const chunk = await reader?.read();
          if (!chunk || chunk.done) return undefined;
          buffer += decoder.decode(chunk.value, { stream: true });
        }
      }
    };
    const streamed = await nextHome();
    expect(status(streamed?.protection_layers, "identity"), "stream current subject").toBe("off");
    expect(status(streamed?.protection_layers, "encrypted_vault")).toBe("on");
    const streamSequence = f.auditLog.currentInMemorySequence();
    channel.setDependencies({ ...deps, currentSessionBinding: () => undefined });
    const refreshed = await nextHome();
    expect(f.auditLog.currentInMemorySequence()).toBe(streamSequence);
    expect(status(refreshed?.protection_layers, "identity"), "stream dependency refresh").toBe("unknown");
    expect(status(refreshed?.protection_layers, "encrypted_vault")).toBe("on");
  } finally {
    releases.forEach(release => release());
    streamAbort.abort(); await reader?.cancel().catch(() => undefined);
    await Promise.allSettled(pending);
    await channel?.stop(); await directory.cleanup();
  }
});
