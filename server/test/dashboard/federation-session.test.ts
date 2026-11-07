import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { readJsonBody } from "../../src/v1/http.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { signOperatorAttestation } from "../../src/v1/operator-attestation.js";
import { addOperatorAuthorizationFields, signOperatorPayload, type OperatorAuthorizationConsumeParams } from "../../src/v1/operator-signed.js";
import { OperatorAuthorizationSpentStore } from "../../src/v1/operator-authorization-spent-store.js";
import { signSyncEnvelope } from "../../src/v1/federation-sync-envelope.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import { persistOperatorCloudJoinedNode } from "../../src/mesh/operator-cloud-joined-node-store.js";
import { OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION, OPERATOR_CLOUD_SCOPE_VERSION, wrapNodePrivateKeyForCloud } from "../../src/mesh/operator-cloud-provision.js";
import { NODE_TRUST_BOUNDARY_VERSION, OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL } from "../../src/mesh/node-posture.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer, type Server } from "node:net";
import { startStandaloneDashboard, handleStandaloneShutdownSignal, __resetStandaloneShutdownStateForTest } from "../../src/dashboard-standalone.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { DistressListener } from "../../src/distress/listener.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { provisionOrLoadFederationTrustRoot, zeroRecordSecrets, mintHybridFederationMaterial, FederationTrustRootStore, type ProvisionedFederationTrustRoot } from "../../src/mesh/federation-trust-root-store.js";
import { loadFederationJoinerTrustRoot, persistFederationJoinerTrustRoot, type ProvisionedFederationJoinerTrustRoot } from "../../src/mesh/federation-joiner-trust-root-store.js";
import { FederationSyncStateStore } from "../../src/v1/federation-sync-state-store.js";
import { MIN_BREAK_GLASS_DELAY_MS, type BreakGlassState } from "../../src/v1/federation-guardian-disable-gate.js";
import type { FederationContext, V1FederationDeps } from "../../src/v1/federation.js";
import { FLEET_ACTIVATION_META_KEY, readFleetActivation } from "../../src/entitlement/activation.js";
import { COMMUNITY_FREE_NODE_CAP } from "../../src/entitlement/fleet-cap.js";
import { withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import * as custody from "../../src/core/master-custody.js";
import { createTempFortress, TEST_PASSPHRASE, type TempFortress } from "../helpers/temp-fortress.js";

vi.mock("../../src/mesh/federation-trust-root-store.js", async (original) => {
  const real = await original<typeof import("../../src/mesh/federation-trust-root-store.js")>();
  return { ...real, provisionOrLoadFederationTrustRoot: vi.fn(real.provisionOrLoadFederationTrustRoot), zeroRecordSecrets: vi.fn(real.zeroRecordSecrets) };
});

vi.mock("../../src/mesh/federation-joiner-trust-root-store.js", async (original) => {
  const real = await original<typeof import("../../src/mesh/federation-joiner-trust-root-store.js")>();
  return { ...real, loadFederationJoinerTrustRoot: vi.fn(real.loadFederationJoinerTrustRoot) };
});

vi.mock("../../src/v1/http.js", async (original) => {
  const real = await original<typeof import("../../src/v1/http.js")>();
  return { ...real, readJsonBody: vi.fn(real.readJsonBody) };
});

type Job = "fleet" | "renewal" | "guardian";
type Owner = { flights: Map<Job, Promise<void>>; drain(): Promise<void> };
type Internals = {
  _federationWork?: Owner;
  _federationContext: FederationContext | null;
  _federationEnabled: boolean;
  _federationEnabledGeneration: number;
  _federationState: { revoked: Set<string>; evictionMaxSerial: number };
  _federationRevokedRoots: Set<string>;
  _federationHighestRevocationSerial: number;
  _operatorAuthorizationSpentStoreUnavailable: boolean;
  _federationReissueChallengeStoreUnavailable: boolean;
  resolveOperatorPublicKey(): Uint8Array | null;
  consumeV1OperatorAuthorization(params: OperatorAuthorizationConsumeParams): Promise<"consumed" | "replayed">;
  persistFederationSyncState(): Promise<void>;
  quiesceFederation(): Promise<void>;
  _federationSyncStateStore: FederationSyncStateStore | null;
  _operatorAuthorizationSpentStore: unknown;
  _federationReissueChallengeStore: unknown;
  _federationGuardianBreakGlass: BreakGlassState | null;
  _federationSyncStateUnavailable: boolean;
  _fleetReResolveTimer: ReturnType<typeof setInterval> | null;
  _federationRenewal: { tick(): Promise<void> } | null;
  _federationBreakGlassPoll: ReturnType<typeof setInterval> | null;
  httpServer: Server | null;
  runFleetLicenseReResolveTick(): Promise<void>;
  runFleetLicenseReResolveTickOnce(): Promise<void>;
  renewLocalFederationNodeCertificate(): Promise<void>;
  tickFederationGuardianBreakGlass(): Promise<void>;
  tickFederationGuardianBreakGlassInner(): Promise<void>;
  armFederationGuardianBreakGlassPoll(): void;
  upsertFederationNode(id: string): unknown;
  buildV1FederationDeps(): V1FederationDeps;
  unlockHandler(credential: { passphrase: string }): Promise<boolean>;
};
const internal = (channel: DashboardApprovalChannel) => channel as unknown as Internals;
const EPHEMERAL_PORT = 0;
const HOUR_MS = 60 * 60 * 1000; // All fixture intervals deliberately share a cadence.
const SIGNAL_STATUS_BASE = 128;
const SIGTERM_NUMBER = 15;
const HTTP_OK = 200;
const HTTP_BAD_REQUEST = 400;
const HTTP_FORBIDDEN = 403;
const FIRST_SERIAL = 1;
const ELAPSED = "2000-01-02T00:00:00.000Z";
const INITIATED = "2000-01-01T00:00:00.000Z";
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
const countdown = (): BreakGlassState => ({ nonce: 1, intent: "disable", targetM: null,
  initiatedAt: INITIATED, completesAt: ELAPSED, delayMs: MIN_BREAK_GLASS_DELAY_MS });

// The owner probe asserts exact flight presence before any settlement-order assertion.
async function drainWinner(entered: Promise<void>, completion: Promise<unknown>, released?: Promise<void>) {
  return await Promise.race([
    entered.then(() => "drain entered"),
    completion.then(() => "completion while flight held"),
    ...(released ? [released.then(() => "release while flight held")] : []),
  ]);
}
function observeDrain(channel: DashboardApprovalChannel) {
  const entered = deferred();
  let flights: Map<Job, Promise<void>> | undefined;
  const owner = internal(channel)._federationWork;
  if (owner) {
    const drain = owner.drain.bind(owner);
    vi.spyOn(owner, "drain").mockImplementation(() => {
      flights = new Map(owner.flights); entered.resolve(); return drain();
    });
  }
  return { entered: entered.promise, assert: (job: Job, flight: Promise<void> | undefined, winner: string) => {
    expect(flights, `drain race winner: ${winner}`).toBeDefined();
    expect(flight, "the admitted flight must be present").toBeDefined();
    expect(flights!.get(job)).toBe(flight);
  } };
}

describe("federation session settlement", () => {
  let fortress: TempFortress;
  let env: NodeJS.ProcessEnv;
  let channels: DashboardApprovalChannel[];
  let listeners: DistressListener[];
  let sessions: custody.EstablishMasterResult[];
  let records: ProvisionedFederationTrustRoot[];
  let gates: ReturnType<typeof deferred>[];
  let pending: Promise<unknown>[];
  let events: string[];
  let released: ReturnType<typeof deferred>;
  let releases: ReturnType<typeof vi.spyOn>[];
  let intervals: Map<ReturnType<typeof setInterval>, () => void>;
  let occupying: Server | undefined;
  let auditLogs: Set<AuditLog>;
  const realReadBody = vi.mocked(readJsonBody).getMockImplementation()!;
  const realScrub = vi.mocked(zeroRecordSecrets).getMockImplementation()!;
  const realLoad = vi.mocked(provisionOrLoadFederationTrustRoot).getMockImplementation()!;
  const realJoinerLoad = vi.mocked(loadFederationJoinerTrustRoot).getMockImplementation()!;
  const storage = () => new FilesystemStorage(join(fortress.storagePath, "state"));
  const own = <T>(promise: Promise<T>) => { pending.push(promise.catch(() => undefined)); return promise; };
  const gate = () => { const value = deferred(); gates.push(value); return value; };
  const boot = (options: Parameters<typeof startStandaloneDashboard>[0] = {}) => own(startStandaloneDashboard({
    passphrase: TEST_PASSPHRASE, host: "127.0.0.1", port: EPHEMERAL_PORT, distressPort: EPHEMERAL_PORT,
    configPath: join(fortress.home, "config.json"),
    discoveryOptions: { home: fortress.home, root: fortress.storagePath, env: {} }, ...options,
  }));
  const exclusive = () => withExclusiveMasterRotationBarrier(storage(), custody.CUSTODY_WRITE_LOCK_NAMESPACE,
    custody.MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 });
  const baseUrl = (channel: DashboardApprovalChannel) =>
    `http://127.0.0.1:${(internal(channel).httpServer!.address() as import("node:net").AddressInfo).port}`;
  const post = async (url: string, body: unknown, token?: string) => {
    const response = await fetch(url, { method: "POST", headers: {
      "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  async function openSession(channel: DashboardApprovalChannel, privateKey: Uint8Array) {
    channel.setAutoAuthLocalhost(true);
    const publicKey = ed25519.getPublicKey(privateKey);
    vi.spyOn(internal(channel), "resolveOperatorPublicKey").mockReturnValue(publicKey);
    const init = await post(`${baseUrl(channel)}/v1/session/init`, {
      client_pubkey: toBase64url(publicKey), operator_attestation: signOperatorAttestation({
        operatorPublicKey: publicKey, operatorPrivateKey: privateKey, clientPubkey: publicKey, issuedAtMs: Date.now(),
      }),
    });
    expect(init.status).toBe(HTTP_OK);
    const challenge = init.body as { challenge: string; challenge_id: string; attestation_ref: string };
    const message = buildChallengeMessage(publicKey, fromBase64url(challenge.challenge), challenge.attestation_ref);
    const complete = await post(`${baseUrl(channel)}/v1/session/complete`, {
      challenge_id: challenge.challenge_id, client_signature: toBase64url(ed25519.sign(message, privateKey)),
    });
    expect(complete.status).toBe(HTTP_OK);
    return (complete.body as { session_token: string }).session_token;
  }
  function holdBody(path: string) {
    const entered = deferred(); const finish = gate();
    vi.mocked(readJsonBody).mockImplementation(async (req, ...args) => {
      if (req.url === path) { entered.resolve(); await finish.promise; }
      return realReadBody(req, ...args);
    });
    return { entered: entered.promise, finish };
  }
  async function stopDuringBody(channel: DashboardApprovalChannel) {
    const probe = observeDrain(channel);
    const stopped = own(channel.stop());
    await probe.entered;
    // Let an idle drain and its continuations finish while the HTTP body remains held.
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(releases[0], "HTTP grace retains custody").not.toHaveBeenCalled();
    return { stopped };
  }
  const authorization = (): OperatorAuthorizationConsumeParams => ({
    replayKey: "session-replay-key", action: "/v1/agents/unprotect", authorizationNonce: "session-nonce",
    expiresAt: new Date(Date.now() + HOUR_MS).toISOString(), operatorPublicKey: new Uint8Array(),
  });
  async function held(channel: DashboardApprovalChannel, probe: ReturnType<typeof observeDrain>, job: Job,
    flight: Promise<void> | undefined, completion: Promise<unknown>) {
    const winner = await drainWinner(probe.entered, completion, released.promise);
    probe.assert(job, flight, winner);
    expect(releases[0]).not.toHaveBeenCalled();
    expect(sessions[0]!.masterKey.some((byte) => byte !== 0)).toBe(true);
    await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    expect(internal(channel).httpServer).toBeNull();
  }
  async function finished() {
    expect(releases[0]).toHaveBeenCalledOnce();
    expect(sessions[0]!.masterKey.every((byte) => byte === 0)).toBe(true);
    expect(events).toContain("settled");
    expect(events).toContain("released");
    expect(events.indexOf("settled")).toBeLessThan(events.indexOf("released"));
    await expect(exclusive()).resolves.toBe("entered");
  }
  beforeEach(async () => {
    env = { ...process.env };
    fortress = await createTempFortress("federation-session");
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "federation-session-token";
    await writeFile(join(fortress.home, "config.json"), "{}");
    channels = []; listeners = []; sessions = []; records = []; gates = []; pending = []; events = []; auditLogs = new Set();
    releases = []; intervals = new Map(); released = deferred(); occupying = undefined;
    __resetStandaloneShutdownStateForTest();
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: fortress.storagePath });
    const root = await realLoad({ storage: storage(), masterKey: seed.masterKey, mint: true, nodeId: "session-home" });
    for (const bytes of [root!.record.master_secret, root!.record.master_private_key!,
      root!.record.issuing_principal_private_key, root!.record.local_node_private_key]) bytes.fill(0);
    await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
    vi.mocked(provisionOrLoadFederationTrustRoot).mockImplementation(async (options) => {
      const loaded = await realLoad(options);
      if (loaded) {
        Object.assign(loaded.context, { nodeCertificateRenewal: { renewalCheckIntervalMs: HOUR_MS } });
        records.push(loaded);
      }
      return loaded;
    });
    const append = AuditLog.prototype.append;
    vi.spyOn(AuditLog.prototype, "append").mockImplementation(function (this: AuditLog, ...args) {
      auditLogs.add(this); return own(append.apply(this, args));
    });
    const critical = AuditLog.prototype.appendCritical;
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementation(function (this: AuditLog, ...args) {
      auditLogs.add(this); return own(critical.apply(this, args));
    });
    const establish = custody.establishMaster;
    vi.spyOn(custody, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options); sessions.push(session);
      const release = session.masterWriteBarrier!.release.bind(session.masterWriteBarrier);
      releases.push(vi.spyOn(session.masterWriteBarrier!, "release").mockImplementation(async () => {
        events.push("released"); released.resolve(); await release();
      }));
      return session;
    });
    const mark = DashboardApprovalChannel.prototype.setStandaloneMode;
    vi.spyOn(DashboardApprovalChannel.prototype, "setStandaloneMode").mockImplementation(function (this: DashboardApprovalChannel, value) {
      channels.push(this); return mark.call(this, value);
    });
    const start = DistressListener.prototype.start;
    vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener) {
      listeners.push(this); return start.call(this);
    });
    // Only intervals are faked so filesystem locks and HTTP closure keep real scheduling.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const schedule = globalThis.setInterval;
    vi.spyOn(globalThis, "setInterval").mockImplementation(((callback: () => void, delay?: number) => {
      const handle = schedule(callback, delay); intervals.set(handle, callback); return handle;
    }) as typeof setInterval);
  });
  afterEach(async () => {
    for (const value of gates) value.resolve();
    await Promise.allSettled(pending);
    for (const channel of channels) await channel.stop().catch(() => undefined);
    for (const listener of listeners) await listener.stop().catch(() => undefined);
    for (const log of auditLogs) await log.flush().catch(() => undefined);
    for (const session of sessions) { await session.masterWriteBarrier?.release(); session.masterKey.fill(0); }
    if (occupying) await new Promise<void>((resolve) => occupying!.close(() => resolve()));
    vi.restoreAllMocks(); vi.useRealTimers();
    vi.mocked(provisionOrLoadFederationTrustRoot).mockImplementation(realLoad);
    vi.mocked(loadFederationJoinerTrustRoot).mockImplementation(realJoinerLoad);
    vi.mocked(readJsonBody).mockImplementation(realReadBody);
    vi.mocked(zeroRecordSecrets).mockImplementation(realScrub);
    __resetStandaloneShutdownStateForTest();
    await fortress.cleanup(); process.env = env;
  });

  it.each(["read", "write"] as const)("scheduled fleet %s settles before final persistence and release", async (boundary) => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick();
    for (let index = 0; index <= COMMUNITY_FREE_NODE_CAP; index++) state.upsertFederationNode(`fleet-${index}`);
    const entered = deferred(); const finish = gate();
    const method = FilesystemStorage.prototype[boundary];
    vi.spyOn(FilesystemStorage.prototype, boundary).mockImplementation(async function (this: FilesystemStorage, ...args: Parameters<typeof method>) {
      if (args[0] === "_meta" && args[1] === FLEET_ACTIVATION_META_KEY) {
        entered.resolve(); await finish.promise;
      }
      const result = await (method as (...values: typeof args) => Promise<Uint8Array | null | void>).apply(this, args);
      if (boundary === "write" && args[1] === FLEET_ACTIVATION_META_KEY) events.push("committed");
      return result;
    } as never);
    const callback = intervals.get(state._fleetReResolveTimer!)!;
    expect(callback).toBeTypeOf("function"); callback(); await entered.promise;
    const flight = state._federationWork?.flights.get("fleet");
    const joined = own(state.runFleetLicenseReResolveTick().then(() => { events.push("settled"); }));
    const master = sessions[0]!.masterKey.slice();
    const probe = observeDrain(channel); const stopped = own(channel.stop());
    await held(channel, probe, "fleet", flight, stopped);
    callback(); await state.runFleetLicenseReResolveTick();
    expect(state._fleetReResolveTimer).toBeNull();
    finish.resolve(); await joined; await stopped;
    expect((await readFleetActivation(storage(), master)).status).toBe("valid"); master.fill(0);
    await finished();
  });

  it("certificate renewal joins its audit tail and seals route admission", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.renewLocalFederationNodeCertificate();
    const context = state._federationContext!;
    context.localNodeCert!.expires_at = new Date().toISOString();
    const copies: Uint8Array[] = [];
    const get = context.getIssuingPrincipalPrivateKey!;
    context.getIssuingPrincipalPrivateKey = () => { const key = get(); copies.push(key); return key; };
    const entered = deferred(); const finish = gate();
    const append = vi.mocked(AuditLog.prototype.append).getMockImplementation()!;
    vi.spyOn(AuditLog.prototype, "append").mockImplementation(async function (this: AuditLog, ...args) {
      if (args[1] === "v1_federation_node_cert_auto_renewed") { entered.resolve(); await finish.promise; }
      const result = await append.apply(this, args);
      if (args[1] === "v1_federation_node_cert_auto_renewed") events.push("settled");
      return result;
    });
    const deps = state.buildV1FederationDeps(); deps.renewLocalNodeCertificate(); await entered.promise;
    const scheduled = state._federationRenewal!;
    own(scheduled.tick());
    const flight = state._federationWork?.flights.get("renewal");
    const probe = observeDrain(channel);
    const stopped = own(DashboardApprovalChannel.prototype.stop.call(channel));
    const winner = await drainWinner(probe.entered, stopped); probe.assert("renewal", flight, winner);
    expect(copies.length).toBe(1); expect(copies.every((key) => key.every((byte) => byte === 0))).toBe(true);
    expect(Date.parse(context.localNodeCert!.expires_at!)).toBeGreaterThan(Date.now());
    context.localNodeCert!.expires_at = new Date().toISOString();
    deps.renewLocalNodeCertificate(); expect(copies.length).toBe(1);
    finish.resolve(); await stopped; await channel.stop(); await finished();
  });

  it.each(["stop", "failed unlock"] as const)("elapsed guardian persistence settles before %s finalization", async (mode) => {
    const session = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE, storagePathHint: fortress.storagePath });
    const seedStore = new FederationSyncStateStore({ storage: storage(), masterKey: session.masterKey });
    const snapshot = await seedStore.load(); snapshot.guardianBreakGlass = countdown(); snapshot.guardianRevocationRequirementGeneration = 1;
    await seedStore.persist(snapshot); await session.masterWriteBarrier?.release(); session.masterKey.fill(0);
    sessions = []; releases = []; released = deferred(); events = [];
    const entered = deferred(); const finish = gate();
    const persist = FederationSyncStateStore.prototype.persist;
    vi.spyOn(FederationSyncStateStore.prototype, "persist").mockImplementation(async function (this: FederationSyncStateStore, ...args) {
      entered.resolve(); await finish.promise; const result = await persist.apply(this, args); events.push("settled"); return result;
    });
    let probe: ReturnType<typeof observeDrain>;
    let flight: Promise<void> | undefined;
    const channel = await boot(mode === "stop" ? {} : { allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      flight = internal(channels[0]!)._federationWork?.flights.get("guardian");
      throw new Error("fixture load stop");
    } });
    const state = internal(channel);
    probe = observeDrain(channel);
    const completion = mode === "stop" ? undefined : own(state.unlockHandler({ passphrase: TEST_PASSPHRASE }));
    await entered.promise;
    if (mode === "stop") { flight = state._federationWork?.flights.get("guardian"); }
    const stopped = completion ?? own(channel.stop());
    const winner = await drainWinner(probe.entered, stopped, released.promise);
    probe!.assert("guardian", flight!, winner);
    expect(releases[0]).not.toHaveBeenCalled(); await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    finish.resolve(); await stopped;
    expect(state._federationSyncStateStore === null).toBe(true);
    const count = events.filter((value) => value === "settled").length;
    await state.tickFederationGuardianBreakGlass();
    expect(events.filter((value) => value === "settled")).toHaveLength(count);
    await finished();
  });

  it.each(["classical", "hybrid"] as const)("failed %s unlock detaches stores and scrubs loaded records before retry", async (suite) => {
    if (suite === "hybrid") {
      const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE, storagePathHint: fortress.storagePath });
      const root = (await realLoad({ storage: storage(), masterKey: seed.masterKey }))!;
      root.record.hybrid = await mintHybridFederationMaterial({ fortressId: root.record.fortress_id, nodeId: root.record.node_id });
      await new FederationTrustRootStore(storage(), seed.masterKey).save(root.record);
      for (const keys of [root.record.hybrid.master_private_keys, root.record.hybrid.issuing_principal_private_keys,
        root.record.hybrid.local_node_private_keys]) { keys.ed25519.private_key.fill(0); keys.ml_dsa_65.secret_key.fill(0); }
      for (const key of [root.record.master_secret, root.record.master_private_key!, root.record.issuing_principal_private_key,
        root.record.local_node_private_key]) key.fill(0);
      await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
      sessions = []; releases = []; events = []; released = deferred();
    }
    let fail = true;
    let stores: unknown[] = [];
    const channel = await boot({ allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      const state = internal(channels[0]!);
      stores = [state._operatorAuthorizationSpentStore, state._federationReissueChallengeStore];
      if (fail) throw new Error("fixture load stop");
    } });
    const state = internal(channel);
    expect(await state.unlockHandler({ passphrase: TEST_PASSPHRASE })).toBe(false);
    expect(records.length).toBe(1);
    expect(channel.isFederationProvisioned()).toBe(false);
    expect(state._federationSyncStateStore === null).toBe(true);
    await expect(state.consumeV1OperatorAuthorization(authorization()), "failed unlock leaves replay consumption unavailable")
      .rejects.toThrow("operator_authorization_spent_store_unavailable");
    expect(state._federationReissueChallengeStoreUnavailable).toBe(true);
    expect(state._federationSyncStateUnavailable).toBe(true);
    expect(state._operatorAuthorizationSpentStore === stores[0]).toBe(false);
    expect(state._federationReissueChallengeStore === stores[1]).toBe(false);
    const record = records[0]!.record;
    expect([record.master_secret, record.master_private_key!, record.issuing_principal_private_key,
      record.local_node_private_key].every((key) => key.every((byte) => byte === 0))).toBe(true);
    if (suite === "hybrid") {
      expect(record.hybrid).toBeDefined();
      expect([record.hybrid!.master_private_keys, record.hybrid!.issuing_principal_private_keys,
        record.hybrid!.local_node_private_keys].every((keys) => keys.ed25519.private_key.every((byte) => byte === 0)
          && keys.ml_dsa_65.secret_key.every((byte) => byte === 0))).toBe(true);
    }
    const previous = state._federationWork;
    for (const callback of intervals.values()) callback();
    expect(channel.isFederationProvisioned()).toBe(false);
    fail = false; expect(await state.unlockHandler({ passphrase: TEST_PASSPHRASE })).toBe(true);
    expect(state._federationWork).not.toBe(previous);
    expect(records[1]!.record.master_secret.some((byte) => byte !== 0)).toBe(true);
  });

  it.each(["fleet", "guardian", "renewal"] as const)("a held %s job retains custody and rejection preserves signal status", async (job) => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick(); await state.renewLocalFederationNodeCertificate();
    const entered = deferred(); const finish = gate();
    const body = job === "fleet" ? "runFleetLicenseReResolveTickOnce"
      : job === "guardian" ? "tickFederationGuardianBreakGlassInner" : "renewLocalFederationNodeCertificateOnce";
    const target = state as unknown as Record<typeof body, () => Promise<void>>;
    if (body in target) vi.spyOn(target, body).mockImplementation(async () => {
      entered.resolve(); await finish.promise; events.push("settled"); throw new Error("fixture job stop");
    });
    else {
      // The pre-wrapper renewal body still reaches the audit boundary on the baseline.
      state._federationContext!.localNodeCert!.expires_at = new Date().toISOString();
      vi.spyOn(AuditLog.prototype, "append").mockImplementation(async () => {
        entered.resolve(); await finish.promise; events.push("settled"); throw new Error("fixture job stop");
      });
    }
    const run = job === "fleet" ? state.runFleetLicenseReResolveTick.bind(state)
      : job === "guardian" ? state.tickFederationGuardianBreakGlass.bind(state) : state.renewLocalFederationNodeCertificate.bind(state);
    own(Promise.resolve(run()).catch(() => undefined)); await entered.promise;
    const flight = state._federationWork?.flights.get(job); const probe = observeDrain(channel);
    const stdout = vi.spyOn(process.stdout, "write"); const stderr = vi.spyOn(process.stderr, "write");
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const stopped = own(handleStandaloneShutdownSignal("SIGTERM"));
    await held(channel, probe, job, flight, stopped);
    await new Promise<void>((resolve) => setImmediate(resolve)); expect(exit).not.toHaveBeenCalled();
    finish.resolve(); await stopped;
    expect(exit).toHaveBeenCalledWith(SIGNAL_STATUS_BASE + SIGTERM_NUMBER);
    expect(stdout).not.toHaveBeenCalled(); expect(stderr).not.toHaveBeenCalled(); await finished();
  });

  it("a captured fleet callback and direct entrance remain sealed after stop", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick();
    const callback = intervals.get(state._fleetReResolveTimer!)!;
    const run = vi.spyOn(state, "runFleetLicenseReResolveTickOnce");
    await channel.stop(); callback(); await state.runFleetLicenseReResolveTick();
    expect(run, "no tick is admitted after stop").not.toHaveBeenCalled();
  });

  it("stop overtaking a successful load prevents binding and scrubs its record", async () => {
    const entered = deferred(); const finish = gate();
    vi.mocked(provisionOrLoadFederationTrustRoot).mockImplementation(async (options) => {
      const loaded = await realLoad(options); if (loaded) records.push(loaded);
      entered.resolve(); await finish.promise; return loaded;
    });
    const started = boot(); await entered.promise;
    const channel = channels[0]!; const bind = vi.spyOn(channel, "setFederationContext");
    const stopped = own(channel.stop()); finish.resolve(); await expect(started).rejects.toMatchObject({ name: "AbortError" }); await stopped;
    expect(bind).not.toHaveBeenCalled();
    expect(records[0]!.record.master_secret.every((byte) => byte === 0)).toBe(true);
    expect(channel.isFederationProvisioned()).toBe(false);
  });

  it.each(["wiring", "stand-down"] as const)("loaded records are scrubbed after %s", async (mode) => {
    let port = EPHEMERAL_PORT;
    if (mode === "stand-down") {
      occupying = createServer(); await new Promise<void>((resolve) => occupying!.listen(0, "127.0.0.1", resolve));
      port = (occupying.address() as import("node:net").AddressInfo).port;
    }
    const failure = new Error("fixture load stop");
    const started = boot({ port, allowPark: true, ...(mode === "wiring" ? { __testFaultAfterLoads: () => { throw failure; } } : {}) });
    if (mode === "wiring") await expect(started).rejects.toBe(failure); else await started;
    expect(records.length).toBe(1);
    expect(records[0]!.record.master_secret.every((byte) => byte === 0)).toBe(true);
    expect(channels[0]!.isFederationProvisioned()).toBe(false);
    await expect(exclusive()).resolves.toBe("entered");
  });
  it("a failed local joiner unlock scrubs its node record before retry", async () => {
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE, storagePathHint: fortress.storagePath });
    const root = (await realLoad({ storage: storage(), masterKey: seed.masterKey }))!;
    await storage().delete("_federation", "trust-root-v1");
    const joined = await persistFederationJoinerTrustRoot({ storage: storage(), masterKey: seed.masterKey,
      pinnedMasterPubkey: root.record.pinned_master_pubkey, issuingPrincipalCert: root.record.issuing_principal_cert,
      localNodeCert: root.record.local_node_cert, localNodePrivateKey: root.record.local_node_private_key });
    joined.record.local_node_private_key.fill(0);
    for (const key of [root.record.master_secret, root.record.master_private_key!, root.record.issuing_principal_private_key,
      root.record.local_node_private_key]) key.fill(0);
    await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
    sessions = []; releases = []; events = []; released = deferred();
    const loaded: ProvisionedFederationJoinerTrustRoot[] = [];
    vi.mocked(loadFederationJoinerTrustRoot).mockImplementation(async (options) => {
      const result = await realJoinerLoad(options); if (result) loaded.push(result); return result;
    });
    let fail = true;
    const channel = await boot({ allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      if (fail) throw new Error("fixture joiner stop");
    } });
    const state = internal(channel);
    expect(await state.unlockHandler({ passphrase: TEST_PASSPHRASE })).toBe(false);
    expect(releases[0]).toHaveBeenCalledOnce(); expect(loaded.length).toBe(1);
    expect(loaded[0]!.record.local_node_private_key.every((byte) => byte === 0)).toBe(true);
    expect(channel.isFederationProvisioned()).toBe(false);
    fail = false; expect(await state.unlockHandler({ passphrase: TEST_PASSPHRASE })).toBe(true);
    expect(state._federationContext!.getIssuingPrincipalPrivateKey).toBeUndefined();
    expect(loaded[1]!.record.local_node_private_key.some((byte) => byte !== 0)).toBe(true);
  });

  it("all recurring flights settle before stop completes when one rejects", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick(); await state.renewLocalFederationNodeCertificate();
    const fleetFinish = gate(); const guardianFinish = gate(); const renewalFinish = gate();
    const entered = [deferred(), deferred(), deferred()];
    const fleet = vi.spyOn(state, "runFleetLicenseReResolveTickOnce").mockImplementation(async () => {
      entered[0]!.resolve(); await fleetFinish.promise; events.push("fleet-settled"); throw new Error("fixture job stop");
    });
    vi.spyOn(state, "tickFederationGuardianBreakGlassInner").mockImplementation(async () => {
      entered[1]!.resolve(); await guardianFinish.promise; events.push("guardian-settled");
    });
    state._federationContext!.localNodeCert!.expires_at = new Date().toISOString();
    const append = vi.mocked(AuditLog.prototype.append).getMockImplementation()!;
    vi.spyOn(AuditLog.prototype, "append").mockImplementation(async function (this: AuditLog, ...args) {
      if (args[1] === "v1_federation_node_cert_auto_renewed") {
        entered[2]!.resolve(); await renewalFinish.promise; events.push("renewal-settled");
      }
      return append.apply(this, args);
    });
    own(state.runFleetLicenseReResolveTick().catch(() => undefined));
    own(state.tickFederationGuardianBreakGlass());
    state.buildV1FederationDeps().renewLocalNodeCertificate();
    await Promise.all(entered.map((value) => value.promise));
    const flights = new Map(state._federationWork?.flights);
    const probe = observeDrain(channel); let completed = false;
    const stopped = own(channel.stop().then(() => { completed = true; }));
    const winner = await drainWinner(probe.entered, stopped, released.promise);
    for (const job of ["fleet", "guardian", "renewal"] as const) probe.assert(job, flights.get(job), winner);
    fleetFinish.resolve(); await flights.get("fleet");
    expect(completed).toBe(false); expect(releases[0]).not.toHaveBeenCalled();
    await state.runFleetLicenseReResolveTick(); expect(fleet).toHaveBeenCalledOnce();
    guardianFinish.resolve(); await flights.get("guardian");
    expect(completed).toBe(false); await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    renewalFinish.resolve(); await stopped;
    for (const job of ["fleet", "guardian", "renewal"]) {
      expect(events).toContain(`${job}-settled`);
      expect(events.indexOf(`${job}-settled`)).toBeLessThan(events.indexOf("released"));
    }
  });

  it("a captured guardian callback remains sealed after stop", async () => {
    const channel = await boot(); const state = internal(channel);
    state._federationGuardianBreakGlass = { ...countdown(), completesAt: "2100-01-01T00:00:00.000Z" };
    state.armFederationGuardianBreakGlassPoll(); await state.tickFederationGuardianBreakGlass();
    const callback = intervals.get(state._federationBreakGlassPoll!)!;
    expect(callback).toBeTypeOf("function");
    const run = vi.spyOn(state, "tickFederationGuardianBreakGlassInner").mockResolvedValue(undefined);
    await channel.stop(); callback(); await state.tickFederationGuardianBreakGlass();
    expect(run, "no guardian tick is admitted after stop").not.toHaveBeenCalled();
  });

  it("route renewal remains sealed while its context is still bound", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.renewLocalFederationNodeCertificate();
    const context = state._federationContext!; const deps = state.buildV1FederationDeps();
    const expires = new Date().toISOString(); context.localNodeCert!.expires_at = expires;
    channel.sealFederationWork();
    expect(state._federationContext).toBe(context);
    vi.mocked(AuditLog.prototype.append).mockResolvedValue(undefined);
    deps.renewLocalNodeCertificate();
    expect(context.localNodeCert!.expires_at).toBe(expires);
  });

  it("latched guardian and non-due renewal settle without corresponding writes", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.renewLocalFederationNodeCertificate();
    const persist = vi.spyOn(FederationSyncStateStore.prototype, "persist");
    state._federationGuardianBreakGlass = countdown(); state._federationSyncStateUnavailable = true;
    await state.tickFederationGuardianBreakGlass();
    expect(persist).not.toHaveBeenCalled();
    const context = state._federationContext!; const cert = context.localNodeCert;
    await state.renewLocalFederationNodeCertificate(); expect(context.localNodeCert).toBe(cert);
    await channel.stop(); expect(state._federationSyncStateStore === null).toBe(true);
  });

  it("a cloud session exposes no raw signing key and detaches after failed unlock", async () => {
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE, storagePathHint: fortress.storagePath });
    const { record } = (await realLoad({ storage: storage(), masterKey: seed.masterKey }))!;
    const unseal = randomBytes(record.master_secret.length);
    const certificate = issueNodeIdentityCertificate({ node_id: record.node_id,
      node_pubkey: fromBase64url(record.local_node_cert.node_pubkey), node_mode: "operator_cloud",
      fortress_id: record.fortress_id, capabilities: record.local_node_cert.capabilities,
      parent_chain: { fortress_master_pubkey: record.pinned_master_pubkey.public_key,
        principal_id: record.issuing_principal_cert.principal_id, principal_pubkey: record.issuing_principal_cert.principal_pubkey },
      principal_private_key: record.issuing_principal_private_key, master_private_key: record.master_private_key });
    await persistOperatorCloudJoinedNode({ storage: storage(), masterKey: seed.masterKey, record: {
      record_version: OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION, fortress_id: record.fortress_id,
      node_id: record.node_id, node_mode: "operator_cloud", pinned_master_pubkey: record.pinned_master_pubkey,
      issuing_principal_cert: record.issuing_principal_cert, local_node_cert: certificate,
      wrapped_local_node_private_key: wrapNodePrivateKeyForCloud({ nodePrivateKey: record.local_node_private_key, cloudNodeUnsealKey: unseal }),
      scope_manifest: { scope_version: OPERATOR_CLOUD_SCOPE_VERSION, node_id: record.node_id,
        agent_ids: ["cloud-agent"], namespaces: ["cloud-state"], state_grant_ids: [] },
      trust_boundary: { version: NODE_TRUST_BOUNDARY_VERSION, posture: "provider_in_trust_boundary_not_tee",
        label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL, provider_in_trust_boundary: true, tee_attested: false },
      disclosure_acknowledged_at: new Date().toISOString(),
    } });
    await storage().delete("_federation", "trust-root-v1");
    for (const key of [record.master_secret, record.master_private_key!, record.issuing_principal_private_key,
      record.local_node_private_key, unseal]) key.fill(0);
    await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
    sessions = []; releases = []; events = []; released = deferred();
    let context: FederationContext | null = null;
    const channel = await boot({ allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      context = internal(channels[0]!)._federationContext;
      throw new Error("fixture cloud stop");
    } });
    expect(await internal(channel).unlockHandler({ passphrase: TEST_PASSPHRASE })).toBe(false);
    expect(context).toMatchObject({ nodeMode: "operator_cloud" });
    for (const accessor of ["getMasterPrivateKey", "getFortressMasterSecret", "getIssuingPrincipalPrivateKey", "getLocalNodePrivateKey"]) {
      expect((context as unknown as Record<string, unknown>)[accessor]).toBeUndefined();
    }
    expect(releases[0]).toHaveBeenCalledOnce(); expect(channel.isFederationProvisioned()).toBe(false);
  });

  it("replacement waits for the previous generation and keeps captured callbacks inert", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick();
    const callback = intervals.get(state._fleetReResolveTimer!)!;
    const entered = deferred(); const finish = gate();
    const run = vi.spyOn(state, "runFleetLicenseReResolveTickOnce").mockImplementation(async () => {
      entered.resolve(); await finish.promise;
    });
    own(state.runFleetLicenseReResolveTick()); await entered.promise;
    state._federationEnabled = true;
    const context = state._federationContext!; const oldOwner = state._federationWork;
    const flight = oldOwner?.flights.get("fleet"); const probe = observeDrain(channel);
    let completed = false;
    const replacement = own(Promise.resolve(channel.setFederationContext({ ...context })).then(() => { completed = true; }));
    const winner = await drainWinner(probe.entered, replacement); probe.assert("fleet", flight, winner);
    expect(completed).toBe(false); expect(state._federationContext).toBe(context);
    await state.buildV1FederationDeps().setEnabled(false);
    const enabledGeneration = state._federationEnabledGeneration;
    finish.resolve(); await replacement;
    expect(state._federationWork).not.toBe(oldOwner);
    expect(state._federationEnabled, "the operator toggle during drain survives replacement").toBe(false);
    expect(state._federationEnabledGeneration).toBe(enabledGeneration);
    await state.runFleetLicenseReResolveTick(); run.mockClear(); callback();
    expect(run).not.toHaveBeenCalled();
  });

  it.each(["spent", "new"] as const)("a %s unprotect authorization keeps durable history through HTTP close", async (kind) => {
    const channel = await boot(); const state = internal(channel);
    const privateKey = ed25519.utils.randomPrivateKey();
    const master = sessions[0]!.masterKey.slice();
    try {
      const token = await openSession(channel, privateKey);
      const path = "/v1/agents/unprotect"; const url = `${baseUrl(channel)}${path}`;
      const payload = addOperatorAuthorizationFields({ agent_id: "session-agent", idempotency_key: kind, node_id: "other-node" });
      const body = { ...payload, operator_signature: toBase64url(signOperatorPayload(path, payload, privateKey)) };
      const consume = vi.spyOn(state, "consumeV1OperatorAuthorization");
      if (kind === "spent") expect((await post(url, body, token)).status).toBe(HTTP_BAD_REQUEST);
      const heldBody = holdBody(path);
      const request = own(post(url, body, token)); await heldBody.entered;
      const { stopped } = await stopDuringBody(channel);
      heldBody.finish.resolve(); const response = await request; await stopped;
      expect(response.status, "an admitted request retains durable replay history during HTTP close")
        .toBe(kind === "spent" ? HTTP_FORBIDDEN : HTTP_BAD_REQUEST);
      const params = consume.mock.calls.at(-1)![0];
      const reopened = OperatorAuthorizationSpentStore.durableFromBoot(storage(), master);
      expect(await reopened.consume(params), "the consumption survives session finalization on disk").toBe("replayed");
    } finally { master.fill(0); privateKey.fill(0); }
  });

  it("an admitted peer sync persists its outbound high water through HTTP close", async () => {
    const channel = await boot(); const state = internal(channel);
    await state.buildV1FederationDeps().setEnabled(true);
    const ctx = state._federationContext!;
    const master = sessions[0]!.masterKey.slice(); const key = ctx.getLocalNodePrivateKey!()!;
    try {
      const body = signSyncEnvelope({ fortressId: ctx.fortressId, senderNodeId: ctx.nodeId,
        recipientNodeId: ctx.nodeId, syncHighWater: FIRST_SERIAL, events: [], senderNodeCert: ctx.localNodeCert!,
        issuingPrincipalCert: ctx.issuingPrincipalCert, nodePrivateKey: key });
      const path = "/v1/federation/sync/peer"; const heldBody = holdBody(path);
      const request = own(post(`${baseUrl(channel)}${path}`, body)); await heldBody.entered;
      const { stopped } = await stopDuringBody(channel);
      heldBody.finish.resolve(); const response = await request; await stopped;
      expect(response.status).toBe(HTTP_OK);
      const snapshot = await new FederationSyncStateStore({ storage: storage(), masterKey: master }).load();
      expect(snapshot.outboundHighWater, "the reciprocal reservation is durable").toBe(FIRST_SERIAL);
    } finally { master.fill(0); key.fill(0); }
  });

  it.each(["idle", "draining"] as const)("a %s replacement retains durable stores and revocation membership", async (mode) => {
    const channel = await boot(); const state = internal(channel);
    await state.runFleetLicenseReResolveTick(); await state.renewLocalFederationNodeCertificate();
    const params = authorization(); await state.consumeV1OperatorAuthorization(params);
    const stores = [state._operatorAuthorizationSpentStore, state._federationReissueChallengeStore, state._federationSyncStateStore];
    state._federationState.revoked.add("revoked-node"); state._federationState.evictionMaxSerial = FIRST_SERIAL;
    state._federationRevokedRoots.add("revoked-root"); state._federationHighestRevocationSerial = FIRST_SERIAL;
    const entered = deferred(); const finish = gate();
    if (mode === "draining") {
      vi.spyOn(state, "runFleetLicenseReResolveTickOnce").mockImplementation(async () => { entered.resolve(); await finish.promise; });
      own(state.runFleetLicenseReResolveTick()); await entered.promise;
    }
    const replacement = own(channel.setFederationContext({ ...state._federationContext! }));
    finish.resolve(); await replacement;
    expect(await state.consumeV1OperatorAuthorization(params), "replacement retains the durable replay refusal").toBe("replayed");
    expect(state._operatorAuthorizationSpentStore).toBe(stores[0]);
    expect(state._federationReissueChallengeStore).toBe(stores[1]);
    expect(state._federationSyncStateStore).toBe(stores[2]);
    expect(state._federationState.revoked.has("revoked-node")).toBe(true);
    expect(state._federationState.evictionMaxSerial).toBe(FIRST_SERIAL);
    expect(state._federationRevokedRoots.has("revoked-root")).toBe(true);
    expect(state._federationHighestRevocationSerial).toBe(FIRST_SERIAL);
  });

  it("replacement retains unavailable store latches", async () => {
    const channel = await boot(); const state = internal(channel);
    state._operatorAuthorizationSpentStoreUnavailable = true;
    state._federationReissueChallengeStoreUnavailable = true; state._federationSyncStateUnavailable = true;
    await channel.setFederationContext({ ...state._federationContext! });
    expect(state._operatorAuthorizationSpentStoreUnavailable).toBe(true);
    expect(state._federationReissueChallengeStoreUnavailable).toBe(true);
    expect(state._federationSyncStateUnavailable).toBe(true);
  });

  it.each(["authorization", "challenge", "sync"] as const)("late %s calls are refused after finalization", async (kind) => {
    const channel = await boot(); const state = internal(channel); const deps = state.buildV1FederationDeps();
    await channel.stop();
    const call = kind === "authorization" ? state.consumeV1OperatorAuthorization(authorization())
      : kind === "challenge" ? deps.issueReissueChallenge({ fortressId: "session-fortress", nodeId: "session-node" })
        : deps.nextOutboundHighWater();
    await expect(call, "finalization latches detached stores unavailable").rejects.toThrow("unavailable");
    expect(state._operatorAuthorizationSpentStore).toBeNull(); expect(state._federationReissueChallengeStore).toBeNull();
    expect(state._federationSyncStateStore).toBeNull();
    await expect(state.persistFederationSyncState()).rejects.toThrow("federation_sync_state_unavailable");
  });

  it("a throwing record scrub still scrubs the master and releases custody", async () => {
    const channel = await boot(); const failure = new Error("fixture record scrub failure");
    vi.mocked(zeroRecordSecrets).mockImplementationOnce(() => { throw failure; });
    try {
      await expect(channel.stop()).rejects.toBe(failure);
      expect(sessions[0]!.masterKey.every((byte) => byte === 0), "master scrub runs after record scrub failure").toBe(true);
      expect(releases[0], "custody release runs after record scrub failure").toHaveBeenCalledOnce();
      await expect(exclusive()).resolves.toBe("entered");
    } finally { realScrub(records[0]!.record); }
  });

  it.each(["load", "persist"] as const)("a late sync store %s completion preserves the unavailable latch", async (boundary) => {
    const channel = await boot(); const state = internal(channel); const store = state._federationSyncStateStore!;
    const entered = deferred(); const finish = gate();
    let operation: Promise<void>;
    if (boundary === "load") {
      const load = store.load.bind(store);
      vi.spyOn(store, "load").mockImplementation(async () => {
        const snapshot = await load(); entered.resolve(); await finish.promise; return snapshot;
      });
      operation = own(channel.setFederationSyncStateStore(store));
    } else {
      const persist = store.persist.bind(store);
      vi.spyOn(store, "persist").mockImplementation(async (snapshot) => {
        await persist(snapshot); entered.resolve(); await finish.promise;
      });
      operation = own(state.persistFederationSyncState());
    }
    await entered.promise; await channel.stop(); finish.resolve(); await operation;
    expect(state._federationSyncStateStore).toBeNull();
    expect(state._federationSyncStateUnavailable, "late completion cannot reopen a detached store").toBe(true);
    await expect(state.buildV1FederationDeps().nextOutboundHighWater()).rejects.toThrow("federation_sync_state_unavailable");
  });

});
