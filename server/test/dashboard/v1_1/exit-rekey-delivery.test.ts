/** The approving dashboard alone receives an export key; reusable views remain metadata only. IC-07. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { createL1Tools } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { buildV11Bindings } from "../../../src/dashboard/v1_1/wiring.js";
import { dispatchV11Request } from "../../../src/dashboard/v1_1/dispatch.js";
import { importExitBundle } from "../../../src/exit/bundle.js";
import * as bundleModule from "../../../src/exit/bundle.js";
import * as randomModule from "../../../src/core/random.js";
import { SanctuaryContextReader } from "../../../src/concierge/sanctuary-context-reader.js";
import { redactAuditEntryForAgent } from "../../../src/operational/agent-audit-redaction.js";
import { formatAsCEF, formatAsOCSF, formatAsECS, formatAsXDM } from "../../../src/audit/siem-formatter.js";
import { DashboardApprovalChannel } from "../../../src/principal-policy/dashboard.js";
import { handleRequest } from "../../../src/dashboard/api.js";
import { createDashboardReadFlightMap } from "../../../src/dashboard/read-response.js";
import { handlePostureRoute } from "../../../src/principal-policy/posture-routes.js";
import type { HubApprovalPendingItem } from "../../../src/contracts/v1.1/hub-events.js";
import { HubInboxStore } from "../../../src/hub/inbox-store.js";

const TOKEN = "synthetic-operator";
const KEY_BYTES = Buffer.from("synthetic-export-key-for-tests!!"); // 32 synthetic bytes, never an operator key.
const KEY = KEY_BYTES.toString("base64url");
const DRAWS_PER_EXPORT = 2; // One bundle key plus one random custody wrap identifier.
const FORMS = ["/api/hub/fortress/exit-bundle/export", "/api/hub/agents/all/exit-bundle/export"];
const temporary: string[] = [];
const logs: AuditLog[] = [];
const releases: Array<() => void> = [];
const pending: Promise<unknown>[] = [];
beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-27T12:00:00Z")); });
afterEach(async () => {
  for (const release of releases.splice(0)) release();
  await Promise.allSettled(pending.splice(0));
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const log of logs.splice(0)) await log.flush().catch(() => {});
  for (const path of temporary.splice(0)) await rm(path, { recursive: true, force: true });
});
function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  releases.push(() => resolve(undefined as T));
  return { promise, resolve, reject };
}
class Reply extends EventEmitter {
  statusCode = 0;
  headersSent = false;
  destroyed = false;
  headers: Record<string, string> = {};
  chunks: string[] = [];
  writeHead(code: number, headers: Record<string, string>) { this.statusCode = code; this.headers = headers; this.headersSent = true; return this; }
  write(chunk: string) { this.chunks.push(String(chunk)); return true; }
  end(chunk = "") { this.write(chunk); return this; }
  destroy() { this.destroyed = true; this.emit("close"); return this; }
  json() { return JSON.parse(this.chunks.join("")); }
}
function request(path: string, method = "POST", token: string | undefined = TOKEN) {
  return Object.assign(new EventEmitter(), { url: path, method, headers: { host: "localhost", ...(token ? { authorization: `Bearer ${token}` } : {}) }, socket: { remoteAddress: "127.0.0.1" } }) as IncomingMessage;
}
async function fortress(nonempty = true) {
  const storagePath = await mkdtemp(join(tmpdir(), "export-delivery-"));
  temporary.push(storagePath);
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const masterKey = new Uint8Array(32).fill(19 + temporary.length); // AES-256 fixture master.
  const auditLog = new AuditLog(storage, masterKey);
  logs.push(auditLog);
  const stateStore = new StateStore(storage, masterKey);
  const { tools, identityManager } = createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog);
  await identityManager.load();
  const identity = JSON.parse((await tools.find(t => t.name === "identity_create")!.handler({ label: "fixture" })).content[0]!.text);
  if (nonempty) await tools.find(t => t.name === "state_write")!.handler({ namespace: "memory", key: "handoff", value: "portable memory", identity_id: identity.identity_id });
  const inputs = { identityId: identity.identity_id, fortressId: "fixture-fortress", storagePath, storage, masterKey, auditLog, identityManager, policy: DEFAULT_POLICY };
  const bindings = buildV11Bindings(inputs);
  const dispatch = (path: string, res = new Reply(), method = "POST", token: string | undefined = TOKEN, configured: string | undefined = TOKEN) => {
    const done = dispatchV11Request({ bindings, authToken: configured, loopbackAutoAuth: true }, request(path, method, token), res as unknown as ServerResponse, new URL(path, "http://localhost"), method);
    pending.push(done);
    return { res, done };
  };
  const call = async (path: string, method = "POST", token: string | undefined = TOKEN, configured: string | undefined = TOKEN) => {
    const run = dispatch(path, new Reply(), method, token, configured); await run.done; return run.res;
  };
  const enqueue = async (form = FORMS[0]!) => {
    const res = await call(form);
    expect(res.statusCode).toBe(202);
    secretFree(res.chunks);
    return res.json().data.inbox_item_id as string;
  };
  return { ...inputs, bindings, stateStore, dispatch, call, enqueue };
}
function syntheticMint() { return vi.spyOn(randomModule, "generateRandomKey").mockImplementation(() => new Uint8Array(KEY_BYTES)); }
function secretFree(value: unknown) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of ["state_rekey_key", KEY, KEY_BYTES.toString("hex"), KEY_BYTES.toString("base64"), Buffer.from(KEY).toString("base64"), encodeURIComponent(KEY)]) expect(text).not.toContain(secret);
}
async function expectImmediateConflict(f: Awaited<ReturnType<typeof fortress>>, path: string) {
  const run = f.dispatch(path);
  // Flush only promise jobs: a losing decision must settle while the winning work remains gated.
  for (let turn = 0; turn < 20; turn++) await Promise.resolve();
  expect(run.res.statusCode).toBe(409);
  await run.done;
}
async function approved(f: Awaited<ReturnType<typeof fortress>>, form = FORMS[0]!) {
  const id = await f.enqueue(form);
  const response = await f.call(`/api/hub/inbox/${id}/approve`);
  expect(response.statusCode).toBe(200);
  expect(response.headers["Cache-Control"]).toBe("no-store");
  const body = response.json();
  expect(body.data.one_time_export.state_rekey_key).toBe(KEY);
  return { id, body, item: body.data.item, delivery: body.data.one_time_export };
}
async function allFiles(path: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) result.push(...await allFiles(child)); else result.push(await readFile(child, "utf8"));
  }
  return result;
}
async function publisherFrames(item: unknown) {
  const frames: string[] = [];
  const channel = new DashboardApprovalChannel({ port: 0, host: "127.0.0.1", timeout_seconds: 30, auto_open: false });
  const internal = channel as any;
  // Two credentialed subscribers per publisher; invoke the actual serializers without opening sockets.
  for (let n = 0; n < 2; n++) internal.sseClients.set({ write: (frame: string) => frames.push(frame) }, "operator_bearer");
  channel.broadcastSSE("inbox", item);
  const listeners: Array<(event: any) => void> = [];
  const replies: Reply[] = [];
  try {
    for (let n = 0; n < 2; n++) {
      const res = new Reply(); replies.push(res);
      await handleRequest({ sources: {}, authToken: TOKEN, readFlightMap: createDashboardReadFlightMap(), onEvent: (listener: (event: any) => void) => { listeners.push(listener); return () => {}; } } as any, request("/api/stream", "GET"), res as unknown as ServerResponse);
    }
    for (const listener of listeners) listener({ type: "inbox", data: item });
    for (const res of replies) frames.push(...res.chunks);
  } finally { for (const res of replies) res.destroy(); }
  expect(frames.filter(frame => frame.includes("event: inbox"))).toHaveLength(4);
  return frames;
}

describe("response-only export delivery", () => {
  it("wired-approved-dashboard-export-delivers-key-on-original-response", async () => {
    const f = await fortress();
    const mint = syntheticMint();
    for (const form of FORMS) {
      const { delivery } = await approved(f, form);
      const state = JSON.parse(await readFile(join(delivery.bundle_dir, "artifacts/encrypted_state.json"), "utf8"));
      expect(state.source_custody.format).toBe("SANCTUARY_EXIT_SOURCE_CUSTODY_V1");
      const destination = await fortress(false);
      const imported = await importExitBundle({ bundleDir: delivery.bundle_dir, storage: destination.storage, masterKey: destination.masterKey, identityManager: destination.identityManager, auditLog: destination.auditLog, activate: true, forceRebind: true, sourceRecoveryKey: delivery.state_rekey_key, destinationSignerIdentityId: destination.identityId });
      expect(imported.state.status).toBe("rekeyed");
      expect(imported.state.imported_keys).toBe(1);
      expect((await destination.stateStore.read("memory", "handoff"))?.value).toBe("portable memory");
    }
    expect(mint).toHaveBeenCalledTimes(FORMS.length * DRAWS_PER_EXPORT);
  });

  it("persisted-item-audit-and-sse-never-contain-rekey-key", async () => {
    const f = await fortress(); syntheticMint();
    const original = bundleModule.exportExitBundle;
    vi.spyOn(bundleModule, "exportExitBundle").mockImplementation(async options => ({
      ...await original(options), warnings: [KEY, KEY_BYTES.toString("hex")], message: KEY, alternate: KEY,
    }));
    const { item, delivery } = await approved(f);
    secretFree(item);
    const store = new HubInboxStore();
    store.enqueueTier1({ ...item, resolved: false, resolution_payload: { state_rekey_key: KEY }, message: KEY }, async () => ({
      resolution_payload: { ...item.resolution_payload, warnings: [KEY], message: KEY, state_rekey_key: KEY },
    }));
    secretFree(store.get(item.item_id));
    await store.resolve(item.item_id, "approve", item.created_at, { isLive: () => true, receive: () => {} });
    store.upsertFromSource({ ...item, resolution_payload: { state_rekey_key: KEY }, message: KEY });
    secretFree(store.get(item.item_id));
    secretFree(f.bindings.hubService.listInbox());
    secretFree((await f.call("/api/hub/inbox", "GET")).json());
    // Re-open the encrypted durable audit with the fixture master; ciphertext scanning is not the witness.
    const reopened = new AuditLog(f.storage, f.masterKey); logs.push(reopened);
    const audit = await reopened.query({ limit: 100 });
    expect(audit.entries.some(e => e.operation === "exit_bundle_exported")).toBe(true);
    secretFree(audit);
    secretFree(await allFiles(delivery.bundle_dir));
    secretFree(await publisherFrames(item));
    expect(new HubInboxStore().size()).toBe(0);
    expect(buildV11Bindings(f).hubService.listInbox()).toEqual([]);
  });

  it("safe-item-remains-safe-through-both-sse-publishers", async () => {
    const f = await fortress(); syntheticMint();
    const publication = vi.spyOn(DashboardApprovalChannel.prototype, "broadcastSSE");
    const { item } = await approved(f);
    expect(publication).not.toHaveBeenCalled();
    const frames = await publisherFrames(item);
    secretFree(frames);
    expect(frames.join("")).toContain(item.resolution_payload.manifest_hash);
  });

  it("all-readers-remain-secret-free-after-export", async () => {
    const f = await fortress(); syntheticMint(); await approved(f);
    const raw = await f.auditLog.query({ limit: 100 });
    secretFree(raw);
    const evidenceReply = new Reply();
    await handlePostureRoute({ auditLog: f.auditLog, originMachine: "fixture", listAgents: () => [], readFlightMap: createDashboardReadFlightMap() }, request("/api/posture/evidence", "GET"), evidenceReply as unknown as ServerResponse, new URL("http://localhost/api/posture/evidence"), "GET");
    expect(evidenceReply.statusCode).toBe(200); secretFree(evidenceReply.json());
    const rawChannel = new DashboardApprovalChannel({ port: 0, host: "127.0.0.1", timeout_seconds: 30, auto_open: false });
    (rawChannel as any).auditLog = f.auditLog;
    const rawReply = new Reply(); const rawDone = deferred();
    rawReply.end = (chunk = "") => { rawReply.write(chunk); rawDone.resolve(); return rawReply; };
    (rawChannel as any).handleAuditLog(new URL("http://localhost/api/audit-log"), rawReply);
    await rawDone.promise; secretFree(rawReply.json());
    secretFree((await f.call("/api/hub/activity", "GET")).json());
    secretFree((await f.call("/api/hub/inbox", "GET")).json());
    const reader = new SanctuaryContextReader({ ...f, inboxSources: { listPendingApprovals: () => f.bindings.hubService.listInbox(), listRecentBlockedEgress: () => [], listRecentPrivacyEvents: () => [], listActiveBudgetWarnings: () => [], listActiveRecoveryPrompts: () => [], listRecentAgentErrors: () => [] } } as any);
    secretFree(await reader.readContext({ question: "show audit log" }));
    for (const entry of raw.entries) {
      const view = redactAuditEntryForAgent(entry);
      secretFree([view, formatAsCEF(view), formatAsOCSF(view), formatAsECS(view), formatAsXDM(view)]);
    }
    const later = await approved(f);
    const receipts = await readFile(join(later.delivery.bundle_dir, "artifacts/audit_receipts.json"), "utf8");
    expect(receipts).toContain("exit_bundle_exported"); secretFree(receipts);
  });

  it("missing-delivery-receiver-fails-before-export", async () => {
    const f = await fortress(); const mint = syntheticMint();
    const exporter = vi.spyOn(bundleModule, "exportExitBundle");
    const id = await f.enqueue();
    const before = await allFiles(f.storagePath);
    await expect(f.bindings.hubService.resolveInboxItem(id, "approve")).rejects.toThrow();
    expect(exporter).not.toHaveBeenCalled(); expect(mint).not.toHaveBeenCalled();
    expect(await allFiles(f.storagePath)).toEqual(before);
    await f.bindings.hubService.resolveInboxItem(id, "deny");
    expect(mint).not.toHaveBeenCalled();
  });

  it("auth-and-dismiss-fail-before-export", async () => {
    const f = await fortress(); const mint = syntheticMint();
    const id = await f.enqueue();
    for (const [token, config] of [["", TOKEN], ["wrong", TOKEN], [TOKEN, ""]]) {
      const reply = await f.call(`/api/hub/inbox/${id}/approve`, "POST", token, config);
      expect(reply.statusCode).toBe(401);
    }
    expect((await f.call(`/api/hub/inbox/${id}/dismiss`)).statusCode).toBe(409);
    expect((await f.call(`/api/hub/inbox/${id}/invalid`)).statusCode).toBe(400);
    expect(mint).not.toHaveBeenCalled();
    const response = await f.call(`/api/hub/inbox/${id}/approve`);
    expect(response.json().data.one_time_export.state_rekey_key).toBe(KEY);
  });

  it("concurrent-approval-and-denial-have-one-execution-owner", async () => {
    const f = await fortress(); const mint = syntheticMint();
    const original = bundleModule.exportExitBundle;
    for (const loser of ["approve", "deny"]) {
      const entered = deferred(); const release = deferred(); const auditEntered = deferred(); const auditRelease = deferred();
      const exportSpy = vi.spyOn(bundleModule, "exportExitBundle").mockImplementation(async options => { entered.resolve(); await release.promise; return original(options); });
      const append = f.auditLog.appendCritical.bind(f.auditLog);
      const auditSpy = vi.spyOn(f.auditLog, "appendCritical").mockImplementation(async entry => { if (entry.operation === "exit_bundle_exported") { auditEntered.resolve(); await auditRelease.promise; } return append(entry); });
      const id = await f.enqueue();
      const winner = f.dispatch(`/api/hub/inbox/${id}/approve`); await entered.promise;
      await expectImmediateConflict(f, `/api/hub/inbox/${id}/${loser}`);
      expect(winner.res.chunks).toEqual([]);
      release.resolve(); await auditEntered.promise;
      await expectImmediateConflict(f, `/api/hub/inbox/${id}/${loser}`);
      expect(winner.res.chunks).toEqual([]);
      auditRelease.resolve(); await winner.done;
      expect(winner.res.json().data.one_time_export.state_rekey_key).toBe(KEY);
      expect(exportSpy).toHaveBeenCalledTimes(1);
      exportSpy.mockRestore(); auditSpy.mockRestore();
    }
    expect(mint).toHaveBeenCalledTimes(2 * DRAWS_PER_EXPORT);
  });

  it("completed-and-failed-approval-replays-never-remint", async () => {
    const f = await fortress(); const mint = syntheticMint();
    const first = await approved(f);
    expect((await f.call(`/api/hub/inbox/${first.id}/approve`)).statusCode).toBe(409);
    const append = f.auditLog.appendCritical.bind(f.auditLog);
    const fail = vi.spyOn(f.auditLog, "appendCritical").mockImplementation(entry => entry.operation === "exit_bundle_exported" ? Promise.reject(new Error(KEY)) : append(entry));
    const id = await f.enqueue();
    expect((await f.call(`/api/hub/inbox/${id}/approve`)).statusCode).toBe(500);
    expect((await f.call(`/api/hub/inbox/${id}/approve`)).statusCode).toBe(409);
    expect((f.bindings.hubService.listInbox().find(i => i.item_id === id && i.kind === "approval_pending") as any)?.resolution_payload).toEqual({ outcome: "failed" });
    expect(mint).toHaveBeenCalledTimes(2 * DRAWS_PER_EXPORT);
    fail.mockRestore(); await approved(f); expect(mint).toHaveBeenCalledTimes(3 * DRAWS_PER_EXPORT);
  });

  it("disconnect-and-late-completion-never-rehome-key", async () => {
    const f = await fortress(); const mint = syntheticMint();
    const diagnostics = [vi.spyOn(console, "error"), vi.spyOn(console, "warn"), vi.spyOn(console, "log")];
    for (const diagnostic of diagnostics) diagnostic.mockImplementation(() => {});
    const original = bundleModule.exportExitBundle;
    // Repeated waves drive both sides of mint and keep admission closed until the delayed work settles.
    for (const phase of ["before", "after", "before", "after"]) {
      const entered = deferred(); const release = deferred();
      const spy = vi.spyOn(bundleModule, "exportExitBundle").mockImplementation(async options => {
        if (phase === "before") { entered.resolve(); await release.promise; }
        return original(options);
      });
      const append = f.auditLog.appendCritical.bind(f.auditLog);
      const auditSpy = vi.spyOn(f.auditLog, "appendCritical").mockImplementation(async entry => {
        if (phase === "after" && entry.operation === "exit_bundle_exported") { entered.resolve(); await release.promise; }
        return append(entry);
      });
      const id = await f.enqueue(); const run = f.dispatch(`/api/hub/inbox/${id}/approve`);
      await entered.promise; run.res.destroy();
      await expectImmediateConflict(f, `/api/hub/inbox/${id}/approve`);
      await expectImmediateConflict(f, `/api/hub/inbox/${id}/deny`);
      await expectImmediateConflict(f, FORMS[0]!);
      release.resolve(); await run.done;
      expect(run.res.chunks).toEqual([]);
      expect((await f.call(`/api/hub/inbox/${id}/approve`)).statusCode).toBe(409);
      secretFree(f.bindings.hubService.listInbox());
      secretFree(await f.auditLog.query({ limit: 100 }));
      secretFree(diagnostics.map(diagnostic => diagnostic.mock.calls));
      secretFree((await f.call("/api/hub/inbox", "GET")).json());
      secretFree(await publisherFrames(f.bindings.hubService.listInbox().find(i => i.item_id === id)));
      spy.mockRestore(); auditSpy.mockRestore();
    }
    expect(mint).toHaveBeenCalledTimes(4 * DRAWS_PER_EXPORT);
  });

  it("post-mint-errors-never-log-secret", async () => {
    const f = await fortress(); syntheticMint();
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    const original = bundleModule.exportExitBundle;
    for (const phase of ["export", "sink", "audit", "store", "serializer"]) {
      const secretError = new Error(KEY, { cause: KEY }); secretError.stack = KEY;
      const restore: Array<() => void> = [];
      if (phase === "export") { const spy = vi.spyOn(bundleModule, "exportExitBundle").mockImplementation(async opts => { await original(opts); throw secretError; }); restore.push(() => spy.mockRestore()); }
      if (phase === "sink") {
        const resolve = f.bindings.hubService.resolveInboxItem.bind(f.bindings.hubService);
        const spy = vi.spyOn(f.bindings.hubService, "resolveInboxItem").mockImplementation((id, action, receiver) => {
          if (receiver) receiver.receive = () => { throw secretError; };
          return resolve(id, action, receiver);
        });
        restore.push(() => spy.mockRestore());
      }
      if (phase === "audit") { const append = f.auditLog.appendCritical.bind(f.auditLog); const spy = vi.spyOn(f.auditLog, "appendCritical").mockImplementation(entry => entry.operation === "exit_bundle_exported" ? Promise.reject(secretError) : append(entry)); restore.push(() => spy.mockRestore()); }
      const id = await f.enqueue();
      if (phase === "store") { const resolve = HubInboxStore.prototype.resolve; const spy = vi.spyOn(HubInboxStore.prototype, "resolve").mockImplementation(async function (this: HubInboxStore, ...args) { await resolve.apply(this, args); throw secretError; }); restore.push(() => spy.mockRestore()); }
      const res = new Reply();
      if (phase === "serializer") vi.spyOn(res, "end").mockImplementation(() => { throw secretError; });
      const run = f.dispatch(`/api/hub/inbox/${id}/approve`, res); await run.done;
      secretFree(res.chunks); secretFree(diagnostic.mock.calls);
      secretFree(f.bindings.hubService.listInbox());
      for (const undo of restore) undo();
      expect((await f.call(`/api/hub/inbox/${id}/approve`)).statusCode).toBe(409);
    }
  });

  it("receiver-that-dies-during-the-export-still-mints-and-the-key-is-discarded", async () => {
    // Liveness is required at entry only; the mint does not re-read it, so a nonempty bundle always carries custody
    // and a receiver that died mid-export sees the key offered once and never stored anywhere else.
    const f = await fortress(); syntheticMint();
    // Three entry probes (the store, the service, then the wiring) see a live receiver; every later probe sees a dead one.
    const ENTRY_PROBES = 3; let probes = 0; const offered: string[] = [];
    const receiver = { isLive: () => probes++ < ENTRY_PROBES, receive: (d: { state_rekey_key: string }) => { offered.push(d.state_rekey_key); } };
    const enqueued = f.bindings.hubService.enqueueFortressExportBundle();
    const item = await f.bindings.hubService.resolveInboxItem(enqueued.inbox_item_id, "approve", receiver);
    expect(probes).toBeGreaterThanOrEqual(ENTRY_PROBES);
    expect(offered).toHaveLength(1);
    expect(offered[0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const payload = (item as HubApprovalPendingItem).resolution_payload!;
    expect(payload.state_entry_count).toBe(1);
    const state = JSON.parse(await readFile(join(payload.bundle_dir!, "artifacts/encrypted_state.json"), "utf8"));
    expect(state.source_custody.format).toBe("SANCTUARY_EXIT_SOURCE_CUSTODY_V1");
    secretFree(item); secretFree(f.bindings.hubService.listInbox());
  });

  it("empty-export-has-no-key-or-custody", async () => {
    const f = await fortress(false); const mint = syntheticMint();
    const id = await f.enqueue();
    // Empty exports still require the response-only receiver before work begins.
    await expect(f.bindings.hubService.resolveInboxItem(id, "approve")).rejects.toThrow();
    const res = await f.call(`/api/hub/inbox/${id}/approve`);
    const data = res.json().data;
    expect(data.one_time_export).toBeUndefined(); expect(data.item.resolution_payload.state_entry_count).toBe(0);
    const artifact = JSON.parse(await readFile(join(data.item.resolution_payload.bundle_dir, "artifacts/encrypted_state.json"), "utf8"));
    expect(artifact.source_custody).toBeUndefined(); expect(mint).not.toHaveBeenCalled();
  });
});
