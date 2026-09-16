/**
 * `sanctuary concierge ask --local-only` — wired-consumer test through the
 * REAL production object graph (2026-09-15 slice).
 *
 * Unlike the stubbed-selector CLI test in `test/cli/concierge.test.ts`
 * ("routes local mode through the selector-backed concierge service"),
 * which hands `ConciergeService` a literal object implementing
 * `ConciergeSelectorLike`, this file constructs the REAL
 * `SubstrateSelector` (the one production class every consumer routes
 * through) and the REAL `ConciergeService`, wired together exactly as
 * `createLocalService()` in `src/cli/concierge.ts` wires them for a genuine
 * fortress. Only the storage backend (a legitimate `StorageBackend`
 * implementation, `MemoryStorage`) and the sanctuary-state reader (whose
 * behavior is orthogonal to the local-only invariant under test) are
 * substituted. This is what proves the `--local-only` CLI flag actually
 * reaches `SubstrateSelector.invoke()`'s chokepoint, not merely that a
 * fake selector's method was called with the right argument.
 */
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/intelligence/substrates/venice.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/intelligence/substrates/venice.js")>();
  return { ...actual, VeniceClient: vi.fn(actual.VeniceClient) };
});

const { runConciergeCommand } = await import("../../src/cli/concierge.js");
const { ConciergeService } = await import("../../src/concierge/index.js");
const { SubstrateSelector } = await import("../../src/intelligence/selector.js");
const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
const { AuditLog } = await import("../../src/operational/audit-log.js");
const { MemoryStorage } = await import("../../src/storage/memory.js");
const { generateRandomKey } = await import("../../src/core/random.js");
const { INTEL_OPS } = await import("../../src/intelligence/audit-events.js");

type ConciergeContextBundle = Awaited<ReturnType<InstanceType<typeof ConciergeService>["ask"]>>["context"];

class CaptureStream extends Writable {
  value = "";
  override _write(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.value += chunk.toString();
    callback();
  }
}

const emptyContext: ConciergeContextBundle = {
  generated_at: new Date().toISOString(),
  read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
  audit_log: { total_matching: 0, entries: [], integrity_findings: [] },
  identity_registry: { identities: [] },
  approval_inbox: { pending_count: 1, items: [] },
  sovereignty_profile: { fortress_id: "local", tier_policy: "local", context_gating_state: "local", castle_wall: { dashboard_enabled: false } },
  task_state: {
    total: 0,
    status_counts: { pending: 0, in_progress: 0, blocked: 0, ready_for_review: 0, completed: 0, cancelled: 0 },
    tasks: [],
    recent_activity: [],
  },
  state_store: { include_payloads: false, namespaces: [] },
};

/** Builds the REAL production pairing: a real SubstrateSelector behind a real ConciergeService. */
async function buildRealLocalService(opts: { fetchImpl?: typeof fetch } = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "test-identity",
    fetchImpl: opts.fetchImpl,
  });
  await selector.load();
  const service = new ConciergeService({
    reader: { readContext: async () => emptyContext },
    selector,
  });
  return { service, selector, auditLog };
}

beforeEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

afterEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

describe("sanctuary concierge ask --local-only (real SubstrateSelector + real ConciergeService)", () => {
  it("refuses without constructing VeniceClient when concierge is bound to venice, and audits the refusal", async () => {
    const { service, selector, auditLog } = await buildRealLocalService();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runConciergeCommand({
      argv: ["ask", "what is pending?", "--no-stream", "--local-only"],
      out,
      err,
      localServiceFactory: async () => service,
    });

    // Real production path returns 1 on ConciergeUnavailableError (see
    // runConciergeCommand's catch block); the operator-facing message
    // names the local-only refusal specifically.
    expect(code).toBe(1);
    expect(err.value).toContain("local-only");
    expect(out.value).toBe("");
    // The claim under test: the hosted client constructor was never
    // reached by this CLI invocation, proven by a constructor spy rather
    // than only "no network request landed".
    expect(VeniceClient).not.toHaveBeenCalled();

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  it("without --local-only, the same venice-bound fortress WOULD construct VeniceClient (control)", async () => {
    const { service, selector } = await buildRealLocalService();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    await runConciergeCommand({
      argv: ["ask", "what is pending?", "--no-stream"],
      out: new CaptureStream(),
      err: new CaptureStream(),
      localServiceFactory: async () => service,
    });

    // Positive control (packet: "Positive control: unconstrained configured
    // fallback still behaves as before"): proves the mock and the fixture
    // are capable of exercising the constructor at all, so the refusal
    // test above is a real negative, not an artifact of an inert mock.
    expect(VeniceClient).toHaveBeenCalledOnce();
  });

  it("succeeds and answers when concierge is (the default) local, with --local-only set", async () => {
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : String(input);
      if (new URL(url, "http://localhost").pathname === "/api/generate") {
        return new Response(JSON.stringify({ response: "Local-only answered locally." }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const { service } = await buildRealLocalService({ fetchImpl });

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runConciergeCommand({
      argv: ["ask", "how many pending approvals?", "--no-stream", "--local-only"],
      out,
      err,
      localServiceFactory: async () => service,
    });

    expect(code).toBe(0);
    expect(out.value).toContain("Local-only answered locally.");
    expect(err.value).toBe("");
    expect(VeniceClient).not.toHaveBeenCalled();
  });
});
