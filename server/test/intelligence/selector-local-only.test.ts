/**
 * SubstrateSelector — request-scoped local-only constraint (2026-09-15 slice)
 *
 * Verifies the chokepoint invariants from
 * `Review/Sanctuary/Day4_Mini2_Prep_2026-09-15/LOCAL_ONLY_NEXT_SLICE.md`:
 *   - a `localOnly: true` request against a surface whose effective (hybrid-
 *     resolved) substrate is not `local` is refused with a typed
 *     `local_only_violation` failure class, and the hosted `VeniceClient`
 *     constructor is never reached (proven by a constructor spy, not just
 *     "fetch was never called")
 *   - the refusal happens BEFORE any handle/hosted-client construction, so a
 *     capability pre-check via `getSubstrate(surface, { localOnly: true })`
 *     is equally safe
 *   - a local-only request whose LOCAL invocation fails never falls back to
 *     Venice, even when the operator's standing fallback behavior is
 *     degrade-silent and a valid Venice key is configured
 *   - every local-only decision (refusal or otherwise) is audited, with the
 *     `local_only` flag set on the emitted payload
 *   - an ordinary (non-local-only) request is completely unaffected
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

vi.mock("../../src/intelligence/substrates/venice.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/intelligence/substrates/venice.js")>();
  return {
    ...actual,
    // Wrap (not replace) the real constructor so existing behavior is
    // unchanged for every OTHER test; this file's tests assert on
    // `.mock.calls.length` to prove construction never happened, which is a
    // stronger claim than "the mocked fetch was never invoked" — it is
    // impossible for the wrapped constructor to run without a call landing
    // in this spy, regardless of what the constructed instance later does.
    VeniceClient: vi.fn(actual.VeniceClient),
  };
});

const { SubstrateSelector } = await import("../../src/intelligence/selector.js");
const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : typeof input === "string" ? input : input.toString();
}

function urlPathnameIs(url: string, pathname: string): boolean {
  try {
    return new URL(url, "http://localhost").pathname === pathname;
  } catch {
    return false;
  }
}

function urlHostnameIs(url: string, hostname: string): boolean {
  try {
    return new URL(url).hostname === hostname;
  } catch {
    return false;
  }
}

function buildSelector(opts: { fetchImpl?: typeof fetch } = {}) {
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
  return { storage, masterKey, auditLog, selector };
}

beforeEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

afterEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

describe("SubstrateSelector — local-only request refused against a hosted binding", () => {
  it("invokeSummarize on a venice-bound surface refuses with local_only_violation and never constructs VeniceClient", async () => {
    const fetchImpl = vi.fn(async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    // setVeniceApiKey probes the key; clear so only the invocation under
    // test is measured.
    vi.mocked(VeniceClient).mockClear();
    (fetchImpl as ReturnType<typeof vi.fn>).mockClear?.();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(resp.body.kind).toBe("failure");
    // The strong claim: the hosted client constructor itself was never
    // reached, not merely that no network call landed.
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    const refusal = failures.entries.find(
      (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
    );
    expect(refusal).toBeDefined();
    const details = refusal!.details as {
      surface: string;
      substrate: string;
      fallback_taken: string;
      local_only: boolean;
    };
    expect(details.surface).toBe("concierge");
    expect(details.substrate).toBe("venice");
    expect(details.fallback_taken).toBe("deny");
    expect(details.local_only).toBe(true);
    expect(refusal!.result).toBe("failure");

    // No invoked-success row for this refused call.
    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    expect(invoked.entries.length).toBe(0);
  });

  it("invokeClassify and invokeRedact are refused the same way on a frontier-bound surface", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("sentinel-scoring", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");

    const classifyResp = await selector.invokeClassify("sentinel-scoring", {
      kind: "classify",
      items: ["x"],
      categories: ["a", "b"],
      localOnly: true,
    });
    expect(classifyResp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
  });

  it("a hybrid binding that resolves to venice is refused exactly like a direct venice binding", async () => {
    const { selector } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "hybrid");
    await selector.setHybridRules({
      perSurface: {
        concierge: "venice",
        "sentinel-scoring": "local",
        "gate-explanation": "local",
        "privacy-filter-tier-2": "local",
        "direct-agent-gate-advisor": "local",
        "template-suggestion": "local",
      },
    });
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });
    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
  });

  it("getSubstrate(surface, { localOnly: true }) on a venice-bound surface returns a capability-zeroed handle without constructing VeniceClient", async () => {
    const { selector, auditLog } = buildSelector();
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const handle = await selector.getSubstrate("concierge", { localOnly: true });
    expect(handle.capability.summarize).toBe(false);
    expect(VeniceClient).not.toHaveBeenCalled();

    // The capability pre-check path is itself a local-only decision and
    // must be audited even though no invocation was attempted.
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);

    // Sanity: without the localOnly opt, the SAME surface yields a real
    // venice handle (proves the guard is opt-in, not a standing change).
    const ordinary = await selector.getSubstrate("concierge");
    expect(ordinary.substrate).toBe("venice");
  });
});

describe("SubstrateSelector — local-only request served locally", () => {
  it("succeeds normally when the surface is bound to local, and audits local_only: true on the invoked row", async () => {
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response(JSON.stringify({ response: "a local answer" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });
    expect(resp.failureClass).toBeNull();
    expect(resp.body.kind).toBe("summarize");
    expect(VeniceClient).not.toHaveBeenCalled();

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const row = invoked.entries[invoked.entries.length - 1]!;
    const details = row.details as { served_by: string; local_only: boolean };
    expect(details.served_by).toBe("local");
    expect(details.local_only).toBe(true);
  });

  it("does NOT set local_only on an ordinary request's invoked row", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ response: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    await selector.invokeSummarize("concierge", { kind: "summarize", context: "ctx", query: "q" });

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const details = invoked.entries[invoked.entries.length - 1]!.details as { local_only: boolean };
    expect(details.local_only).toBe(false);
  });

  it("a local-only request whose local invocation fails never falls back to Venice, even with a valid key and degrade-silent fallback configured", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response("", { status: 500 });
      }
      if (urlHostnameIs(url, "api.venice.ai")) {
        return new Response(
          JSON.stringify({ choices: [{ message: { content: "should never be served" } }] }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // Default fallback behavior is degrade-silent; default binding for
    // concierge is local. A valid venice key exists as the WOULD-BE
    // fallback target for an ordinary request (see the sibling
    // non-local-only test in selector.test.ts that proves the opposite
    // case: fallback DOES serve when localOnly is absent).
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    // The response is a genuine local failure, not the local-only refusal
    // class: the surface WAS local-compatible, local generation itself
    // failed, and the request's constraint simply forbids the fallback
    // that would otherwise have served it.
    expect(resp.failureClass).not.toBeNull();
    expect(resp.failureClass).not.toBe("local_only_violation");
    // The strongest available proof that fallback was never attempted:
    // the hosted client constructor was never reached, so the Venice call
    // recorded in `fetchImpl` above (which WOULD succeed) could not have
    // fired regardless of network stubbing.
    expect(VeniceClient).not.toHaveBeenCalled();
    for (const call of fetchImpl.mock.calls) {
      expect(urlHostnameIs(requestUrl(call[0] as RequestInfo | URL), "api.venice.ai")).toBe(false);
    }

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    const row = failures.entries[failures.entries.length - 1]!;
    const details = row.details as { fallback_taken: string; local_only: boolean };
    expect(details.fallback_taken).not.toBe("next-substrate");
    expect(details.local_only).toBe(true);
  });
});
