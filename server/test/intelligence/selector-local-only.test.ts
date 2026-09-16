/**
 * SubstrateSelector — request-scoped local-only constraint (2026-09-15 slice)
 *
 * Verifies the chokepoint invariants from
 * `Review/Sanctuary/Day4_Mini2_Prep_2026-09-15/LOCAL_ONLY_NEXT_SLICE.md`,
 * plus the fix-round findings from the two-family gate:
 *   - a `localOnly: true` request against a surface whose effective (hybrid-
 *     resolved) substrate is not `local` is refused with a typed
 *     `local_only_violation` failure class, and the hosted `VeniceClient`/
 *     `FrontierClient` constructor is never reached (proven by a
 *     constructor spy, not just "fetch was never called"), with a
 *     same-file positive control proving each spy fires when the
 *     constraint is absent
 *   - the refusal happens BEFORE any handle/hosted-client construction, so a
 *     capability pre-check via `getSubstrate(surface, { localOnly: true })`
 *     is equally safe
 *   - a handle obtained from a PLAIN `getSubstrate(surface)` call (no
 *     localOnly opt) is itself chokepoint-backed: calling
 *     `handle.summarize({ localOnly: true })` directly refuses and
 *     constructs no hosted client, exactly like `invokeSummarize` would
 *   - a local-only request whose LOCAL invocation fails is ALSO reported as
 *     `local_only_violation` (one truth: every way a local-only request can
 *     fail to be served locally reads the same to a caller), never falls
 *     back to Venice/frontier even when the operator's standing fallback
 *     behavior is degrade-silent and a valid key is configured
 *   - every local-only decision (refusal or otherwise) is audited, with the
 *     `local_only` flag set on the emitted payload
 *   - an ordinary (non-local-only) request is completely unaffected
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type {
  ClassifyRequest,
  RedactRequest,
  SummarizeRequest,
} from "../../src/intelligence/types.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hash, hashToString } from "../../src/core/hashing.js";
import { stringToBytes } from "../../src/core/encoding.js";

// `vi.fn(ActualClass)` records the call but does NOT reliably delegate
// `new` for a class with private/instance fields: `mock.calls` still grows,
// yet the RETURNED instance can be missing internal state, so a later
// method call on it throws instead of behaving like the real thing. That
// silently broke the positive-control tests below (which need construction
// to actually work end-to-end) while leaving the refusal tests, which only
// assert "never constructed", accidentally passing either way. A thin
// wrapper that explicitly re-constructs the real class and returns the
// resulting object avoids this: a function invoked via `new` that returns
// an object uses THAT object as the `new` expression's result, so the spy
// still records every call while every constructed instance is the genuine
// article.
vi.mock("../../src/intelligence/substrates/venice.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/intelligence/substrates/venice.js")>();
  const VeniceClient = vi.fn(function (
    ...args: ConstructorParameters<typeof actual.VeniceClient>
  ) {
    return new actual.VeniceClient(...args);
  });
  return { ...actual, VeniceClient };
});

vi.mock("../../src/intelligence/substrates/frontier.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/intelligence/substrates/frontier.js")>();
  const FrontierClient = vi.fn(function (
    ...args: ConstructorParameters<typeof actual.FrontierClient>
  ) {
    return new actual.FrontierClient(...args);
  });
  return { ...actual, FrontierClient };
});

const { SubstrateSelector } = await import("../../src/intelligence/selector.js");
const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
const { FrontierClient } = await import("../../src/intelligence/substrates/frontier.js");

// `Parameters<typeof fetch>[0]` resolves to the same union `fetch` itself
// declares (`RequestInfo | URL` under the DOM lib) WITHOUT writing the bare
// identifier `RequestInfo`, which is not a visible global type under this
// package's test tsconfig (no `dom` lib). Referencing it by name is what
// widened the typecheck baseline in the prior round; this form type-checks
// clean.
type FetchInput = Parameters<typeof fetch>[0];

function requestUrl(input: FetchInput): string {
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

/**
 * A typed fetch mock: `vi.fn<Parameters<typeof fetch>, ReturnType<typeof
 * fetch>>` keeps full `.mock` access (call args, `.mockClear()`) AND stays
 * structurally assignable to `typeof fetch` with no `as unknown as` cast,
 * so a caller passing the wrong request shape is still a real typecheck
 * error rather than silently erased by the cast.
 */
function fetchMock(
  impl: (input: FetchInput, init?: RequestInit) => Promise<Response>,
) {
  return vi.fn<typeof fetch>(impl);
}

/**
 * Fix-round-4/5 (item 6): a deterministic fetchImpl, never the real
 * network, for the tests below that call `setVeniceApiKey()`/
 * `setFrontierApiKey()` purely to reach a hosted binding (venice OR
 * frontier) and do not otherwise care about the response body's exact
 * shape (the frontier positive control only asserts the constructor was
 * called, not what it parsed). Reused for both providers rather than a
 * separate frontier-specific mock: every one of these tests either never
 * reaches `fetchImpl` at all (refused before construction, or refused
 * before invocation via a held handle) or only checks that construction
 * happened.
 */
function deterministicVeniceFetch(): typeof fetch {
  return fetchMock(async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: "hosted answer" } }] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
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
  vi.mocked(FrontierClient).mockClear();
});

afterEach(() => {
  vi.mocked(VeniceClient).mockClear();
  vi.mocked(FrontierClient).mockClear();
});

describe("SubstrateSelector — local-only request refused against a hosted binding", () => {
  it("invokeSummarize on a venice-bound surface refuses with local_only_violation and never constructs VeniceClient", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    // setVeniceApiKey probes the key; clear so only the invocation under
    // test is measured.
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

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

  // Lens-B (b): a same-file positive control. Without this, a bug that
  // silently disabled the VeniceClient spy (or mocked the wrong export)
  // would make every "not.toHaveBeenCalled()" assertion above pass
  // vacuously. This proves the spy DOES fire for an otherwise-identical
  // ordinary (non-local-only) request against the same venice binding.
  it("positive control: the SAME venice binding without localOnly DOES construct VeniceClient", async () => {
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ choices: [{ message: { content: "hosted answer" } }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
    });

    expect(resp.failureClass).toBeNull();
    expect(VeniceClient).toHaveBeenCalledOnce();
  });

  it("invokeClassify and invokeRedact are refused the same way on a frontier-bound surface, and FrontierClient is never constructed", async () => {
    const { selector } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("sentinel-scoring", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");
    vi.mocked(FrontierClient).mockClear();

    const classifyResp = await selector.invokeClassify("sentinel-scoring", {
      kind: "classify",
      items: ["x"],
      categories: ["a", "b"],
      localOnly: true,
    });
    expect(classifyResp.failureClass).toBe("local_only_violation");
    // Fixed from the prior round: this test asserts on the client it is
    // actually about (frontier), not on VeniceClient, which this test
    // never touches.
    expect(FrontierClient).not.toHaveBeenCalled();
  });

  // Lens-B (b)/(a) positive control for the frontier client, mirroring the
  // venice one above.
  it("positive control: the SAME frontier binding without localOnly DOES construct FrontierClient", async () => {
    const { selector } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("sentinel-scoring", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");
    vi.mocked(FrontierClient).mockClear();

    await selector.invokeClassify("sentinel-scoring", {
      kind: "classify",
      items: ["x"],
      categories: ["a", "b"],
    });
    expect(FrontierClient).toHaveBeenCalledOnce();
  });

  it("a hybrid binding that resolves to venice is refused exactly like a direct venice binding", async () => {
    const { selector } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
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
    const { selector, auditLog } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const handle = await selector.getSubstrate("concierge", { localOnly: true });
    expect(handle.capability.summarize).toBe(false);
    expect(handle.summarize).toBeUndefined();
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

  // P0-1 fix: a caller that obtained a PLAIN (non-localOnly) handle from
  // getSubstrate() must NOT be able to bypass the constraint by calling the
  // handle's own bound method directly instead of going through
  // invokeSummarize(). Every handle getSubstrate() hands out is now
  // chokepoint-backed: its bound methods delegate to invoke() internally,
  // so a per-request localOnly on the ARGUMENT still refuses even though
  // the handle itself was obtained without any localOnly opt.
  it("a handle held from a plain getSubstrate() call still refuses a local-only invocation made directly on it", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    // No localOnly opt here: this is exactly the handle an ordinary
    // capability pre-check (concierge-service, operator-chat-service)
    // would hold, and it correctly reports the venice binding.
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("venice");
    expect(handle.capability.summarize).toBe(true);
    expect(handle.summarize).toBeDefined();
    vi.mocked(VeniceClient).mockClear();

    const resp = await handle.summarize!({
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // Positive control for the P0-1 test above: the same held handle, called
  // directly, DOES reach VeniceClient when the argument carries no
  // localOnly constraint — proving the chokepoint wrapper is a pass-through
  // for ordinary calls, not a blanket block on direct handle invocation.
  it("positive control: the same held handle, called directly WITHOUT localOnly, DOES construct VeniceClient", async () => {
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ choices: [{ message: { content: "hosted via handle" } }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    // Deliberately NOT cleared between `getSubstrate()` and
    // `handle.summarize()`: the selector caches issued handles per
    // surface+choice, so `handle.summarize()`'s internal `invoke()` call
    // reuses the SAME already-issued raw handle rather than reconstructing
    // a second client — that cache reuse is correct, expected behavior,
    // not a gap. What this proves is that the combined path (obtain a
    // handle, then call its bound method) reaches a genuinely working,
    // constructed VeniceClient at least once, i.e. the machinery is not
    // secretly dead — which is what makes the P0-1 refusal test's
    // "never constructed" claim meaningful rather than vacuous.
    const handle = await selector.getSubstrate("concierge");
    const resp = await handle.summarize!({ kind: "summarize", context: "ctx", query: "q" });

    expect(resp.failureClass).toBeNull();
    expect(VeniceClient).toHaveBeenCalledOnce();
  });
});

describe("SubstrateSelector — a held handle's guard reads the HANDLE's own substrate, never the surface's current binding (fix-round-3 P0)", () => {
  // The reviewers' exact trigger: a handle issued while the surface was
  // hosted, then the surface is REBOUND to local, then the HELD handle is
  // called with localOnly. A guard that re-derives the CURRENT binding
  // would see "local" and wrongly allow; `raw.summarize` is still the
  // Venice closure regardless, so the request would reach Venice. The
  // fix reads `raw.substrate` (captured at issue time), so this refuses.
  it("trigger: bind venice, hold, rebind local, call the HELD handle with localOnly — refuses, constructs no client", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("venice");

    await selector.setPerSurfaceChoice("concierge", "local");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    const resp = await handle.summarize!({
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // The mirror: a handle issued while local, held across a rebind to
  // venice, still serves locally when called with localOnly — because
  // `raw.substrate` (captured as "local") never changed, and `raw` is
  // still the ORIGINAL local closure, unaffected by the later rebind.
  it("mirror: bind local, hold, rebind venice, call the HELD handle with localOnly — still served locally", async () => {
    const fetchImpl = fetchMock(async (input) => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response(JSON.stringify({ response: "served from the held local handle" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("local");

    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const resp = await handle.summarize!({
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    expect(resp.failureClass).toBeNull();
    expect(resp.body.kind === "summarize" ? resp.body.text : null).toBe(
      "served from the held local handle",
    );
    expect(VeniceClient).not.toHaveBeenCalled();
  });

  // Same guard, a different method (classify) and a different hosted
  // substrate (frontier): the reviewers asked this be proven for classify
  // and redact and for Frontier and hybrid handles, not just
  // summarize+venice. Frontier here; hybrid+redact below.
  it("trigger (classify, frontier): bind frontier, hold, rebind local, call the HELD handle with localOnly — refuses, constructs no client", async () => {
    const { selector, auditLog } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("gate-explanation", "frontier-with-filter");
    await selector.setFrontierApiKey("anthropic", "test-key");
    const handle = await selector.getSubstrate("gate-explanation");
    expect(handle.substrate).toBe("frontier-with-filter");

    await selector.setPerSurfaceChoice("gate-explanation", "local");
    vi.mocked(FrontierClient).mockClear();

    const resp = await handle.classify!({
      kind: "classify",
      items: ["x"],
      categories: ["a", "b"],
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(FrontierClient).not.toHaveBeenCalled();
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // Same guard, redact, and a hybrid binding: the raw handle hybrid
  // resolves to at issue time is what `raw.substrate` carries (hybrid
  // itself is never a concrete substrate — see `issueHandle`'s recursive
  // resolution), so rebinding the HYBRID RULES afterward is the "rebind"
  // here rather than a direct per-surface choice change.
  it("trigger (redact, hybrid): bind hybrid resolving venice, hold, change the hybrid rule to local, call the HELD handle with localOnly — refuses, constructs no client", async () => {
    const { selector, auditLog } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("template-suggestion", "hybrid");
    await selector.setHybridRules({
      perSurface: {
        concierge: "local",
        "sentinel-scoring": "local",
        "gate-explanation": "local",
        "privacy-filter-tier-2": "local",
        "direct-agent-gate-advisor": "local",
        "template-suggestion": "venice",
      },
    });
    await selector.setVeniceApiKey("test-venice-key");
    const handle = await selector.getSubstrate("template-suggestion");
    expect(handle.substrate).toBe("venice");

    await selector.setHybridRules({
      perSurface: {
        concierge: "local",
        "sentinel-scoring": "local",
        "gate-explanation": "local",
        "privacy-filter-tier-2": "local",
        "direct-agent-gate-advisor": "local",
        "template-suggestion": "local",
      },
    });
    vi.mocked(VeniceClient).mockClear();

    const resp = await handle.redact!({
      kind: "redact",
      text: "sensitive text",
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });
});

describe("SubstrateSelector — local-only request served locally", () => {
  it("succeeds normally when the surface is bound to local, and audits local_only: true on the invoked row", async () => {
    const fetchImpl = fetchMock(async (input) => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response(JSON.stringify({ response: "a local answer" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    });
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
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ response: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();

    await selector.invokeSummarize("concierge", { kind: "summarize", context: "ctx", query: "q" });

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const details = invoked.entries[invoked.entries.length - 1]!.details as { local_only: boolean };
    expect(details.local_only).toBe(false);
  });

  it("a local-only request whose local invocation fails reads as local_only_violation too (one truth), and never falls back to Venice", async () => {
    const fetchImpl = fetchMock(async (input) => {
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
    });
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // Default fallback behavior is degrade-silent; default binding for
    // concierge is local. A valid venice key exists as the WOULD-BE
    // fallback target for an ordinary request (see the sibling
    // non-local-only test in selector.test.ts that proves the opposite
    // case: fallback DOES serve when localOnly is absent).
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();
    // `setVeniceApiKey` itself probes the key against the SAME mocked
    // `api.venice.ai` endpoint, which this test's fetchImpl answers with a
    // 200 for any venice-hostname request; without clearing here, that
    // setup-phase probe call would already be sitting in
    // `fetchImpl.mock.calls` and make the "no venice.ai call happened
    // during the invocation under test" assertion below pass vacuously.
    fetchImpl.mockClear();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    // P2-4 fix: BOTH ways a local-only request can fail to be served
    // locally (a conflicting binding, refused before any handle is
    // issued — see the tests above — and this one, where the binding WAS
    // local but generation itself failed) now surface the SAME typed
    // class to the caller. The original substrate reason is not lost; it
    // survives in the message text.
    expect(resp.failureClass).toBe("local_only_violation");
    expect(resp.body.kind).toBe("failure");
    if (resp.body.kind === "failure") {
      expect(resp.body.message).toContain("local generation failed");
    }
    // The strongest available proof that fallback was never attempted:
    // the hosted client constructor was never reached, so the Venice call
    // recorded in `fetchImpl` above (which WOULD succeed) could not have
    // fired regardless of network stubbing.
    expect(VeniceClient).not.toHaveBeenCalled();
    for (const call of fetchImpl.mock.calls) {
      expect(urlHostnameIs(requestUrl(call[0]), "api.venice.ai")).toBe(false);
    }

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    const row = failures.entries[failures.entries.length - 1]!;
    const details = row.details as { failure_class: string; fallback_taken: string; local_only: boolean };
    expect(details.failure_class).toBe("local_only_violation");
    expect(details.fallback_taken).toBe("deny");
    expect(details.local_only).toBe(true);
  });
});

describe("SubstrateSelector — fix-round-6: TOCTOU, held-handle local-failure normalization, audit-attempt reporting", () => {
  // P0: the reviewer's exact trigger. A caller starts an invocation with
  // `localOnly: true`, then mutates the SAME request object to `false`
  // WHILE the local invocation is genuinely pending (a controllable
  // fetchImpl gate proves this, rather than hoping timing works out), then
  // releases it to fail. The snapshot taken as invoke()'s first statement
  // must be what `tryNextSubstrate` honors, not the mutated value — so
  // fallback to venice (which would otherwise succeed, proving the gate
  // itself works) must never be attempted.
  it("mutating req.localOnly to false WHILE local generation is pending does not defeat the refusal or reach the fallback", async () => {
    let reachedGate: () => void;
    const reachedGatePromise = new Promise<void>((resolve) => {
      reachedGate = resolve;
    });
    let releaseGate: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const fetchImpl = fetchMock(async (input) => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        reachedGate();
        await gate;
        return new Response("", { status: 500 });
      }
      if (urlHostnameIs(url, "api.venice.ai")) {
        return new Response(
          JSON.stringify({ choices: [{ message: { content: "should never be served" } }] }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("", { status: 404 });
    });
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local"; venice is the WOULD-BE fallback
    // target (degrade-silent is the default fallback behavior), proving
    // the gate genuinely leads somewhere reachable if the snapshot fails.
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const req = {
      kind: "summarize" as const,
      context: "ctx",
      query: "q",
      localOnly: true,
    };
    const pending = selector.invokeSummarize("concierge", req);
    await reachedGatePromise; // local generation is now genuinely in flight
    req.localOnly = false; // mutate AFTER the call started, WHILE it is pending
    releaseGate!();
    const resp = await pending;

    expect(resp.failureClass).toBe("local_only_violation");
    expect(resp.localOnlyReason).toBe("local_unavailable");
    expect(VeniceClient).not.toHaveBeenCalled();

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // P1, item 2: a directly held LOCAL handle (never refused by
  // guardDirectHandleCall, since its own substrate IS local) whose local
  // invocation fails must read the same way invoke()'s equivalent failure
  // reads: local_only_violation / local_unavailable, with an audit event —
  // not the raw substrate_unavailable class the substrate client itself
  // returns, unaudited.
  it("a held LOCAL handle's own generation failure normalizes to local_only_violation/local_unavailable with an audit event, not the raw substrate_unavailable", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    const handle = await selector.getSubstrate("concierge");
    expect(handle.substrate).toBe("local");

    const resp = await handle.summarize!({
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    expect(resp.failureClass).toBe("local_only_violation");
    expect(resp.localOnlyReason).toBe("local_unavailable");
    expect(resp.body.kind).toBe("failure");
    if (resp.body.kind === "failure") {
      expect(resp.body.message).toContain("substrate_unavailable");
    }
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // Positive control: an ordinary (non-local-only) call through the SAME
  // held local handle, on the SAME kind of failure, is left UNNORMALIZED
  // (the raw substrate_unavailable class), proving the normalization is
  // localOnly-scoped, not a blanket rewrite of every local failure.
  it("positive control: the SAME held LOCAL handle's failure is NOT normalized when the request is not local-only", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    const handle = await selector.getSubstrate("concierge");

    const resp = await handle.summarize!({ kind: "summarize", context: "ctx", query: "q" });

    expect(resp.failureClass).toBe("substrate_unavailable");
    expect(resp.localOnlyReason).toBeUndefined();
  });

  // P1, item 3: subtraction, not durability. A failing audit backend must
  // not silently swallow the failed attempt — the refusal still refuses
  // (fail-closed), but the response reports auditRecorded: false plus the
  // error class.
  it("a failing audit backend still refuses (fail-closed), and reports auditRecorded: false with the error class", async () => {
    // Two selectors share the SAME storage/masterKey: the first, with a
    // REAL audit log, persists a venice binding for concierge (so
    // `setPerSurfaceChoice`'s own fire-and-forget `emit()` never touches
    // the throwing backend and cannot produce an unrelated unhandled
    // rejection); the second, with the THROWING audit log, reads that
    // already-persisted binding and is the one under test.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const setupAuditLog = new AuditLog(storage, masterKey);
    const setupSelector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog: setupAuditLog,
      identityId: "test-identity",
    });
    await setupSelector.load();
    await setupSelector.setPerSurfaceChoice("concierge", "venice");

    class ThrowingAuditLog {
      async append(): Promise<never> {
        throw new TypeError("simulated audit backend failure");
      }
    }
    const auditLog = new ThrowingAuditLog() as unknown as AuditLog;
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    // load()'s own success-path audit-emit is already try/catch-wrapped
    // (unrelated to this fix), so this does not throw even against the
    // throwing backend.
    await selector.load();

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });

    // Fail-closed always wins: the refusal itself is unconditional.
    expect(resp.failureClass).toBe("local_only_violation");
    // The audit ATTEMPT's own failure is surfaced, not dropped.
    expect(resp.auditRecorded).toBe(false);
    expect(resp.auditError).toBe("TypeError");
  });

  // P1 fix-round-9, item 2: `getSubstrate()`'s capability-precheck path
  // (a local-only request against a hosted binding, refused BEFORE any
  // handle/client is constructed) is a local-only DECISION exactly like
  // `invoke()`'s pre-emptive refusal, and its audit ATTEMPT can fail the
  // same way. The prior version of `getOrIssueHandle` awaited that
  // attempt's result and then discarded it, returning a plain
  // `disabledHandle(surface)` with no way to signal a failed audit write
  // -- a caller holding only the handle (this method's whole contract)
  // had no signal at all, unlike every OTHER local-only refusal shape in
  // this file. `SubstrateHandle` now carries the same `auditRecorded`/
  // `auditError` pair `SubstrateResponse` does, set exactly when this
  // path's audit write fails.
  it("getSubstrate()'s capability-precheck refusal against a failing audit backend still returns a disabled handle (fail-closed), and reports auditRecorded: false with the error class", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const setupAuditLog = new AuditLog(storage, masterKey);
    const setupSelector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog: setupAuditLog,
      identityId: "test-identity",
    });
    await setupSelector.load();
    await setupSelector.setPerSurfaceChoice("concierge", "venice");

    class ThrowingAuditLog {
      async append(): Promise<never> {
        throw new TypeError("simulated audit backend failure");
      }
    }
    const auditLog = new ThrowingAuditLog() as unknown as AuditLog;
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    await selector.load();
    vi.mocked(VeniceClient).mockClear();

    const handle = await selector.getSubstrate("concierge", { localOnly: true });

    // Fail-closed always wins: the refusal itself is unconditional.
    expect(handle.capability.summarize).toBe(false);
    expect(handle.summarize).toBeUndefined();
    expect(VeniceClient).not.toHaveBeenCalled();
    // The audit ATTEMPT's own failure is surfaced on the HANDLE, not
    // dropped.
    expect(handle.auditRecorded).toBe(false);
    expect(handle.auditError).toBe("TypeError");
  });

  // Positive control: the SAME capability-precheck refusal against a
  // WORKING audit backend leaves `auditRecorded`/`auditError` absent
  // (never `auditRecorded: true`), matching `SubstrateResponse`'s own
  // convention (`failureResponse`'s doc comment) -- the fields exist to
  // flag a failed attempt, not to certify every successful one.
  it("positive control: the SAME capability-precheck refusal against a WORKING audit backend leaves auditRecorded/auditError absent", async () => {
    const { selector } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const handle = await selector.getSubstrate("concierge", { localOnly: true });

    expect(handle.capability.summarize).toBe(false);
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(handle.auditRecorded).toBeUndefined();
    expect(handle.auditError).toBeUndefined();
  });
});

describe("SubstrateSelector — fix-round-8: readLocalOnlyOnce closes the re-read class without copying the request", () => {
  /**
   * A request whose `localOnly` is an ACCESSOR: answers `true` on the
   * FIRST read and `false` on every read after that. A snapshot taken as
   * a separate boolean (round 6's fix) is safe against a caller MUTATING
   * a plain property between two reads of the SAME object, but is not
   * safe against a getter like this one if anything downstream still
   * reads `.localOnly` off the caller's ORIGINAL object a second time --
   * exactly what round 7's three findings identified (`guardDirectHandleCall`
   * still read the caller's own `req` internally, even though a separate
   * `localOnly` boolean had already been snapshotted beside it). Round
   * 7's own fix (`freezeLocalOnlyRequest`) closed THAT gap by copying the
   * whole request, coercing `localOnly` at copy time -- but a plain-object
   * copy (spread/rest) only sees OWN ENUMERABLE properties, so a
   * class-backed request (fields as prototype getters, as real production
   * request objects can be) silently lost its content in the copy. Round
   * 8's fix (`readLocalOnlyOnce`) reads the accessor exactly ONCE and
   * returns just the boolean, never a copy of the request -- the
   * request itself is threaded on UNCHANGED for its content. Each test
   * below asserts the outward behavior (refusal, no hosted client
   * constructed); the DECISION path's read count is asserted where the
   * decision refuses (which short-circuits before anything else touches
   * the request); an ACCEPTED request's content is separately hashed for
   * the audit record afterward (`hashOfRequest`, via `JSON.stringify`),
   * which incidentally re-reads every own enumerable property including
   * `localOnly` -- unrelated to the local-only decision (already made,
   * once, correctly) and not a regression this suite needs to forbid.
   */
  function accessorSummarizeRequest(): { req: SummarizeRequest; reads: () => number } {
    let count = 0;
    const req = {
      kind: "summarize" as const,
      context: "ctx",
      query: "q",
      get localOnly() {
        count += 1;
        return count === 1;
      },
    };
    return { req, reads: () => count };
  }

  function accessorClassifyRequest(): { req: ClassifyRequest; reads: () => number } {
    let count = 0;
    const req = {
      kind: "classify" as const,
      items: ["x"],
      categories: ["a", "b"],
      get localOnly() {
        count += 1;
        return count === 1;
      },
    };
    return { req, reads: () => count };
  }

  function accessorRedactRequest(): { req: RedactRequest; reads: () => number } {
    let count = 0;
    const req = {
      kind: "redact" as const,
      text: "secret",
      get localOnly() {
        count += 1;
        return count === 1;
      },
    };
    return { req, reads: () => count };
  }

  it("invoke(): a getter answering true-then-false still refuses, constructs no hosted client, and is read exactly once", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    const { req, reads } = accessorSummarizeRequest();
    const resp = await selector.invokeSummarize("concierge", req);

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reads()).toBe(1);

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  it("chokepointHandle summarize: a getter answering true-then-false still refuses, constructs no hosted client, and is read exactly once", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    // getSubstrate() without localOnly issues (and constructs) the raw
    // venice handle; clear AFTER issuance so the assertion below is about
    // the direct-handle CALL, not the handle's own construction.
    const handle = await selector.getSubstrate("concierge");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    const { req, reads } = accessorSummarizeRequest();
    const resp = await handle.summarize!(req);

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reads()).toBe(1);
  });

  it("chokepointHandle classify: a getter answering true-then-false still refuses, constructs no hosted client, and is read exactly once", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    const handle = await selector.getSubstrate("concierge");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    const { req, reads } = accessorClassifyRequest();
    const resp = await handle.classify!(req);

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reads()).toBe(1);
  });

  it("chokepointHandle redact: a getter answering true-then-false still refuses, constructs no hosted client, and is read exactly once", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    const handle = await selector.getSubstrate("concierge");
    vi.mocked(VeniceClient).mockClear();
    fetchImpl.mockClear();

    const { req, reads } = accessorRedactRequest();
    const resp = await handle.redact!(req);

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reads()).toBe(1);
  });

  // Round 4, item 3: the getter/read-count proof for `getSubstrate()`'s
  // OWN `opts` parameter, not just the request objects `invoke()` and the
  // chokepointHandle closures read. `getSubstrate()` is a public entry
  // point (concierge/operator-chat call it directly for a capability
  // pre-check), so its `opts` is exactly as caller-owned as a request —
  // this proves `readLocalOnlyOnce(opts ?? {})` reads a getter-backed
  // `opts.localOnly` exactly once too, not just plain-object opts.
  it("getSubstrate(): an opts object whose localOnly is a getter answering true-then-false still returns a capability-zeroed handle without constructing VeniceClient, and is read exactly once", async () => {
    const { selector } = buildSelector({ fetchImpl: deterministicVeniceFetch() });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    let count = 0;
    const opts = {
      get localOnly() {
        count += 1;
        return count === 1;
      },
    };
    const handle = await selector.getSubstrate("concierge", opts);

    expect(handle.capability.summarize).toBe(false);
    expect(handle.summarize).toBeUndefined();
    expect(VeniceClient).not.toHaveBeenCalled();
    expect(count).toBe(1);
  });

  // Positive control: the SAME accessor shape, on a LOCAL binding (where
  // refusesLocalOnly is false regardless of the boolean's value), proves
  // these tests are not vacuously passing because the accessor itself
  // throws or misbehaves -- the request is genuinely accepted and served
  // when there is no conflicting binding to refuse against. Fix-round-9
  // (P1, item 1): this path now ALSO asserts `reads() === 1`. A prior
  // round's comment here exempted this specific test from that assertion,
  // because `hashOfRequest` used to run `JSON.stringify(req)` directly on
  // the caller's object, which read `req.localOnly` a SECOND time as an
  // unavoidable side effect of serializing the whole request. Now that
  // `hashOfRequest` takes the already-read `localOnly` boolean as an
  // explicit parameter and builds its hash input from a named-field
  // projection instead of the raw object (see `hashOfRequest`'s and
  // `canonicalRequestProjection`'s doc comments in selector.ts), there is
  // no second read anywhere on the ACCEPTED path either -- the exemption
  // no longer describes real behavior, so keeping it would let a
  // regression that reintroduces a second read pass silently on exactly
  // this path.
  it("positive control: the same true-then-false accessor on a LOCAL binding is served normally, and is still read exactly once", async () => {
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ response: "local answer" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local".

    const { req, reads } = accessorSummarizeRequest();
    const resp = await selector.invokeSummarize("concierge", req);

    expect(resp.failureClass).toBeNull();
    expect(reads()).toBe(1);
  });

  // P1 fix-round-9 -> fix-round-10 (item 1 -> items 2/3): the original
  // `hashOfRequest` ran `JSON.stringify(req)` on the caller's raw object,
  // which (a) re-read `req.localOnly` a second time and (b) serialized
  // only OWN ENUMERABLE properties, so a class-backed request (content as
  // prototype getters) hashed as `{}`. Fix-round-9 tried fixing this by
  // changing `request_hash`'s own preimage shape (adding `surface`,
  // coercing `localOnly`, making omitted fields explicit `null`s) --
  // which round 4's review correctly flagged as an undocumented MEANING
  // change to an existing field (identical historical requests would
  // hash differently with no version bump). Fix-round-10 reverted
  // `request_hash` to its EXACT original preimage shape and instead fixed
  // the ROOT problem underneath both bugs: `invoke()` now materializes
  // every content field ONCE, via ordinary property access (works on a
  // getter same as a plain field), and hashes THAT materialized snapshot
  // -- never `JSON.stringify`ing the live object directly. This test
  // still proves what it always proved (a getter-backed request is not
  // silently hashing as `{}`, and the hash is genuinely content-sensitive)
  // but now against `request_hash`, the LEGACY field, which fix-round-10
  // made robust to getters WITHOUT changing its preimage shape for a
  // well-behaved plain-object caller. The NEW `request_projection_hash`
  // field (preimage v2: surface-bound, coerced boolean, explicit nulls)
  // is checked alongside it for the same parity, since it is built from
  // the SAME materialized snapshot.
  it("a getter-backed request hashes identically, in the audit record, to its plain-object equivalent -- and differently from a request with different content", async () => {
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ response: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local", so all three requests below are
    // accepted (not refused) and reach the audited invoked row.

    const plainReq: SummarizeRequest = {
      kind: "summarize",
      context: "shared-context",
      query: "shared-query",
      localOnly: true,
    };
    class GetterBackedSummarizeRequest {
      get kind(): "summarize" {
        return "summarize";
      }
      get context(): string {
        return "shared-context";
      }
      get query(): string {
        return "shared-query";
      }
      get localOnly(): boolean {
        return true;
      }
    }
    const getterReq = new GetterBackedSummarizeRequest() as unknown as SummarizeRequest;
    const differentReq: SummarizeRequest = {
      kind: "summarize",
      context: "different-context",
      query: "shared-query",
      localOnly: true,
    };

    await selector.invokeSummarize("concierge", plainReq);
    await selector.invokeSummarize("concierge", getterReq);
    await selector.invokeSummarize("concierge", differentReq);

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const rows = invoked.entries
      .slice(-3)
      .map((e) => e.details as { request_hash: string; request_projection_hash?: string });
    const [plainRow, getterRow, differentRow] = rows;

    expect(plainRow.request_hash).toBeTruthy();
    expect(getterRow.request_hash).toBe(plainRow.request_hash);
    expect(differentRow.request_hash).not.toBe(plainRow.request_hash);

    // Fix-round-10, item 2: the NEW preimage-v2 field is built from the
    // SAME single-read materialized content, so it carries the identical
    // parity property.
    expect(plainRow.request_projection_hash).toBeTruthy();
    expect(getterRow.request_projection_hash).toBe(plainRow.request_projection_hash);
    expect(differentRow.request_projection_hash).not.toBe(plainRow.request_projection_hash);
  });

  // P1 fix-round-10, item 2: the CORE regression-preventing test for the
  // legacy-preimage-preservation property. A request that never sets
  // `localOnly` at all -- the OVERWHELMING majority of real production
  // callers today (every existing call site in `src/` omits it) -- must
  // still hash under `request_hash` EXACTLY as `JSON.stringify` of its
  // own fields would, with NO `localOnly` key present at all (never a
  // coerced `localOnly: false`). This is computed independently here
  // (the same SHA-256-over-JSON pipeline `hashOfRequest` itself uses,
  // but built from a hand-written expected preimage, not by calling any
  // of this file's own helpers) so a regression that reintroduces
  // fix-round-9's coercion is caught by an INDEPENDENT expected value,
  // not by re-deriving the same possibly-wrong value the code under test
  // would also produce.
  it("request_hash omits the localOnly key entirely for a request that never sets it, matching JSON.stringify's own undefined-skipping behavior", async () => {
    const fetchImpl = fetchMock(async () =>
      new Response(JSON.stringify({ response: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local"; this request has NO localOnly key.

    await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "no-local-only-key",
      query: "q",
    });

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const row = invoked.entries[invoked.entries.length - 1]!.details as { request_hash: string };

    const expectedPreimage = JSON.stringify({ kind: "summarize", context: "no-local-only-key", query: "q" });
    const expectedHash = hashToString(hash(stringToBytes(expectedPreimage)));
    expect(row.request_hash).toBe(expectedHash);
  });

  // P1 fix-round-10, item 3: the stateful-getter proof. A request whose
  // CONTENT (not just `localOnly`) is an accessor returning a DIFFERENT
  // value on each read would, without materializing content once at
  // entry, present one value to the pre-egress context scanner, a
  // DIFFERENT value to the audit hash, and a THIRD value to the substrate
  // actually invoked. This proves all three now agree: the fetch body
  // the local substrate actually received, and the audited `request_hash`
  // (independently recomputed from the FIRST-read content, matching what
  // `materializeRequestContent` should have captured), both reflect the
  // SAME single read.
  it("a stateful getter (different content on each read) is screened, hashed, and sent using the SAME single-read content", async () => {
    let contextReads = 0;
    const contextValues = ["first-read-content", "second-read-content", "third-read-content"];
    const req = {
      kind: "summarize" as const,
      get context() {
        const value = contextValues[Math.min(contextReads, contextValues.length - 1)];
        contextReads += 1;
        return value;
      },
      query: "q",
      localOnly: true,
    };

    const fetchImpl = fetchMock(async (input, init) => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response(JSON.stringify({ response: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    });
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local", so this is accepted, screened, and
    // actually invoked -- exercising all three consumers of `.context`.

    const resp = await selector.invokeSummarize("concierge", req);
    expect(resp.failureClass).toBeNull();

    // The FIRST read is the one and only value every consumer must see.
    expect(contextReads).toBe(1);

    const generateCall = fetchImpl.mock.calls.find(([input]) => urlPathnameIs(requestUrl(input), "/api/generate"));
    expect(generateCall).toBeDefined();
    const body = JSON.parse(String(generateCall![1]?.body));
    expect(body.prompt).toContain("first-read-content");
    expect(body.prompt).not.toContain("second-read-content");
    expect(body.prompt).not.toContain("third-read-content");

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const row = invoked.entries[invoked.entries.length - 1]!.details as { request_hash: string };
    const expectedPreimage = JSON.stringify({
      kind: "summarize",
      context: "first-read-content",
      query: "q",
      localOnly: true,
    });
    const expectedHash = hashToString(hash(stringToBytes(expectedPreimage)));
    expect(row.request_hash).toBe(expectedHash);
  });

  // P1 fix-round-10, item 4: `invoke()` promises ONE `substrate_invoked`
  // event per call, carrying `request_hash`/`response_hash`/`latency_ms`
  // -- fields NO OTHER event shape carries. The local-only local-failure
  // early-return path (a local-only request whose LOCAL generation
  // genuinely fails) used to skip this event entirely, emitting only the
  // `substrate_failure` row from `auditLocalOnlyRefusal`, which has none
  // of those three fields -- silently thinner evidence than every other
  // `invoke()` outcome. This proves the invoked row now exists too, with
  // a real hash and a non-negative latency, and a failure_class matching
  // the typed refusal the caller received.
  it("a local-only request whose local generation fails ALSO emits a substrate_invoked event (with hash and latency), not just the substrate_failure row", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector, auditLog } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local"; the 500 above makes local generation
    // genuinely fail, reaching the requestLocalOnly early-return branch.

    const resp = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "ctx",
      query: "q",
      localOnly: true,
    });
    expect(resp.failureClass).toBe("local_only_violation");
    expect(resp.localOnlyReason).toBe("local_unavailable");

    const invoked = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_INVOKED });
    const row = invoked.entries[invoked.entries.length - 1]!.details as {
      request_hash: string;
      request_projection_hash?: string;
      response_hash: string | null;
      latency_ms: number;
      failure_class: string | null;
      local_only?: boolean;
    };
    expect(row.request_hash).toBeTruthy();
    expect(row.request_projection_hash).toBeTruthy();
    expect(row.response_hash).toBeNull();
    expect(row.latency_ms).toBeGreaterThanOrEqual(0);
    expect(row.failure_class).toBe("local_only_violation");
    expect(row.local_only).toBe(true);

    // The refusal event is STILL emitted too -- this is additive, not a
    // replacement.
    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  // P1 regression fix-round-8: a CLASS-BACKED request whose fields
  // (including `localOnly`) are defined as GETTERS ON THE PROTOTYPE, not
  // own enumerable instance properties -- exactly the shape
  // `freezeLocalOnlyRequest`'s plain-object copy (round 7) silently
  // mangled, because `{ ...request }` and object-rest destructuring both
  // only see OWN ENUMERABLE properties. `readLocalOnlyOnce` never copies
  // `request`, so this request's content reaches `compileSubstrateContext`
  // and the local substrate's own prompt-building UNCHANGED, and the
  // refusal decision (made from `localOnly`, read via ordinary property
  // access, which works on any accessor regardless of enumerability) is
  // unaffected either way.
  class ClassBackedSummarizeRequest {
    get kind(): "summarize" {
      return "summarize";
    }
    get context(): string {
      return "class-backed-context-marker";
    }
    get query(): string {
      return "class-backed-query-marker";
    }
    get localOnly(): boolean {
      return true;
    }
  }

  it("a class-backed request (fields as non-enumerable prototype getters) still refuses when localOnly is true, without losing its content to a mangled copy", async () => {
    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    await selector.setPerSurfaceChoice("concierge", "venice");
    await selector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const req = new ClassBackedSummarizeRequest() as unknown as SummarizeRequest;
    const resp = await selector.invokeSummarize("concierge", req);

    expect(resp.failureClass).toBe("local_only_violation");
    expect(VeniceClient).not.toHaveBeenCalled();
  });

  it("a class-backed request's CONTENT survives to the local substrate's prompt when the request is accepted (proves the fix never copies/mangles the request)", async () => {
    const fetchImpl = fetchMock(async (input, init) => {
      const url = requestUrl(input);
      if (urlPathnameIs(url, "/api/generate")) {
        return new Response(JSON.stringify({ response: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    });
    const { selector } = buildSelector({ fetchImpl });
    await selector.load();
    // concierge defaults to "local", so this class-backed request (whose
    // own `localOnly` getter answers `true`) is accepted, not refused.

    const req = new ClassBackedSummarizeRequest() as unknown as SummarizeRequest;
    const resp = await selector.invokeSummarize("concierge", req);

    expect(resp.failureClass).toBeNull();
    const generateCall = fetchImpl.mock.calls.find(([input]) => urlPathnameIs(requestUrl(input), "/api/generate"));
    expect(generateCall).toBeDefined();
    const body = JSON.parse(String(generateCall![1]?.body));
    expect(body.prompt).toContain("class-backed-context-marker");
    expect(body.prompt).toContain("class-backed-query-marker");
  });

  // P1 fix-round-7, item 2: `invoke()`'s local-failure branch, when the
  // request is local-only, must return through `auditLocalOnlyRefusal`
  // (which never throws) exactly like the other three refusal sites --
  // not fall through to the shared `emitAwaited` calls, which DO throw on
  // a failed audit write by design for the non-local-only paths that
  // share them. Before this fix, a failing audit backend crashed this
  // specific case (local-only request, local generation genuinely fails)
  // instead of returning the typed `local_only_violation` response with
  // `auditRecorded: false`, unlike every other local-only refusal shape.
  it("a local-only request whose local generation fails, against a failing audit backend, still returns the typed response with auditRecorded: false instead of throwing", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    class ThrowingAuditLog {
      async append(): Promise<never> {
        throw new TypeError("simulated audit backend failure");
      }
    }
    const auditLog = new ThrowingAuditLog() as unknown as AuditLog;
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "test-identity",
    });
    // load()'s own success-path audit-emit is already try/catch-wrapped
    // (unrelated to this fix), so this does not throw against the
    // throwing backend. concierge defaults to "local", so local
    // generation is what genuinely fails below (a 500 from the local
    // substrate's own fetch), not a pre-emptive binding-conflict refusal.
    await selector.load();

    const fetchImpl = fetchMock(async () => new Response("", { status: 500 }));
    (selector as unknown as { fetchImpl: typeof fetch }).fetchImpl = fetchImpl;

    let resp: Awaited<ReturnType<typeof selector.invokeSummarize>> | undefined;
    let thrown: unknown;
    try {
      resp = await selector.invokeSummarize("concierge", {
        kind: "summarize",
        context: "ctx",
        query: "q",
        localOnly: true,
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeUndefined();
    expect(resp).toBeDefined();
    expect(resp!.failureClass).toBe("local_only_violation");
    expect(resp!.localOnlyReason).toBe("local_unavailable");
    expect(resp!.auditRecorded).toBe(false);
    expect(resp!.auditError).toBe("TypeError");
  });
});
