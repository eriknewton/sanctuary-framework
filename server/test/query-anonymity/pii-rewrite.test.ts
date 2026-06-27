/**
 * WP-V1.x-QUERY-LAYER-ANONYMITY Rho-2 Tier B PII rewrite regression suite.
 *
 * Coverage:
 *   - Regex first-pass per category (7 categories: email, phone, SSN,
 *     IPv4/IPv6, credit-card-Luhn, street address, name patterns).
 *   - Luhn validation gates credit-card false positives.
 *   - Name stop-list filters out common false positives like
 *     "United States".
 *   - Placeholder tokens are category-stable + per-call indexed +
 *     deduplicated across repeated occurrences.
 *   - LLM-assist runs on residuals via selector.invokeRedact on the
 *     `privacy-filter-tier-2` surface; failures degrade to regex
 *     output without throwing.
 *   - Per-fortress config: default off, consent-required gate,
 *     refuses to flip enabled=true without consent in the merged
 *     patch, consented_at stamp-once invariant, last_toggled_at
 *     tracks the most recent flip, multi-fortress AAD isolation.
 *   - Per-query override semantics (true / false / undefined).
 *   - HTTP routes: GET config returns default + persisted; PATCH
 *     toggles + records consent + emits audit; 409 on consent_required;
 *     trade-off explainer route + POST rewrite preview.
 *   - Audit emission shape (category counts + LLM flags +
 *     consented_to_trade_off snapshot).
 *
 * Castle-walking: no outbound surface; LLM-assist re-uses existing
 * substrate-selector channel.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type {
  SubstrateResponse,
  SummarizeRequest,
  ClassifyRequest,
  RedactRequest,
} from "../../src/intelligence/types.js";

import {
  rewritePiiRegexOnly,
  rewritePiiWithLlm,
  PII_REWRITE_AUDIT_OPS,
  PII_TRADE_OFF_EXPLAINER,
  PII_REWRITE_LLM_SURFACE,
  type PiiRewriteSelector,
} from "../../src/query-anonymity/pii-rewrite.js";
import {
  PiiConfigStore,
  PiiConsentRequired,
  defaultPiiRewriteConfig,
  TIER_B_NAMESPACE,
} from "../../src/query-anonymity/pii-config-store.js";
import {
  PII_REWRITE_API_PREFIX,
  handlePiiRewriteRoute,
  emitPiiRewriteAudit,
  effectiveTierBEnabled,
  TIER_B_INACTIVE_REASON,
} from "../../src/query-anonymity/pii-rewrite-routes.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

function makeRig(opts?: { fortressId?: string; now?: () => Date }) {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new PiiConfigStore({
    storage,
    masterKey,
    fortressId,
    now: opts?.now,
  });
  return { storage, masterKey, auditLog, store, fortressId };
}

/**
 * A `now` provider whose every call returns a STRICTLY-INCREASING
 * timestamp, guaranteeing the two independent samples inside
 * `patch()` (`updated_at` then `consented_at`) differ. This is the
 * exact condition that broke the old timestamp-equality heuristic:
 * with mismatched timestamps the legacy
 * `consented_at === updated_at` comparison is false and the consent
 * audit event was silently dropped.
 */
function strictlyIncreasingNow(startMs = Date.UTC(2026, 0, 1)): () => Date {
  let tick = startMs;
  return () => new Date((tick += 1000));
}

/**
 * Fake selector for LLM-assist tests. Configurable response shape so
 * each test can assert against deterministic output.
 */
class FakeSelector implements PiiRewriteSelector {
  responses: SubstrateResponse[] = [];
  calls: Array<{ surface: string; request: RedactRequest }> = [];
  shouldThrow = false;
  async invokeRedact(
    surface: string,
    req: SummarizeRequest | ClassifyRequest | RedactRequest,
  ): Promise<SubstrateResponse> {
    if (req.kind !== "redact") {
      throw new Error("FakeSelector: unexpected request kind");
    }
    this.calls.push({ surface, request: req });
    if (this.shouldThrow) throw new Error("selector exploded");
    const next = this.responses.shift();
    if (!next) {
      return {
        servedBy: "claude-anthropic",
        failureClass: null,
        body: {
          kind: "redact",
          redacted: req.text,
          placeholders: {},
        },
        completedAt: new Date().toISOString(),
        latencyMs: 0,
      };
    }
    return next;
  }
}

describe("Rho-2 regex first-pass per category", () => {
  it("redacts emails with category-stable placeholders", () => {
    const result = rewritePiiRegexOnly(
      "email me at alex@example.com and CC bob@test.org",
    );
    expect(result.rewritten).not.toContain("alex@example.com");
    expect(result.rewritten).not.toContain("bob@test.org");
    expect(result.redaction_counts.email).toBe(2);
    expect(result.rewritten).toContain("[EMAIL_0]");
    expect(result.rewritten).toContain("[EMAIL_1]");
    expect(Object.values(result.placeholders)).toContain("alex@example.com");
  });

  it("dedupes repeated occurrences to the same placeholder token", () => {
    const result = rewritePiiRegexOnly(
      "send to a@b.com, no wait, send to a@b.com again",
    );
    expect(result.redaction_counts.email).toBe(1);
    expect(result.rewritten.split("[EMAIL_0]").length - 1).toBe(2);
  });

  it("redacts US-format phone numbers across common shapes", () => {
    const text = "call (415) 555-1234 or 415-555-9876 or +1 555 123 4567";
    const result = rewritePiiRegexOnly(text);
    expect(result.redaction_counts.phone).toBeGreaterThanOrEqual(2);
    expect(result.rewritten).toContain("[PHONE_");
  });

  it("redacts SSN-shape strings", () => {
    const result = rewritePiiRegexOnly("ssn: 123-45-6789, again 987-65-4321");
    expect(result.redaction_counts.ssn).toBe(2);
    expect(result.rewritten).not.toContain("123-45-6789");
    expect(result.rewritten).not.toContain("987-65-4321");
  });

  it("redacts IPv4 and IPv6 addresses under ip_address category", () => {
    const result = rewritePiiRegexOnly(
      "server 192.168.1.10 also 2001:db8:85a3:0:0:8a2e:370:7334",
    );
    expect(result.redaction_counts.ip_address).toBe(2);
    expect(result.rewritten).not.toContain("192.168.1.10");
    expect(result.rewritten).not.toContain(
      "2001:db8:85a3:0:0:8a2e:370:7334",
    );
  });

  it("redacts Luhn-valid credit cards; skips non-Luhn 16-digit strings", () => {
    // 4111 1111 1111 1111 is a canonical Visa test number (Luhn-valid).
    // 1234 5678 9012 3456 is not Luhn-valid.
    const result = rewritePiiRegexOnly(
      "card 4111 1111 1111 1111 vs invoice 1234 5678 9012 3456",
    );
    expect(result.redaction_counts.credit_card).toBe(1);
    expect(result.rewritten).not.toContain("4111 1111 1111 1111");
    expect(result.rewritten).toContain("1234 5678 9012 3456");
  });

  it("redacts street-address shape (number + words + suffix)", () => {
    const result = rewritePiiRegexOnly("meet me at 123 Main Street tomorrow");
    expect(result.redaction_counts.street_address).toBe(1);
    expect(result.rewritten).not.toContain("123 Main Street");
  });

  it("redacts two-capitalized-word names; stop-list excludes place names", () => {
    const result = rewritePiiRegexOnly(
      "Alex Johnson lives in New York and works at Microsoft",
    );
    expect(result.redaction_counts.name).toBeGreaterThanOrEqual(1);
    expect(result.rewritten).not.toContain("Alex Johnson");
    // Stop-list keeps the place name intact.
    expect(result.rewritten).toContain("New York");
  });

  it("empty text returns zero redactions and the unchanged string", () => {
    const result = rewritePiiRegexOnly("");
    expect(result.rewritten).toBe("");
    expect(
      Object.values(result.redaction_counts).reduce((a, b) => a + b, 0),
    ).toBe(0);
    expect(result.placeholders).toEqual({});
  });
});

describe("Rho-2 LLM-assist on residuals", () => {
  it("invokes selector.invokeRedact on the privacy-filter-tier-2 surface", async () => {
    const selector = new FakeSelector();
    selector.responses.push({
      servedBy: "claude-anthropic",
      failureClass: null,
      body: {
        kind: "redact",
        redacted: "email [EMAIL_0] and ping [USER_0]",
        placeholders: {
          "[EMAIL_0]": "a@b.com",
          "[USER_0]": "alex_xyz",
        },
      },
      completedAt: new Date().toISOString(),
      latencyMs: 4,
    });
    const result = await rewritePiiWithLlm(
      "email a@b.com and ping alex_xyz on the side channel",
      selector,
      { identityId: IDENTITY },
    );
    expect(selector.calls.length).toBe(1);
    expect(selector.calls[0]?.surface).toBe(PII_REWRITE_LLM_SURFACE);
    expect(result.llm_assist_ran).toBe(true);
    expect(result.llm_residual_count).toBeGreaterThanOrEqual(1);
    // Merged placeholder map carries both regex + LLM finds.
    expect(result.placeholders["[EMAIL_0]"]).toBe("a@b.com");
    expect(result.placeholders["[USER_0]"]).toBe("alex_xyz");
  });

  it("selector failure degrades to regex-only without throwing", async () => {
    const selector = new FakeSelector();
    selector.shouldThrow = true;
    const result = await rewritePiiWithLlm(
      "email a@b.com about it",
      selector,
      { identityId: IDENTITY },
    );
    expect(result.llm_assist_ran).toBe(false);
    expect(result.redaction_counts.email).toBe(1);
  });

  it("short text with zero regex hits short-circuits the LLM call", async () => {
    const selector = new FakeSelector();
    const result = await rewritePiiWithLlm("hi", selector, {
      identityId: IDENTITY,
    });
    expect(selector.calls.length).toBe(0);
    expect(result.llm_assist_ran).toBe(false);
  });
});

describe("Rho-2 PiiConfigStore lifecycle", () => {
  it("default config is off + no consent; returned on first read", async () => {
    const { store } = makeRig();
    const config = await store.get();
    expect(config?.enabled).toBe(false);
    expect(config?.consented_to_trade_off).toBe(false);
  });

  it("refuses to flip enabled=true without consent (PiiConsentRequired)", async () => {
    const { store } = makeRig();
    await expect(store.patch({ enabled: true })).rejects.toBeInstanceOf(
      PiiConsentRequired,
    );
  });

  it("patches consent + enable together; stamps consented_at + last_toggled_at", async () => {
    const { store } = makeRig();
    const { config: result, consentJustRecorded } = await store.patch({
      enabled: true,
      consented_to_trade_off: true,
    });
    expect(result.enabled).toBe(true);
    expect(result.consented_to_trade_off).toBe(true);
    expect(result.consented_at).toBeDefined();
    expect(result.last_toggled_at).toBeDefined();
    // The false->true consent flip is signalled explicitly.
    expect(consentJustRecorded).toBe(true);
  });

  it("consented_at is stamped once and never overwritten on re-toggle", async () => {
    const { store } = makeRig();
    const { config: first } = await store.patch({
      enabled: true,
      consented_to_trade_off: true,
    });
    const consentedAt = first.consented_at!;
    // Wait a tick so timestamps would differ if overwritten.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const { config: toggled } = await store.patch({ enabled: false });
    expect(toggled.consented_at).toBe(consentedAt);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const { config: reenabled } = await store.patch({ enabled: true });
    expect(reenabled.consented_at).toBe(consentedAt);
  });

  it("consentJustRecorded fires on exactly the false->true transition only", async () => {
    const { store } = makeRig();
    // First consent: false -> true => signal true.
    const first = await store.patch({ consented_to_trade_off: true });
    expect(first.consentJustRecorded).toBe(true);
    // No-op re-PATCH with consent already true => signal false.
    const reaffirm = await store.patch({ consented_to_trade_off: true });
    expect(reaffirm.consentJustRecorded).toBe(false);
    // Non-consent patch (toggle a different field) => signal false.
    const otherField = await store.patch({ enabled: true });
    expect(otherField.consentJustRecorded).toBe(false);
  });

  it("consentJustRecorded is false on revocation and on non-consent patches", async () => {
    const { store } = makeRig();
    await store.patch({ consented_to_trade_off: true });
    // Revocation true -> false => not a recording event.
    const revoked = await store.patch({ consented_to_trade_off: false });
    expect(revoked.consentJustRecorded).toBe(false);
    expect(revoked.config.consented_to_trade_off).toBe(false);
    // A patch that never mentions consent => signal false.
    const noConsentField = await store.patch({ smart_mode_enabled: false });
    expect(noConsentField.consentJustRecorded).toBe(false);
  });

  it("consentJustRecorded stays deterministic when wall-clock samples differ", async () => {
    // strictlyIncreasingNow guarantees updated_at != consented_at,
    // the exact condition that defeated the old timestamp-equality
    // heuristic. The explicit signal must still report the transition.
    const { store } = makeRig({ now: strictlyIncreasingNow() });
    const result = await store.patch({ consented_to_trade_off: true });
    expect(result.consentJustRecorded).toBe(true);
    expect(result.config.consented_at).toBeDefined();
    // Sanity: the two samples really did diverge (would have broken
    // the legacy comparison).
    expect(result.config.consented_at).not.toBe(result.config.updated_at);
  });

  it("shouldRewrite honors per-query override (true/false/undefined)", async () => {
    const { store } = makeRig();
    await store.patch({ consented_to_trade_off: true, enabled: false });
    expect(await store.shouldRewrite(undefined)).toBe(false);
    expect(await store.shouldRewrite(true)).toBe(true);
    expect(await store.shouldRewrite(false)).toBe(false);
    await store.patch({ enabled: true });
    expect(await store.shouldRewrite(undefined)).toBe(true);
    expect(await store.shouldRewrite(false)).toBe(false);
  });

  it("shouldRewrite(true) without recorded consent throws PiiConsentRequired", async () => {
    const { store } = makeRig();
    await expect(store.shouldRewrite(true)).rejects.toBeInstanceOf(
      PiiConsentRequired,
    );
  });

  it("multi-fortress AAD isolation: fortress A config unreadable from fortress B", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new PiiConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const storeB = new PiiConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_B,
    });
    await storeA.patch({
      enabled: true,
      consented_to_trade_off: true,
    });
    // Fortress B sees its own (empty) default; not fortress A's
    // ciphertext. The store either returns the default (no record) or
    // null (corrupt/wrong-aad); both signal "not fortress A's state".
    const fromB = await storeB.get();
    expect(fromB?.enabled ?? false).toBe(false);
    expect(fromB?.consented_to_trade_off ?? false).toBe(false);
  });

  it("ciphertext does NOT contain plaintext fortress id or enabled value", async () => {
    const { store, storage } = makeRig();
    await store.patch({ enabled: true, consented_to_trade_off: true });
    const raw = await storage.read(TIER_B_NAMESPACE, "config");
    expect(raw).not.toBeNull();
    const asString = Buffer.from(raw!).toString("utf8");
    expect(asString).not.toContain(FORTRESS_A);
    expect(asString).not.toContain("consented_to_trade_off");
    expect(asString).toContain("alg");
  });
});

describe("Rho-2 HTTP routes", () => {
  async function makeServer(rig: ReturnType<typeof makeRig>): Promise<{
    base: string;
    close: () => Promise<void>;
  }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handlePiiRewriteRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          store: rig.store,
          auditLog: rig.auditLog,
          identityId: IDENTITY,
          fortressId: rig.fortressId,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () =>
        new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("GET /api/query-anonymity/pii/config returns the default config initially", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { config: { enabled: boolean; consented_to_trade_off: boolean } };
      };
      expect(body.data.config.enabled).toBe(false);
      expect(body.data.config.consented_to_trade_off).toBe(false);
    } finally {
      await close();
    }
  });

  it("PATCH config refuses enabled=true without consent (409)", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: true }),
      });
      expect(res.status).toBe(409);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("consent_required");
    } finally {
      await close();
    }
  });

  it("PATCH config accepts consent + enable; emits CONSENT_RECORDED + CONFIG_UPDATED audit", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: true,
          consented_to_trade_off: true,
        }),
      });
      expect(res.status).toBe(200);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = audit.entries.map((e) => e.operation);
      expect(ops).toContain(PII_REWRITE_AUDIT_OPS.CONSENT_RECORDED);
      expect(ops).toContain(PII_REWRITE_AUDIT_OPS.CONFIG_UPDATED);
    } finally {
      await close();
    }
  });

  it("emits CONSENT_RECORDED even when the two wall-clock samples differ (audit-completeness race fix)", async () => {
    // Make-or-break: inject a now() that returns DIFFERENT timestamps
    // for the two samples in patch() (updated_at then consented_at).
    // Under the old `consented_at === updated_at` heuristic this
    // mismatch silently dropped the consent audit event. The explicit
    // transition signal must emit it deterministically.
    const rig = makeRig({ now: strictlyIncreasingNow() });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: true,
          consented_to_trade_off: true,
        }),
      });
      expect(res.status).toBe(200);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = audit.entries.map((e) => e.operation);
      // The whole point: the consent event fires despite mismatched
      // timestamps.
      expect(ops).toContain(PII_REWRITE_AUDIT_OPS.CONSENT_RECORDED);
      expect(ops).toContain(PII_REWRITE_AUDIT_OPS.CONFIG_UPDATED);
      // Consent is durably recorded (no regression).
      const config = await rig.store.get();
      expect(config?.consented_at).toBeDefined();
      expect(config?.consented_to_trade_off).toBe(true);
    } finally {
      await close();
    }
  });

  it("does NOT re-emit CONSENT_RECORDED on a no-op re-PATCH where consent was already true", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      // First flip records consent.
      await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consented_to_trade_off: true }),
      });
      // Second PATCH re-affirms consent (already true) + toggles a
      // different field; must NOT produce a second consent event.
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          consented_to_trade_off: true,
          enabled: true,
        }),
      });
      expect(res.status).toBe(200);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const consentEvents = audit.entries.filter(
        (e) => e.operation === PII_REWRITE_AUDIT_OPS.CONSENT_RECORDED,
      );
      expect(consentEvents.length).toBe(1);
    } finally {
      await close();
    }
  });

  it("does NOT emit CONSENT_RECORDED on a non-consent-field patch", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      // smart_mode_enabled=false patch with no consent => 200, no
      // consent event.
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ smart_mode_enabled: false }),
      });
      expect(res.status).toBe(200);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = audit.entries.map((e) => e.operation);
      expect(ops).not.toContain(PII_REWRITE_AUDIT_OPS.CONSENT_RECORDED);
      expect(ops).toContain(PII_REWRITE_AUDIT_OPS.CONFIG_UPDATED);
    } finally {
      await close();
    }
  });

  it("GET /api/query-anonymity/pii/trade-off returns the explainer text", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/trade-off`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: { explainer: string } };
      expect(body.data.explainer).toBe(PII_TRADE_OFF_EXPLAINER);
      expect(body.data.explainer).toContain("Tier B PII rewrite");
      expect(body.data.explainer).toContain("OFF by default");
    } finally {
      await close();
    }
  });

  it("GET config surfaces the true (inactive) effective Tier B state", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          effective_tier_b_enabled: boolean;
          inactive_reason: string | null;
        };
      };
      expect(body.data.effective_tier_b_enabled).toBe(false);
      expect(body.data.inactive_reason).toBe(TIER_B_INACTIVE_REASON);
    } finally {
      await close();
    }
  });

  it("PATCH config does NOT report effective_tier_b_enabled=true while inactive (response body)", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: true,
          consented_to_trade_off: true,
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          config: { enabled: boolean };
          effective_tier_b_enabled: boolean;
          inactive_reason: string | null;
        };
      };
      // The operator's preference is persisted...
      expect(body.data.config.enabled).toBe(true);
      // ...but the surface must NOT claim the protection is active.
      expect(body.data.effective_tier_b_enabled).toBe(false);
      expect(body.data.inactive_reason).toBe(TIER_B_INACTIVE_REASON);
    } finally {
      await close();
    }
  });

  it("PATCH config audit event reports the true (inactive) effective state, not the inert toggle", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: true,
          smart_mode_enabled: true,
          consented_to_trade_off: true,
        }),
      });
      expect(res.status).toBe(200);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const updated = audit.entries.find(
        (e) => e.operation === PII_REWRITE_AUDIT_OPS.CONFIG_UPDATED,
      );
      expect(updated).toBeDefined();
      // Stored preference is recorded honestly...
      expect(updated?.details?.["enabled"]).toBe(true);
      expect(updated?.details?.["smart_mode_enabled"]).toBe(true);
      // ...but the EFFECTIVE state is false (no redactor wired), and the
      // reason is recorded. The old code emitted
      // `enabled || smart_mode_enabled` (would be true) here.
      expect(updated?.details?.["effective_tier_b_enabled"]).toBe(false);
      expect(updated?.details?.["inactive_reason"]).toBe(
        TIER_B_INACTIVE_REASON,
      );
    } finally {
      await close();
    }
  });

  it("POST /api/query-anonymity/pii/rewrite previews regex-only redaction", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${PII_REWRITE_API_PREFIX}/rewrite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "email me at a@b.com" }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          result: {
            rewritten: string;
            redaction_counts: { email: number };
          };
        };
      };
      expect(body.data.result.rewritten).not.toContain("a@b.com");
      expect(body.data.result.redaction_counts.email).toBe(1);
    } finally {
      await close();
    }
  });
});

describe("Rho-2 audit emission helper", () => {
  it("emitPiiRewriteAudit fires PII_REWRITTEN with per-category counts + LLM flags", async () => {
    const rig = makeRig();
    emitPiiRewriteAudit({
      auditLog: rig.auditLog,
      identityId: IDENTITY,
      fortressId: rig.fortressId,
      redactionCounts: {
        email: 1,
        phone: 0,
        ssn: 0,
        ip_address: 0,
        credit_card: 0,
        street_address: 0,
        name: 0,
      },
      llmAssistRan: true,
      llmResidualCount: 2,
      consentedToTradeOff: true,
    });
    const audit = await rig.auditLog.query({ layer: "l2", limit: 50 });
    const entry = audit.entries.find(
      (e) => e.operation === PII_REWRITE_AUDIT_OPS.PII_REWRITTEN,
    );
    expect(entry).toBeDefined();
    expect(entry?.details?.["llm_assist_ran"]).toBe(true);
    expect(entry?.details?.["llm_residual_count"]).toBe(2);
    expect(entry?.details?.["consented_to_trade_off"]).toBe(true);
    expect(
      (entry?.details?.["redaction_counts"] as Record<string, number>).email,
    ).toBe(1);
  });
});

describe("Rho-2 Tier B honesty (never-overclaim)", () => {
  it("explainer carries a not-yet-active notice", () => {
    expect(PII_TRADE_OFF_EXPLAINER).toContain("not yet active");
  });

  it("explainer no longer asserts an active 'never crosses the outbound boundary' protection", () => {
    // The present-tense overclaim ("Your original text never crosses
    // the outbound boundary") must be gone; any boundary language must
    // be future-tense/conditional. Guard against the exact prior copy.
    expect(PII_TRADE_OFF_EXPLAINER).not.toContain(
      "Your original text never crosses the outbound boundary",
    );
    expect(PII_TRADE_OFF_EXPLAINER).not.toContain("never crosses");
  });

  it("explainer describes the protection in the future tense, not as currently-on", () => {
    expect(PII_TRADE_OFF_EXPLAINER).toContain("once active");
    // No present-tense active-protection claim at the top.
    expect(PII_TRADE_OFF_EXPLAINER).not.toContain(
      "scrubs personal information from your queries\nbefore they reach",
    );
  });

  it("effectiveTierBEnabled() is false until the redactor is wired", () => {
    expect(effectiveTierBEnabled()).toBe(false);
  });
});

// Reference imports so the trade-off explainer + default helpers are
// exercised at least once at the type level; both feed runtime tests
// above but TypeScript flags otherwise-unused imports.
void defaultPiiRewriteConfig;
