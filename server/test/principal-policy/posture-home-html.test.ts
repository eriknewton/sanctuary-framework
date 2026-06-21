import { describe, expect, it } from "vitest";
import {
  custodyPill,
  featureHealthPill,
  queryPrivacyPill,
  renderPostureHomeHTML,
} from "../../src/principal-policy/posture-home-html.js";
import type { FeatureHealthStatus } from "../../src/principal-policy/feature-health.js";
import type { CustodyState } from "../../src/principal-policy/posture.js";

/**
 * Slice 2 of the unified posture dashboard: the feature-health panel is now
 * rendered on Home. These tests pin the #617/#634 honesty contract on the new
 * panel — an "unknown"/"unconfirmed" feature must NEVER render green; green is
 * earned only by "active"; "fault" is red. The contract is enforced both by the
 * pure exported mapper (the canonical definition) and inside the self-contained
 * client-side renderer string (which mirrors it).
 */
describe("posture home — feature-health panel honesty", () => {
  it("featureHealthPill: an unknown/unconfirmed feature never renders green", () => {
    expect(featureHealthPill("unknown").cls).toBe("amber");
    expect(featureHealthPill("unconfirmed").cls).toBe("amber");
    // Neither non-green status may map to the single green class.
    expect(featureHealthPill("unknown").cls).not.toBe("green");
    expect(featureHealthPill("unconfirmed").cls).not.toBe("green");
  });

  it("featureHealthPill: a known-good (active) feature renders its positive green chip", () => {
    const pill = featureHealthPill("active");
    expect(pill.cls).toBe("green");
    expect(pill.label).toBe("active");
  });

  it("featureHealthPill: a fault renders red, never green", () => {
    expect(featureHealthPill("fault").cls).toBe("red");
    expect(featureHealthPill("fault").cls).not.toBe("green");
  });

  it("featureHealthPill: green is reserved exclusively for active across every status", () => {
    const statuses: FeatureHealthStatus[] = [
      "active",
      "fault",
      "unconfirmed",
      "unknown",
    ];
    for (const s of statuses) {
      const isGreen = featureHealthPill(s).cls === "green";
      expect(isGreen).toBe(s === "active");
    }
  });

  it("renders a Security features section on the Home page", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain("Security features");
    expect(html).toContain('id="features"');
    // The panel is fed from the home payload's already-built feature-health
    // panel (no duplicate endpoint logic on the surface).
    expect(html).toContain("renderFeatures(home.feature_health)");
  });

  it("the client-side feature renderer never maps a non-active status to a green pill", () => {
    const html = renderPostureHomeHTML();
    // Isolate the embedded featurePill function source and assert its honest
    // mapping: only "active" produces a green pill; unconfirmed/unknown are amber.
    const start = html.indexOf("function featurePill(status)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 400);
    expect(fnSource).toContain('status === "active") return \'<span class="pill green">');
    // No green branch keyed on unconfirmed or unknown.
    expect(fnSource).not.toMatch(/unconfirmed[^\n]*pill green/);
    expect(fnSource).not.toMatch(/unknown[^\n]*pill green/);
    expect(fnSource).toContain('unconfirmed") return \'<span class="pill amber">');
  });
});

/**
 * Slice 3 of the unified posture dashboard: the Custody and Exit panel. These
 * tests pin the #617 honesty contract on the new tile — custody is GREEN NEVER
 * (custody HEALTH lives under the transient master at boot and is not
 * re-derivable from the dashboard's request-time view), so "unconfirmed" is
 * amber and "damaged" is red, with no green branch. The exit half is the honest
 * CLI-gated export capability with NO clean-exit guarantee claimed.
 */
describe("posture home — Custody and Exit panel honesty", () => {
  it("custodyPill: there is no green branch — unconfirmed is amber, damaged is red", () => {
    expect(custodyPill("unconfirmed").cls).toBe("amber");
    expect(custodyPill("damaged").cls).toBe("red");
    // Neither state may ever map to a green class.
    const states: CustodyState[] = ["unconfirmed", "damaged"];
    for (const s of states) {
      expect(custodyPill(s).cls).not.toBe("green");
    }
  });

  it("renders a Custody and Exit section on the Home page", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain("Custody and Exit");
    expect(html).toContain('id="custody"');
    // Fed from the home payload's already-built custody-exit panel (no duplicate
    // endpoint logic on the surface).
    expect(html).toContain("renderCustodyExit(home.custody_exit)");
  });

  it("the client-side custody renderer never maps any state to a green pill", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function custodyPill(state)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 300);
    // damaged -> red; the default (unconfirmed) -> amber. No green anywhere.
    expect(fnSource).toContain('state === "damaged") return \'<span class="pill red">');
    expect(fnSource).toContain('<span class="pill amber">UNCONFIRMED');
    expect(fnSource).not.toContain("pill green");
  });

  it("surfaces the exit export as a capability WITHOUT claiming a clean-exit guarantee", () => {
    const html = renderPostureHomeHTML();
    // The honest exit affordance: export available, Tier-1 gated. The command
    // string is sourced from the panel at render time; the renderer falls back
    // to the literal `sanctuary exit` verb, which is therefore present statically.
    expect(html).toContain("export available");
    expect(html).toContain("sanctuary exit");
    // It is a Tier-1 (approval-gated) operation, surfaced honestly.
    expect(html).toContain("a Tier-1 operation");
    // And the explicit honesty disclaimer that the full clean-exit guarantee is
    // NOT yet earned (delta review). No "clean exit guaranteed" claim on Home.
    expect(html).toContain("does not yet mean a guaranteed clean exit");
    expect(html.toLowerCase()).not.toContain("clean exit guaranteed");
  });

  it("uses no em-dashes in the rendered Custody and Exit user-facing copy", () => {
    const html = renderPostureHomeHTML();
    // Isolate the custody renderer's user-facing strings region.
    const start = html.indexOf("function renderCustodyExit(panel)");
    const end = html.indexOf("function renderBanner(home");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const region = html.slice(start, end);
    expect(region).not.toContain("—"); // em-dash
  });
});

/**
 * Phase 2 query-privacy section (design 2026-06-19 2.1). Surfaces the Opacity
 * principle from real header-strip evidence. Honesty contract:
 *  - it must NEVER imply anonymity (header stripping is metadata hygiene; the
 *    provider still sees content + the API key);
 *  - Tier A is never green from absence; Tier B PII rewrite is never green from
 *    config (it stays unconfirmed until its emitter is wired).
 */
describe("posture home - Query-privacy section honesty", () => {
  it("queryPrivacyPill: green is reserved exclusively for active", () => {
    const statuses: FeatureHealthStatus[] = [
      "active",
      "fault",
      "unconfirmed",
      "unknown",
    ];
    for (const s of statuses) {
      const isGreen = queryPrivacyPill(s).cls === "green";
      expect(isGreen).toBe(s === "active");
    }
    // unconfirmed/unknown never green (Tier B PII-rewrite stays here).
    expect(queryPrivacyPill("unconfirmed").cls).toBe("amber");
    expect(queryPrivacyPill("unknown").cls).toBe("amber");
  });

  it("renders a Query privacy section on the Home page fed by the home payload", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain("Query privacy");
    expect(html).toContain('id="queryprivacy"');
    expect(html).toContain("renderQueryPrivacy(home.query_privacy)");
  });

  it("the headline is metadata-hygiene, never an anonymity claim", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function renderQueryPrivacy(qp)");
    expect(start).toBeGreaterThan(-1);
    const end = html.indexOf("function renderBanner(home");
    const region = html.slice(start, end);
    // The honest boundary statement is present.
    expect(region).toContain("metadata hygiene, not anonymity");
    expect(region).toContain("still sees the query content");
    expect(region).toContain("does not make");
    // It must NOT make an AFFIRMATIVE anonymity claim. The honest negation
    // ("does not make your queries anonymous") is allowed; the affirmative is not.
    const lower = region.toLowerCase();
    expect(lower).not.toContain("your queries are anonymous");
    expect(lower).not.toContain("queries are anonymous");
    expect(lower).not.toContain("makes your queries anonymous");
    // No em-dash in the user-facing query-privacy copy.
    expect(region).not.toContain("—");
  });

  it("the Tier-A copy distinguishes 'stripped' from 'nothing to strip' from 'no calls' (#617)", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function queryPrivacyWhy(row)");
    expect(start).toBeGreaterThan(-1);
    const end = html.indexOf("function renderQueryPrivacy(qp)");
    const region = html.slice(start, end);
    // Three distinct branches keyed on the honesty discriminator, so a viewer
    // never reads a 0-stripped window as stripping-happened.
    expect(region).toContain('row.tier_a_evidence === "stripped"');
    expect(region).toContain('row.tier_a_evidence === "none_to_strip"');
    // The "calls observed but nothing stripped" copy plainly says NOTHING was
    // stripped - it cannot be misread as the affirmative stripped-headers copy.
    expect(region).toContain("none carried a fingerprintable header to strip");
    expect(region).toContain("nothing was stripped");
    // The affirmative stripped copy stays gated to the "stripped" branch only.
    const strippedIdx = region.indexOf("Fingerprintable headers were stripped");
    const noneIdx = region.indexOf("none carried a fingerprintable header");
    expect(strippedIdx).toBeGreaterThan(-1);
    expect(noneIdx).toBeGreaterThan(-1);
    expect(strippedIdx).not.toBe(noneIdx);
    // No em-dash in the new copy.
    expect(region).not.toContain("—");
  });

  it("the client-side query-privacy pill never maps a non-active status to green", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function queryPrivacyPill(status)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 400);
    expect(fnSource).toContain('status === "active") return \'<span class="pill green">');
    expect(fnSource).not.toMatch(/unconfirmed[^\n]*pill green/);
    expect(fnSource).not.toMatch(/unknown[^\n]*pill green/);
    // The default (covers unconfirmed/unknown, including Tier B) is amber.
    expect(fnSource).toContain('<span class="pill amber">unconfirmed');
  });
});

/**
 * SEC-012 stream handshake (this PR). The posture board's live-refresh SSE
 * stream cannot authenticate in a REMOTE token-hash session (EventSource cannot
 * set an Authorization header, and checkAuth rejects the long-lived ?token= in
 * the URL). The fix reuses the dashboard's EXISTING short-lived session mint
 * (POST /auth/session) and ?session= acceptance: the client exchanges the bearer
 * (in the POST header, never a URL) for a short-lived session id, then connects
 * via ?session=<id>. These tests pin the invariants:
 *  - the mint is performed ONLY for a remote token-hash session (token in hash,
 *    no session cookie); the loopback / cookie path is unchanged (no mint);
 *  - any mint failure / 401 / expiry degrades to honest polling, never blocks;
 *  - the long-lived bearer NEVER appears in any URL (only the Authorization
 *    header of the POST);
 *  - the static page still renders.
 *
 * The client is a self-contained string, so (matching the convention in the
 * panels above) these assert on the embedded source rather than running a DOM.
 */
describe("posture home - SEC-012 SSE ?session= handshake", () => {
  it("the static page still renders (progressive enhancement, never blocked)", () => {
    const html = renderPostureHomeHTML();
    expect(html.length).toBeGreaterThan(0);
    // The boot path still renders once and only attaches the stream as an
    // enhancement (poll-only fallback survives if SSE is unavailable).
    expect(html).toContain("function connectStream()");
    expect(html).toContain("function pollOnce()");
  });

  it("reuses the EXISTING POST /auth/session mint with the bearer in the header, never a URL", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function mintStreamSession()");
    expect(start).toBeGreaterThan(-1);
    const end = html.indexOf("function esc(");
    expect(end).toBeGreaterThan(start);
    const fn = html.slice(start, end);
    // The existing mint endpoint and method.
    expect(fn).toContain('fetch("/auth/session", {');
    expect(fn).toContain('method: "POST"');
    // The long-lived bearer travels in the Authorization header of the POST,
    // NOT in any URL (SEC-012).
    expect(fn).toContain('"Authorization": "Bearer " + token');
    // It consumes the existing response shape and emits a ?session= query.
    expect(fn).toContain("body.session_id");
    expect(fn).toContain('"?session=" + encodeURIComponent(body.session_id)');
  });

  it("mints ONLY for a remote token-hash session - no token or a session cookie means no mint (loopback/cookie path unchanged)", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function mintStreamSession()");
    const end = html.indexOf("function esc(");
    const fn = html.slice(start, end);
    // The guard: no bearer token in the hash, OR a session cookie already
    // authorizes -> resolve "" and attempt NO mint. This is what keeps the
    // loopback / cookie path byte-for-byte unchanged.
    expect(fn).toContain("if (!token || hasSessionCookie()) return Promise.resolve");
    // The cookie probe looks for the EXISTING sanctuary_session cookie name.
    const cookieStart = html.indexOf("function hasSessionCookie()");
    expect(cookieStart).toBeGreaterThan(-1);
    const cookieFn = html.slice(cookieStart, cookieStart + 260);
    expect(cookieFn).toContain("sanctuary_session=");
    expect(cookieFn).toContain("document.cookie");
  });

  it("connects the stream via ?session=<id> when one was minted, and never appends the long-lived token to the stream URL", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function connectStream()");
    expect(start).toBeGreaterThan(-1);
    const end = html.indexOf("function wireStream()");
    expect(end).toBeGreaterThan(start);
    const fn = html.slice(start, end);
    // The handshake runs first; the minted ?session= query is appended to the
    // stream URL (empty string when no mint, so the bare URL is unchanged).
    expect(fn).toContain("mintStreamSession().then(function (sessionQuery)");
    expect(fn).toContain('"/api/posture/stream" + (sessionQuery || "")');
    expect(fn).toContain("new EventSource(url, { withCredentials: true })");
    // The long-lived token is NEVER placed on the stream URL anywhere on the page.
    expect(html).not.toMatch(/posture\/stream[^"]*token=/);
    // And no ?token= query is ever constructed for any stream URL.
    expect(html).not.toContain('"/api/posture/stream?token=');
  });

  it("degrades to honest polling on mint failure / 401 / expiry - the mint never throws and reconnect re-mints", () => {
    const html = renderPostureHomeHTML();
    const mStart = html.indexOf("function mintStreamSession()");
    const mEnd = html.indexOf("function esc(");
    const mintFn = html.slice(mStart, mEnd);
    // A non-ok mint response (e.g. 401) resolves to "" rather than throwing, so
    // the caller falls through to opening the bare stream and the existing
    // onerror -> scheduleReconnect -> startPolling path keeps the board honest.
    expect(mintFn).toContain("if (!r.ok) return");
    // Both the network-reject and json-parse-reject branches resolve to "".
    expect(mintFn).toContain('function () { return ""; }');
    // The reconnect path keeps polling while disconnected (honest staleness) and
    // re-enters connectStream (which re-mints), handling session expiry.
    const sStart = html.indexOf("function scheduleReconnect()");
    expect(sStart).toBeGreaterThan(-1);
    const sEnd = html.indexOf("function connectStream()");
    expect(sEnd).toBeGreaterThan(sStart);
    const sFn = html.slice(sStart, sEnd);
    expect(sFn).toContain("startPolling()");
    expect(sFn).toContain("connectStream()");
  });

  it("uses no em-dashes in the handshake client source", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function hasSessionCookie()");
    const end = html.indexOf("function esc(");
    const region = html.slice(start, end);
    expect(region).not.toContain("—");
  });
});

describe("posture home - folded approval controls", () => {
  type ApprovalState = {
    rows: Array<{
      source: string;
      approve_path: string;
      deny_path: string;
      review_href: string;
    }>;
    can_decide: boolean;
    mode: string;
  };
  type ApprovalHelpers = {
    buildApprovalState: (
      legacyBody: unknown,
      inboxBody: unknown,
      status: unknown,
    ) => ApprovalState;
  };

  function approvalHelpers(): ApprovalHelpers {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function normalizeLegacyApproval");
    const end = html.indexOf("function renderApprovals");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const source =
      html.slice(start, end) +
      "\nreturn { buildApprovalState: buildApprovalState };";
    // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
    return new Function(source)() as ApprovalHelpers;
  }

  it("refreshes both approval read models plus status before rendering", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function refreshAuxiliary()");
    expect(start).toBeGreaterThan(-1);
    const region = html.slice(start, start + 700);
    expect(region).toContain('api("/api/pending")');
    expect(region).toContain('api("/api/approval-inbox?status=pending")');
    expect(region).toContain('api("/api/status")');
    expect(region).toContain("buildApprovalState(rest[0], rest[1], rest[2])");
  });

  it("default co-located mode renders decision routes against the legacy pending inbox", () => {
    const helpers = approvalHelpers();
    const state = helpers.buildApprovalState(
      [{ id: "legacy-1", operation: "state_export", tier: 1 }],
      {
        data: {
          entries: [
            {
              aggregator_id: "agg-1",
              action_summary: "state export",
              source_harness: "claude-code",
            },
          ],
        },
      },
      {
        standalone_mode: false,
        decision_capable: true,
        policy: { approval_redirect: { enabled: false, mode: "replace" } },
      },
    );
    expect(state.can_decide).toBe(true);
    expect(state.mode).toBe("co-located");
    expect(state.rows).toHaveLength(1);
    expect(state.rows[0]!.source).toBe("legacy");
    expect(state.rows[0]!.approve_path).toBe("/api/approve/legacy-1");
    expect(state.rows[0]!.deny_path).toBe("/api/deny/legacy-1");
  });

  it("replace mode renders decision routes against the approval inbox", () => {
    const helpers = approvalHelpers();
    const state = helpers.buildApprovalState(
      [{ id: "legacy-should-not-win", operation: "state_export", tier: 1 }],
      {
        data: {
          entries: [
            {
              aggregator_id: "agg-1",
              action_summary: "state export",
              source_harness: "claude-code",
            },
          ],
        },
      },
      {
        standalone_mode: false,
        decision_capable: true,
        policy: { approval_redirect: { enabled: true, mode: "replace" } },
      },
    );
    expect(state.can_decide).toBe(true);
    expect(state.rows).toHaveLength(1);
    expect(state.rows[0]!.source).toBe("approval-inbox");
    expect(state.rows[0]!.approve_path).toBe("/api/approval-inbox/agg-1/approve");
    expect(state.rows[0]!.deny_path).toBe("/api/approval-inbox/agg-1/deny");
  });

  it("standalone mode keeps the approval section read-only", () => {
    const helpers = approvalHelpers();
    const state = helpers.buildApprovalState(
      [{ id: "legacy-1", operation: "state_export", tier: 1 }],
      { data: { entries: [] } },
      {
        standalone_mode: true,
        decision_capable: false,
        policy: { approval_redirect: { enabled: false, mode: "replace" } },
      },
    );
    expect(state.mode).toBe("standalone");
    expect(state.can_decide).toBe(false);

    const html = renderPostureHomeHTML();
    const start = html.indexOf("function renderApprovals(approvalState)");
    const end = html.indexOf("function wireApprovalButtons");
    const region = html.slice(start, end);
    expect(region).toContain("approvalState && approvalState.can_decide");
    expect(html).toContain("status.decision_capable === true");
    expect(region).toContain("review &rarr;");
  });

  it("decision POSTs prefer the bearer header and retry once after a 401 prompt", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function decisionHeaders()");
    const end = html.indexOf("// SEC-012 stream handshake");
    const region = html.slice(start, end);
    expect(region).toContain('method: "POST"');
    expect(region).toContain('credentials: "same-origin"');
    expect(region).toContain('headers["Authorization"] = "Bearer " + token');
    expect(region).toContain("r.status === 401 && !retried");
    expect(region).toContain("promptForToken()");
    expect(region).toContain("return postDecision(path, true)");
  });
});

/**
 * Recognition + portability panel (P5) renderer honesty. The panel is the most
 * impartiality-loaded surface: these assert the rendered HTML/source honors the
 * contract — the panel is hidden until the composition gate is confirmed, it
 * never fetches a vendor score, and counterparty verification is labeled local
 * bridge crypto. The client is a self-contained string, so (per the convention
 * above) we assert on the embedded source rather than running a DOM.
 */
describe("posture home - Recognition panel (P5) impartiality", () => {
  it("renders the Recognition section hidden by default (absent until composition gate confirmed)", () => {
    const html = renderPostureHomeHTML();
    expect(html).toContain('id="recognition-section"');
    // The section markup carries display:none so the panel is absent (never a
    // greyed shell) until /api/posture/recognition returns 200.
    const idx = html.indexOf('id="recognition-section"');
    const sectionTag = html.slice(idx - 40, idx + 60);
    expect(sectionTag).toContain('style="display:none"');
  });

  it("reveals the section only on a 200 and hides it on any error (404 = composition off)", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function loadRecognition(attempt)");
    const end = html.indexOf("function loadRecognitionOnce()");
    const region = html.slice(start, end);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    // On success the section is revealed; on catch it is hidden (absent).
    expect(region).toContain('section.style.display = ""');
    expect(region).toContain('section.style.display = "none"');
    expect(region).toContain("/api/posture/recognition");
  });

  it("retries on a locked (503) first response so the panel appears after unlock, but a 404 (composition off) is a permanent absence (#651)", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function loadRecognition(attempt)");
    const end = html.indexOf("function loadRecognitionOnce()");
    const region = html.slice(start, end);
    expect(start).toBeGreaterThan(-1);
    // A 404 stops retrying (composition off is a config fact, not a transient
    // lock): the catch returns early on a 404.
    expect(region).toMatch(/404\$/);
    expect(region).toContain("return;");
    // Any non-404 error schedules a retry via setTimeout + backoff so a locked /
    // booting fortress recovers the panel after unlock. The first one-shot fetch
    // alone would have left the panel hidden forever.
    expect(region).toContain("setTimeout(");
    expect(region).toContain("loadRecognition(");
    // The retry never renders a greyed shell while waiting: the section stays
    // display:none until a 200, so there is exactly one reveal path.
    expect(region).toContain('section.style.display = "none"');
  });

  it("never fetches a vendor reputation score: no score-fetch path in the page source", () => {
    const html = renderPostureHomeHTML();
    // There is no Verascore (or any vendor) score-fetch URL anywhere in the page.
    expect(html).not.toContain("verascore.ai/api");
    expect(html).not.toContain("api.verascore");
    expect(html).not.toMatch(/fetch\([^)]*score/i);
  });

  it("labels counterparty verification as LOCAL bridge crypto, never 'by Concordia/Verascore'", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function renderRecognition");
    const end = html.indexOf("function loadRecognitionOnce");
    const region = html.slice(start, end);
    expect(region).toContain("local_bridge_crypto");
    expect(region).toContain("verified locally");
    expect(region.toLowerCase()).not.toContain("verified by concordia");
    expect(region.toLowerCase()).not.toContain("verified by verascore");
  });

  it("never-fake-green: the reputation pill is amber unless evidence is present", () => {
    const html = renderPostureHomeHTML();
    const start = html.indexOf("function recognitionRepPill");
    const end = html.indexOf("function renderRecognition");
    const region = html.slice(start, end);
    // Green is returned ONLY for "present"; everything else is amber.
    expect(region).toContain('"present"');
    expect(region).toContain('pill green');
    expect(region).toContain('pill amber');
    // The amber "no evidence yet" copy must be the default branch.
    expect(region).toContain("no evidence yet");
    // NEGATIVE GUARD (#651 LOW): green must bind STRICTLY to the "present" state.
    // Mirror featureHealthPill's guards: no branch keyed on a non-present state
    // (the "red" branch, or the default "no evidence yet" branch) may emit a
    // green pill. The `[^\n]*` keeps the match on a single source line so a green
    // branch elsewhere cannot satisfy it. This turns the weak presence check into
    // a real never-fake-green assertion: a future edit that returns green for
    // "red" or for the amber default would fail here.
    expect(region).not.toMatch(/"red"[^\n]*pill green/);
    expect(region).not.toMatch(/no evidence yet[^\n]*pill green/);
    // The green pill line is the "present" line: assert green is co-located with
    // the present state, never with another state token on its line.
    expect(region).toMatch(/"present"[^\n]*pill green/);
  });
});
