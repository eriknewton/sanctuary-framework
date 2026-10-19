import type { Page } from "@playwright/test";
import { expect } from "./fixtures/dashboard.js";

// Design r3's desktop, stacked and narrow feedback configurations.
export const FEEDBACK_VIEWPORTS = {
  D: { width: 1440, height: 900 },
  S: { width: 1399, height: 900 },
  N: { width: 375, height: 667 },
};
export const TOAST_LIFETIME_MS = 4 * 1000;
// Two controlled frames deliver MutationObserver and ResizeObserver samples.
export const SETTLE_FRAMES_MS = 2 * Math.ceil(1000 / 60);
const FIXTURE_TIME = "2026-10-19T12:00:00.000Z";
const held = (id: string, tier = "tier2") => ({
  item_id: id, kind: "approval_pending", tier, agent_id: "fixture-agent",
  display_template_id: `approval_pending.${tier}.other`,
  display_template_args: [{ kind: "agent_id", value: "fixture-agent" }],
  resolved: false, created_at: FIXTURE_TIME, identity_id: "operator-e2e", operation_category: "state_export",
});

/** Boot the shipping shell with local reads and a refused decision to retain in F. */
export async function prepareFeedback(page: Page, url: string, routeName: string) {
  const requests: string[] = [];
  await page.clock.install({ time: new Date(FIXTURE_TIME) });
  await page.clock.pauseAt(new Date(FIXTURE_TIME));
  // Expose existing feedback entry points only. No layout, lock, node registry or
  // activation implementation is supplied by the harness. Result setup uses a
  // real POST below; message variation calls the shipping feedback patcher.
  await page.route(url + "/", async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace('void loadPanel(panelJobs[0]);', `
      window.feedbackDriver = {
        toast,
        locked: () => decisionInFlight(),
        // One hundred sentences overflow the six-line F even at desktop width.
        varyResult() {
          state.approvals.result.message = "Retained feedback. ".repeat(100);
          renderFeedback();
        }
      };
      void loadPanel(panelJobs[0]);`);
    await route.fulfill({ response, body: html });
  });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    requests.push(route.request().method() + " " + path);
    if (path === "/api/stream") {
      // Hold this read without frames until page teardown cancels it. Ending an
      // SSE response would schedule a separate reconnect/read transition.
      return;
    }
    if (route.request().method() === "POST") {
      await route.fulfill({ status: 409, json: { error: "Fixture refusal" } });
      return;
    }
    const items = [held("seed"), held("later"), held("armed", "tier1")];
    const data = path === "/api/hub/inbox" ? { data: { items } }
      : path === "/api/posture/home" ? { origin_machine: "fixture", agents: [], castle_wall: { arm_state: "unknown" }, digest: {} }
      : path === "/api/posture/evidence" ? { origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } }
      : path === "/api/policy/current" ? { data: { view: { lines: [] } } }
      : { data: { configured: false, agents: [], items: [], entries: [], findings: [], messages: [], policies: [], rules: [], recommendations: [] } };
    await route.fulfill({ json: data });
  });
  await page.goto(url + "/#" + routeName);
  const seed = page.locator('[data-action="inbox-approve"][data-item-id="seed"]').first();
  await expect(seed).toBeEnabled();
  await seed.click();
  await expect(page.locator('#feedback [data-decision-status="refused"]')).toContainText("Fixture refusal");
  await expect(page.locator('[data-action="decision-result-clear"]')).toBeEnabled();
  await page.evaluate("document.fonts.ready");
  await page.clock.runFor(SETTLE_FRAMES_MS);
  return requests;
}

/** Record every existing main element, its ancestors and predecessors, not just a hand-picked control. */
export async function recordFeedbackBaseline(page: Page, controlSelector: string, bottom: boolean) {
  expect(await page.evaluate("['static', 'relative'].includes(getComputedStyle(document.getElementById('feedback')).position)"), "F stays in flow").toBe(true);
  expect(await page.locator('#main #feedback').count(), "F is outside the route body").toBe(0);
  await page.locator(controlSelector).scrollIntoViewIfNeeded();
  if (bottom) await page.evaluate("document.getElementById('main').scrollTop = document.getElementById('main').scrollHeight");
  await page.clock.runFor(SETTLE_FRAMES_MS);
  await page.evaluate(`(() => {
    const main = document.getElementById('main');
    const feedback = document.getElementById('feedback');
    const control = document.querySelector(${JSON.stringify(controlSelector)});
    const app = document.getElementById('app');
    const nodes = [...new Set([document.documentElement, document.body, app,
      ...app.querySelectorAll('*')])].filter(n => n === feedback || !feedback.contains(n));
    const rect = n => {
      const r = n.getBoundingClientRect();
      let sx = 0, sy = 0;
      for (let a = n.parentElement; a; a = a.parentElement) { sx += a.scrollLeft; sy += a.scrollTop; }
      return [r.x, r.y, r.width, r.height, r.x + sx, r.y + sy];
    };
    const scroll = n => [n.scrollLeft, n.scrollTop, n.scrollWidth, n.scrollHeight, n.clientWidth, n.clientHeight];
    const baseline = nodes.map(n => ({ n, rect: rect(n), scroll: scroll(n),
      action: n.getAttribute('data-action'), subject: n.getAttribute('data-item-id'), disabled: n.disabled }));
    const failures = [];
    let samples = 0, mutations = 0;
    function sample() {
      samples++;
      if (feedbackDriver.locked()) failures.push('decision lock changed');
      for (const b of baseline) {
        const label = b.n.id || b.action || b.n.tagName;
        if (!b.n.isConnected) { failures.push(label + ': node replaced'); continue; }
        if (b.action !== b.n.getAttribute('data-action') || b.subject !== b.n.getAttribute('data-item-id') || b.disabled !== b.n.disabled)
          failures.push(label + ': identity or eligibility changed');
        const r = rect(b.n);
        if (r.some((v, i) => Math.abs(v - b.rect[i]) > 1)) failures.push(label + ': rectangle changed');
        // F owns its content extent and scroll position; main and all ancestors do not.
        if (b.n !== feedback && scroll(b.n).some((v, i) => Math.abs(v - b.scroll[i]) > 1)) failures.push(label + ': scroll changed');
      }
      const c = control.getBoundingClientRect(), f = feedback.getBoundingClientRect(), m = main.getBoundingClientRect();
      if (c.bottom > f.top + 1) failures.push('control intersects F');
      if (c.top < m.top - 1 || c.bottom > m.bottom + 1 || c.left < m.left - 1 || c.right > m.right + 1)
        failures.push('target is not fully visible in main');
      if (document.elementFromPoint(c.x + c.width / 2, c.y + c.height / 2) !== control)
        failures.push('target hit test changed');
    }
    const mo = new MutationObserver(records => {
      mutations += records.filter(r => !feedback.contains(r.target) || (r.target === feedback && r.type === 'attributes')).length;
      sample();
    });
    mo.observe(app, { subtree: true, childList: true, attributes: true, characterData: true });
    const fm = new MutationObserver(sample);
    fm.observe(feedback, { subtree: true, childList: true, attributes: true, characterData: true });
    const ro = new ResizeObserver(sample);
    nodes.forEach(n => ro.observe(n));
    // Freeze user scroll input without changing CSS overflow or content geometry.
    main.addEventListener('wheel', e => e.preventDefault(), { passive: false });
    main.addEventListener('touchmove', e => e.preventDefault(), { passive: false });
    main.addEventListener('keydown', e => {
      if (['PageUp', 'PageDown', 'Home', 'End', 'ArrowUp', 'ArrowDown', ' '].includes(e.key)) e.preventDefault();
    });
    window.feedbackRecord = { sample, failures, stats: () => ({ samples, mutations }) };
    sample();
  })()`);
}

/** One baseline, one CSS pixel tolerance; every observer sample must agree. */
export async function assertFeedbackIsolation(page: Page, witness: string) {
  await page.clock.runFor(SETTLE_FRAMES_MS);
  const result = await page.evaluate<{ failures: string[]; stats: { samples: number; mutations: number } }>(`(() => {
    feedbackRecord.sample();
    return { failures: [...new Set(feedbackRecord.failures)], stats: feedbackRecord.stats() };
  })()`);
  expect(result.failures, witness + ': feedback preserves main geometry, offsets, identity, eligibility and hit target').toEqual([]);
  expect(result.stats.mutations, witness + ': changes only F interior').toBe(0);
  expect(result.stats.samples, witness + ': observers sampled the transition').toBeGreaterThan(1);
}
