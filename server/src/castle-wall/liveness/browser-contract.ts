/** Evaluator projections and a bounded, conservative browser expiry schedule. */
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "./evaluate.js";
import { LIVENESS_STATES, DISPLAY_PERIOD, LOCAL_JITTER, SCHEDULE_STEPS, LIVENESS_SEVERITY_ORDER, type LivenessVerdicts } from "./constants.js";

export type { LivenessVerdicts } from "./constants.js";
export interface LivenessScheduleEntry { after_ms: number; projection: LivenessVerdicts }
export interface LivenessProjection extends LivenessVerdicts {
  evaluated_at: string;
  served_age_ms: number;
  schedule: LivenessScheduleEntry[];
}

export function verdicts(envelope: LivenessEnvelope): LivenessVerdicts {
  const component = <S extends string>(v: { state: S; alarm: boolean; reasons: string[]; evidence?: { cause?: string } }) =>
    ({ state: v.state, alarm: v.alarm, reasons: [...v.reasons], cause: v.evidence?.cause ?? null });
  return { wall: component(envelope.wall), agent: component(envelope.agent), coverage: component(envelope.coverage), exit_code: envelope.exit_code };
}

const components = ["wall", "agent", "coverage"] as const;
type Component = typeof components[number];
/** Higher numbers are more severe, following the evaluator's component precedence. */
function severity(component: Component, state: string): number {
  const name = state.slice(component.length + 1);
  const index = LIVENESS_SEVERITY_ORDER[component].indexOf(name.startsWith("OK_") ? "OK" : name);
  // An unlisted state ranks as the most severe class, so unknown states cannot improve a verdict.
  return index < 0 ? LIVENESS_SEVERITY_ORDER[component].length : index;
}

function compare(component: Component, next: LivenessVerdicts, previous: LivenessVerdicts): number {
  const a = next[component], b = previous[component];
  if (a.alarm !== b.alarm) return a.alarm ? 1 : -1;
  return severity(component, a.state) - severity(component, b.state);
}
function replace(target: LivenessVerdicts, source: LivenessVerdicts, component: Component): void {
  // The entire verdict travels together; the wall's exit must describe that same evaluation.
  Object.assign(target, { [component]: source[component] });
  if (component === "wall") target.exit_code = source.exit_code;
}

export function buildLivenessSchedule(input: LivenessInput): LivenessScheduleEntry[] {
  const at = (offset: number) => verdicts(evaluateLiveness({ ...input, nowMs: input.nowMs + offset,
    host: input.host.ok ? { ...input.host, uptimeMs: input.host.uptimeMs + offset } : input.host }));
  let previous = at(0);
  const entries: LivenessScheduleEntry[] = [{ after_ms: 0, projection: previous }];
  function emit(after_ms: number, projection: LivenessVerdicts): void {
    const last = entries[entries.length - 1]!;
    if (last.after_ms !== after_ms) { entries.push({ after_ms, projection }); return; }
    const merged = { ...last.projection };
    for (const component of components) {
      // A collision keeps the more severe complete verdict, including a newly selected equal-severity worsening.
      if (compare(component, projection, merged) >= 0) replace(merged, projection, component);
    }
    last.projection = merged;
  }
  for (let k = 1; k <= SCHEDULE_STEPS; k++) {
    const next = at(k * LOCAL_JITTER);
    const early = { ...previous };
    let worsened = false, improved = false;
    for (const component of components) {
      if (JSON.stringify(next[component]) === JSON.stringify(previous[component])) continue;
      // Worsenings are placed early and improvements late, independently for each component.
      if (compare(component, next, previous) < 0) improved = true;
      else { worsened = true; replace(early, next, component); }
    }
    if (worsened) emit((k - 1) * LOCAL_JITTER, early);
    // Must match createLivenessDisplay terminal validation below: beyond observer freshness, neither component is OK and coverage is UNAVAILABLE.
    if (improved || k === SCHEDULE_STEPS) emit(k * LOCAL_JITTER, next);
    previous = next;
  }
  return entries;
}

/** Must match the interpolation sites in posture-home-html.ts, posture-agent-html.ts and dashboard/v1_1/client.ts, via posture-html-shared.ts. */
export const LIVENESS_SCHEDULE_FN_SOURCE = String.raw`
function createLivenessDisplay(paint) {
  var invalid = false;
  // observation_invalid is a browser-only refusal reason, not an evaluator registry reason.
  var fallback = { wall: { state: "wall_DOWN", alarm: true, reasons: ["observation_invalid"], cause: null },
    agent: { state: "agent_DOWN", alarm: true, reasons: ["observation_invalid"], cause: null },
    coverage: { state: "coverage_UNAVAILABLE", alarm: true, reasons: ["observation_invalid"], cause: null }, exit_code: 1 };
  var installed = null, dateAnchor = 0, performanceAnchor = 0, base = 0, elapsed = 0;
  function age() {
    if (!installed) return 0;
    elapsed = Math.max(elapsed, base + Math.max(0, Date.now() - dateAnchor, performance.now() - performanceAnchor));
    return elapsed;
  }
  function render() {
    if (invalid) { paint(fallback); return; }
    if (!installed) return;
    var currentAge = age(), selected = installed.schedule[0];
    for (var i = 1; i < installed.schedule.length; i++) {
      if (installed.schedule[i].after_ms <= currentAge) selected = installed.schedule[i];
    }
    paint(selected.projection);
  }
  // Must match LIVENESS_STATES in constants.ts; only closed component states can reach a paint.
  var states = ${JSON.stringify(LIVENESS_STATES)};
  function validVerdicts(value) {
    return value && Number.isInteger(value.exit_code) && ['wall', 'agent', 'coverage'].every(function(component) {
      var verdict = value[component];
      return verdict && typeof verdict.state === 'string' && states[component].includes(verdict.state) &&
        typeof verdict.alarm === 'boolean' && Array.isArray(verdict.reasons) &&
        verdict.reasons.every(function(reason) { return typeof reason === 'string'; }) &&
        (verdict.cause === null || typeof verdict.cause === 'string');
    });
  }
  function refuse() { invalid = true; render(); }
  function install(projection) {
    // Must match buildLivenessSchedule terminal emission above: neither component is OK and coverage is UNAVAILABLE.
    // Invalid age, shape or unknown state must never leave a healthy first entry painted indefinitely.
    var origin = projection && parseEvidenceTimestamp(projection.evaluated_at);
    if (!projection || !Number.isFinite(projection.served_age_ms) || projection.served_age_ms < 0 ||
        origin === undefined || !validVerdicts(projection) || !Array.isArray(projection.schedule) ||
        projection.schedule.length === 0 || projection.schedule.length > ${2 * SCHEDULE_STEPS + 1} ||
        !projection.schedule.every(function(entry, index, entries) {
          return entry && Number.isFinite(entry.after_ms) && entry.after_ms >= 0 &&
            (index === 0 ? entry.after_ms === 0 : entry.after_ms > entries[index - 1].after_ms) && validVerdicts(entry.projection);
        }) || projection.schedule[projection.schedule.length - 1].after_ms !== ${SCHEDULE_STEPS * LOCAL_JITTER} ||
        projection.schedule[projection.schedule.length - 1].projection.wall.state.indexOf('wall_OK_') === 0 ||
        projection.schedule[projection.schedule.length - 1].projection.agent.state.indexOf('agent_OK_') === 0 ||
        projection.schedule[projection.schedule.length - 1].projection.coverage.state !== 'coverage_UNAVAILABLE') { refuse(); return; }
    // Must match parseEvidenceTimestamp in POSTURE_AUDIT_TIMESTAMP_PARSER_SOURCE in posture-home-types.ts.
    if (installed && origin < parseEvidenceTimestamp(installed.evaluated_at)) return;
    invalid = false;
    if (!installed || origin > parseEvidenceTimestamp(installed.evaluated_at)) {
      installed = projection;
      // Served age belongs to this evaluation; receiving the same evaluation cannot renew it.
      base = elapsed = Math.max(0, projection.served_age_ms);
      dateAnchor = Date.now(); performanceAnchor = performance.now();
    } else if (projection.served_age_ms > age()) {
      base = elapsed = projection.served_age_ms;
      dateAnchor = Date.now(); performanceAnchor = performance.now();
    }
    render();
  }
  return { install: install, render: render, refuse: refuse };
}
function mountLivenessDisplay() {
  var observing = false;
  var display = createLivenessDisplay(function(projection) {
    // No repaint work exists before evidence arrives; one accepted projection starts the display's lifetime.
    if (!observing) {
      observing = true;
      setInterval(display.render, ${DISPLAY_PERIOD});
      document.addEventListener('visibilitychange', display.render);
    }
    var box = document.getElementById('castle-wall-liveness');
    if (box) box.innerHTML = renderLivenessBadges(projection);
  });
  return display;
}
`;
