/** Evaluator projections and a bounded, conservative browser expiry schedule. */
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "./evaluate.js";
import { DISPLAY_PERIOD, LOCAL_JITTER, SCHEDULE_STEPS } from "./constants.js";

type Verdict<S extends string> = { state: S; alarm: boolean; reasons: string[]; cause: string | null };
export interface LivenessVerdicts {
  wall: Verdict<LivenessEnvelope["wall"]["state"]>;
  agent: Verdict<LivenessEnvelope["agent"]["state"]>;
  coverage: Verdict<LivenessEnvelope["coverage"]["state"]>;
  exit_code: number;
}
export interface LivenessScheduleEntry { after_ms: number; projection: LivenessVerdicts }
export interface LivenessProjection extends LivenessVerdicts {
  evaluated_at: string;
  served_age_ms: number;
  schedule: LivenessScheduleEntry[];
}

export function verdicts(envelope: LivenessEnvelope): LivenessVerdicts {
  const component = <S extends string>(v: { state: S; alarm: boolean; reasons: string[]; evidence?: { cause?: string } }): Verdict<S> =>
    ({ state: v.state, alarm: v.alarm, reasons: [...v.reasons], cause: v.evidence?.cause ?? null });
  return { wall: component(envelope.wall), agent: component(envelope.agent), coverage: component(envelope.coverage), exit_code: envelope.exit_code };
}

const components = ["wall", "agent", "coverage"] as const;
type Component = typeof components[number];
/** Higher numbers are more severe, following the evaluator's component precedence. */
function severity(component: Component, state: string): number {
  const orders: Record<Component, readonly string[]> = {
    wall: ["OK", "RECOVERING", "DEGRADED", "TTL_WARNING"],
    agent: ["OK", "RECOVERING", "DEGRADED_STALE_MCP", "INITIALIZING", "DOWN", "UNMONITORED"],
    coverage: ["COMPLETE", "WALL_ONLY", "LEGACY_PARTIAL", "UNAVAILABLE"],
  };
  const name = state.slice(component.length + 1);
  const index = orders[component].indexOf(name.startsWith("OK_") ? "OK" : name);
  return index < 0 ? orders[component].length : index;
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
    // The terminal evaluation is always emitted strictly beyond observer freshness, even without a change.
    if (improved || k === SCHEDULE_STEPS) emit(k * LOCAL_JITTER, next);
    previous = next;
  }
  return entries;
}

/** Must match the interpolation sites in posture-home-html.ts, posture-agent-html.ts and dashboard/v1_1/client.ts, via posture-html-shared.ts. */
export const LIVENESS_SCHEDULE_FN_SOURCE = String.raw`
function createLivenessDisplay(paint) {
  var installed = null, dateAnchor = 0, performanceAnchor = 0, base = 0, elapsed = 0;
  function age() {
    if (!installed) return 0;
    elapsed = Math.max(elapsed, base + Math.max(0, Date.now() - dateAnchor, performance.now() - performanceAnchor));
    return elapsed;
  }
  function render() {
    if (!installed) return;
    var currentAge = age(), selected = installed.schedule[0];
    for (var i = 1; i < installed.schedule.length; i++) {
      if (installed.schedule[i].after_ms <= currentAge) selected = installed.schedule[i];
    }
    paint(selected.projection);
  }
  function install(projection) {
    if (!projection) return;
    // Must match parseEvidenceTimestamp in POSTURE_AUDIT_TIMESTAMP_PARSER_SOURCE in posture-home-types.ts.
    var origin = parseEvidenceTimestamp(projection.evaluated_at);
    if (origin === undefined) return;
    if (installed && origin < parseEvidenceTimestamp(installed.evaluated_at)) return;
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
  return { install: install, render: render };
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
    if (!box) {
      box = document.createElement('section'); box.id = 'castle-wall-liveness';
      box.setAttribute('aria-label', 'Castle Wall liveness'); document.body.appendChild(box);
    }
    box.textContent = ['wall', 'agent', 'coverage'].map(function(component) {
      var verdict = projection[component];
      return component + ': ' + verdict.state + ' (' + verdict.reasons.join(', ') + ')';
    }).join(' | ');
  });
  return display;
}
`;
