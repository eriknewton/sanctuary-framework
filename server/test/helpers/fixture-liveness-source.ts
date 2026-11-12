import { evaluateLiveness, type LivenessInput } from "../../src/castle-wall/liveness/evaluate.js";
import { project, type LivenessSurfaceSource } from "../../src/castle-wall/liveness/surface-reader.js";

// Root uid is a synthetic fixture identity, never a host account lookup.
const FIXTURE_OPERATOR_UID = 0;

export function createFixtureLivenessSource(): Pick<LivenessSurfaceSource, "readProjection"> {
  return { readProjection: async () => {
    const input: LivenessInput = {
      nowMs: Date.now(), platform: "darwin",
      host: { ok: false },
      local: { fortress_id: "fixture-fortress", platform: "darwin", operator_uid: FIXTURE_OPERATOR_UID },
      // Audit-panel fixtures supply no liveness records; their audit verdicts cannot prove live enforcement.
      directory: { status: "absent" }, daemon: { status: "absent" },
      observer: { status: "absent" }, config: { status: "absent" },
    };
    return project(evaluateLiveness(input), input, input.nowMs);
  } };
}
