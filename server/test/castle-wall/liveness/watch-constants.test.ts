/** The observer's derived constants and the installer exit set, asserted against their derivations and the help text. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ACCOUNT_NAME_MAX,
  AGENT_WINDOW_MAX,
  CENSUS_CHILDREN,
  CENSUS_PAIR_MAX,
  CENSUS_PAIR_MIN,
  CENSUS_REREAD,
  CENSUS_RUN,
  CENSUS_SAMPLES_MAX,
  CHILD_READ_DEADLINE,
  COLLECT_DEADLINE,
  KILL_REAP_GRACE,
  LIVENESS_EXIT_DOWN,
  LIVENESS_EXIT_OK,
  LIVENESS_EXIT_USAGE,
  LIVENESS_EXIT_WARNING,
  LIVENESS_STATUS_INTERNAL_EXIT_CODE,
  MAX_COLLECTION_CHILDREN,
  OBSERVER_CYCLE_CHILD_SET,
  OBSERVER_CYCLE_CHILDREN,
  PROCESS_READ_DEADLINE,
  TERM_GRACE,
} from "../../../src/castle-wall/liveness/constants.js";
import { CENSUS_RETENTION_SPAN_HOLDS } from "../../../src/castle-wall/liveness/census-sampler.js";
import { CANARY_PLIST_BYTES, generateCanaryPlist } from "../../../src/castle-wall/liveness/launchd-plists.js";
import { FULL_AGENT_ROLLBACK_INCOMPLETE_EXIT_CODE } from "../../../src/cli/castle-wall-full-agent.js";
import {
  STABLE_RUNTIME_REFUSAL_EXIT_CODE,
  WATCH_EXIT_CANARY_PENDING,
  WATCH_EXIT_CANARY_STILL_INSTALLED,
  WATCH_EXIT_FAILED,
  WATCH_EXIT_INSTALLED,
  WATCH_EXIT_ROLLBACK_INCOMPLETE,
  WATCH_EXIT_USAGE,
} from "../../../src/cli/castle-wall-watch.js";

describe("derived constants", () => {
  it("CENSUS_REREAD, CHILD_READ_DEADLINE and MAX_COLLECTION_CHILDREN equal their derivations", () => {
    expect(CENSUS_REREAD).toBe(TERM_GRACE + KILL_REAP_GRACE);
    expect(CHILD_READ_DEADLINE).toBe(COLLECT_DEADLINE - TERM_GRACE - KILL_REAP_GRACE);
    expect([...OBSERVER_CYCLE_CHILD_SET]).toEqual(["full_agent_print", "canary_print", "harness_print", "ps", "id_chain", "sysctl"]);
    expect(OBSERVER_CYCLE_CHILDREN).toBe(OBSERVER_CYCLE_CHILD_SET.length);
    expect(CENSUS_CHILDREN).toBe(1);
    expect(MAX_COLLECTION_CHILDREN).toBe(OBSERVER_CYCLE_CHILD_SET.length + 1);
  });

  it("fits two process reads, the pause and one termination inside one cycle deadline", () => {
    expect(2 * PROCESS_READ_DEADLINE + CENSUS_REREAD + TERM_GRACE + KILL_REAP_GRACE).toBeLessThanOrEqual(COLLECT_DEADLINE);
    expect(CHILD_READ_DEADLINE).toBeGreaterThan(0);
  });

  it("a full census series spans more than any agent window plus one run", () => {
    expect((CENSUS_SAMPLES_MAX - 1) * CENSUS_PAIR_MIN).toBeGreaterThan(AGENT_WINDOW_MAX + CENSUS_RUN * CENSUS_PAIR_MAX);
    expect(CENSUS_RETENTION_SPAN_HOLDS).toBe(true);
  });

  it("CANARY_PLIST_BYTES equals the generated size for the longest valid account name", () => {
    expect(CANARY_PLIST_BYTES).toBe(Buffer.byteLength(generateCanaryPlist("z".repeat(ACCOUNT_NAME_MAX))));
    expect(() => generateCanaryPlist("z".repeat(ACCOUNT_NAME_MAX + 1))).toThrow();
  });
});

describe("installer exit set", () => {
  const installer = [WATCH_EXIT_INSTALLED, WATCH_EXIT_FAILED, WATCH_EXIT_ROLLBACK_INCOMPLETE, WATCH_EXIT_CANARY_PENDING, WATCH_EXIT_CANARY_STILL_INSTALLED];

  it("is exactly {0, 1, 3, 5, 6} plus usage 2 and runtime 78", () => {
    expect(new Set(installer)).toEqual(new Set([0, 1, 3, 5, 6]));
    expect(installer).toHaveLength(5);
    expect(WATCH_EXIT_USAGE).toBe(2);
    expect(STABLE_RUNTIME_REFUSAL_EXIT_CODE).toBe(78);
    expect(WATCH_EXIT_ROLLBACK_INCOMPLETE).toBe(FULL_AGENT_ROLLBACK_INCOMPLETE_EXIT_CODE);
  });

  it("keeps 5 and 6 apart from usage, runtime and every liveness exit", () => {
    const liveness = [LIVENESS_EXIT_OK, LIVENESS_EXIT_DOWN, LIVENESS_EXIT_USAGE, LIVENESS_EXIT_WARNING, LIVENESS_STATUS_INTERNAL_EXIT_CODE, STABLE_RUNTIME_REFUSAL_EXIT_CODE];
    for (const code of [WATCH_EXIT_CANARY_PENDING, WATCH_EXIT_CANARY_STILL_INSTALLED]) {
      expect(code).not.toBe(WATCH_EXIT_USAGE);
      expect(code).not.toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
      expect(liveness).not.toContain(code);
    }
    expect(WATCH_EXIT_CANARY_PENDING).not.toBe(WATCH_EXIT_CANARY_STILL_INSTALLED);
  });

  it("is named in the CLI help for each verb", () => {
    const source = readFileSync(join(__dirname, "..", "..", "..", "src", "cli.ts"), "utf8");
    const start = source.indexOf("    install-watch    ");
    const end = source.indexOf("    full-status ", start);
    expect(start).toBeGreaterThan(0);
    const help = source.slice(start, end);
    const block = (verb: string, next: string | null) => help.slice(help.indexOf(`    ${verb} `), next === null ? undefined : help.indexOf(`    ${next} `));
    const install = block("install-watch", "run-watch");
    const run = block("run-watch", "uninstall-watch");
    const uninstall = block("uninstall-watch", null);
    expect(install).toMatch(/Exit 0 /);
    expect(install).toMatch(/Exit 5:/);
    expect(install).toMatch(/Exit 1 failed or refused, 3 rollback incomplete, 2 usage,\s+78 unstable/);
    expect(run).toMatch(/Exit 0 on stop,\s+1 refused/);
    expect(uninstall).toMatch(/Exit 0 only when/);
    expect(uninstall).toMatch(/\s6 when the canary is still installed/);
    expect(uninstall).toMatch(/\s1 when the canary state cannot be read/);
    expect(uninstall).toMatch(/\s3 partial removal/);
  });
});
