/**
 * Tests for the `castle-wall configure-origin` CLI command (A1).
 *
 * Asserts:
 *  - uid mode writes a valid agent-origin.json
 *  - nat mode writes a valid agent-origin.json
 *  - missing required args return exit code 2
 *  - invalid descriptors return exit code 1
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runConfigureOrigin } from "../../src/cli/castle-wall.js";

function collectStream(): { stream: Writable; text: () => string } {
  let buf = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      buf += String(chunk);
      callback();
    },
  });
  return { stream, text: () => buf };
}

describe("castle-wall configure-origin CLI", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "cw-origin-test-"));
    await mkdir(join(tmpDir, "policy", "egress"), { recursive: true });
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("writes a valid uid-mode agent-origin.json", async () => {
    const out = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=502", "--ceiling=500", `--fortress`, tmpDir],
      { out: out.stream, err: out.stream, env: {} }
    );
    expect(code).toBe(0);

    const raw = await readFile(
      join(tmpDir, "policy", "egress", "agent-origin.json"),
      "utf8"
    );
    const parsed = JSON.parse(raw);
    expect(parsed).toEqual({
      mode: "uid",
      agent_uid: 502,
      system_uid_allow_ceiling: 500,
    });
  });

  it("writes a valid nat-mode agent-origin.json", async () => {
    const out = collectStream();
    const code = await runConfigureOrigin(
      [
        "nat",
        "--signing-id=ai.sanctuaryprotocol.egress-helper",
        "--team-id=YFQSWQ9BJN",
        "--fortress",
        tmpDir,
      ],
      { out: out.stream, err: out.stream, env: {} }
    );
    expect(code).toBe(0);

    const raw = await readFile(
      join(tmpDir, "policy", "egress", "agent-origin.json"),
      "utf8"
    );
    const parsed = JSON.parse(raw);
    expect(parsed.mode).toBe("nat");
    expect(parsed.egress_helper_signing_id).toBe(
      "ai.sanctuaryprotocol.egress-helper"
    );
    expect(parsed.egress_helper_team_id).toBe("YFQSWQ9BJN");
  });

  it("defaults system_uid_allow_ceiling to 500", async () => {
    const out = collectStream();
    await runConfigureOrigin(
      ["uid", "--agent-uid=502", "--fortress", tmpDir],
      { out: out.stream, err: out.stream, env: {} }
    );

    const raw = await readFile(
      join(tmpDir, "policy", "egress", "agent-origin.json"),
      "utf8"
    );
    const parsed = JSON.parse(raw);
    expect(parsed.system_uid_allow_ceiling).toBe(500);
  });

  it("returns exit code 2 when mode is missing", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(["--fortress", tmpDir], {
      out: err.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain("Usage:");
  });

  it("returns exit code 2 when uid mode has no --agent-uid", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    expect(code).toBe(2);
    expect(err.text()).toContain("--agent-uid");
  });

  it("returns exit code 2 when nat mode has no signing-id or team-id", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["nat", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    expect(code).toBe(2);
    expect(err.text()).toContain("--signing-id");
  });

  // --- Hardening: strict numeric parse + floor invariant (shared chokepoint) ---

  async function originExists(): Promise<boolean> {
    try {
      await readFile(join(tmpDir, "policy", "egress", "agent-origin.json"), "utf8");
      return true;
    } catch {
      return false;
    }
  }

  it("rejects --agent-uid=0 (root can never be the confined agent)", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=0", "--ceiling=0", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    expect(code).toBe(1);
    expect(await originExists()).toBe(false);
  });

  it("rejects an agent uid below the ceiling", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=100", "--ceiling=500", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    expect(code).toBe(1);
    expect(await originExists()).toBe(false);
  });

  it("accepts agent uid EQUAL to the ceiling (boundary)", async () => {
    const out = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=500", "--ceiling=500", "--fortress", tmpDir],
      { out: out.stream, err: out.stream, env: {} }
    );
    expect(code).toBe(0);
    const raw = await readFile(
      join(tmpDir, "policy", "egress", "agent-origin.json"),
      "utf8"
    );
    expect(JSON.parse(raw)).toEqual({
      mode: "uid",
      agent_uid: 500,
      system_uid_allow_ceiling: 500,
    });
  });

  it("rejects a non-numeric --agent-uid fail-closed (no parseInt truncation)", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=501abc", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    // parseInt("501abc") would have silently produced 501; strict parse refuses.
    expect(code).toBe(1);
    expect(err.text()).toContain("plain positive integer");
    expect(await originExists()).toBe(false);
  });

  it("rejects a non-numeric --ceiling fail-closed (no parseInt truncation)", async () => {
    const err = collectStream();
    const code = await runConfigureOrigin(
      ["uid", "--agent-uid=502", "--ceiling=500abc", "--fortress", tmpDir],
      { out: err.stream, err: err.stream, env: {} }
    );
    expect(code).toBe(1);
    expect(err.text()).toContain("--ceiling");
    expect(await originExists()).toBe(false);
  });
});
