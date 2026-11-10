/** `castle-wall liveness-status`: wall-only exits from stored evidence, help routing, usage refusals, a read-only reader and the compiled dispatch path. */
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { LIVENESS_STATUS_INTERNAL_EXIT_CODE, livenessFortressId, runLivenessStatus } from "../../src/cli/castle-wall-liveness-status.js";
import { evaluateLiveness, type HostClock, type LivenessInput } from "../../src/castle-wall/liveness/evaluate.js";
import type { HostClockProvider } from "../../src/castle-wall/liveness/read-status.js";
import { runCliRaw, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli.js";

const UID = process.getuid?.() ?? 0;
type Patch = { op: "set" | "add" | "delete"; path: string; value?: unknown };
type Row = { name: string; patches: Patch[]; expect: Record<string, unknown> };
const STATES = JSON.parse(readFileSync(join(__dirname, "..", "castle-wall", "liveness", "fixtures", "states.json"), "utf8")) as { base: LivenessInput; rows: Row[] };
const RECORD_FILES = ["daemon", "observer", "config"] as const;

class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void) { this.text += String(chunk); callback(); }
}
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { try { chmodSync(join(root, "liveness"), 0o700); } catch { /* absent */ } rmSync(root, { recursive: true, force: true }); } });

function patched(patches: readonly Patch[]): LivenessInput {
  const input = structuredClone(STATES.base) as unknown as Record<string, unknown>;
  for (const patch of patches) {
    const keys = patch.path.split(".");
    const last = keys.pop()!;
    let target = input;
    for (const key of keys) target = target[key] as Record<string, unknown>;
    if (patch.op === "delete") delete target[last];
    else if (patch.op === "add") target[last] = (target[last] as number) + (patch.value as number);
    else target[last] = structuredClone(patch.value);
  }
  return input as unknown as LivenessInput;
}

/** A temp fortress holding the fixture's records, re-subjected to this fortress and this operator, plus the matching injected reader context. */
function fortressFrom(patches: readonly Patch[]) {
  const root = mkdtempSync(join(tmpdir(), "lv-cli-"));
  roots.push(root);
  const input = patched(patches) as unknown as Record<string, any>;
  mkdirSync(join(root, "liveness"), { mode: 0o700 });
  for (const name of RECORD_FILES) {
    const read = input[name] as { status: string; value?: Record<string, any> };
    if (read.status !== "present") continue;
    const value = read.value!;
    if (value.subject) Object.assign(value.subject, { fortress_id: livenessFortressId(root), operator_uid: UID });
    writeFileSync(join(root, "liveness", `${name}.json`), JSON.stringify(value), { mode: 0o600 });
  }
  const host = input.host as HostClock;
  const hostClock: HostClockProvider = { read: async () => host, uptimeMs: () => (host.ok ? host.uptimeMs : 0) };
  const expected = evaluateLiveness({ ...(input as unknown as LivenessInput), local: { fortress_id: livenessFortressId(root), platform: "darwin", operator_uid: UID } });
  return { root, ctx: { platform: "darwin", getuid: () => UID, now: () => input.nowMs as number, hostClock }, expected };
}
function rowNamed(name: string): Row {
  const row = STATES.rows.find(r => r.name === name);
  if (!row) throw new Error(`no states.json row ${name}`);
  return row;
}
// A wall-only fault: one recorder hook unwired gives wall DOWN while the observer evidence keeps the agent OK.
const WALL_DOWN_AGENT_OK: Patch[] = [{ op: "delete", path: "daemon.value.raw.hooks.emission_tick" }];
function snapshotLiveness(root: string): Record<string, { bytes: string; mode: number }> {
  const dir = join(root, "liveness");
  const files: Record<string, { bytes: string; mode: number }> = { ".": { bytes: "", mode: statSync(dir).mode } };
  for (const name of readdirSync(dir).sort()) files[name] = { bytes: readFileSync(join(dir, name), "base64"), mode: statSync(join(dir, name)).mode };
  return files;
}

describe("liveness-status wall-only exit", () => {
  it("wall OK with agent DOWN exits 0, and the printed envelope reports the agent DOWN", async () => {
    const f = fortressFrom(rowNamed("agent down process missing").patches);
    expect(f.expected.wall.state.startsWith("wall_OK_")).toBe(true);
    expect(f.expected.agent.state).toBe("agent_DOWN");
    const out = new Capture();
    expect(await runLivenessStatus(["--json", "--fortress", f.root], { ...f.ctx, out })).toBe(0);
    const envelope = JSON.parse(out.text);
    expect(envelope).toMatchObject({ exit_code: 0, wall: { state: f.expected.wall.state }, agent: { state: "agent_DOWN", alarm: true } });
  });

  it("wall DOWN with agent OK exits 1", async () => {
    const f = fortressFrom(WALL_DOWN_AGENT_OK);
    expect(f.expected.wall.state).toBe("wall_DOWN");
    expect(f.expected.agent.state.startsWith("agent_OK_")).toBe(true);
    const out = new Capture();
    expect(await runLivenessStatus(["--fortress", f.root], { ...f.ctx, out })).toBe(1);
    expect(out.text).toContain("Liveness wall: wall_DOWN (evidence_incomplete)");
    expect(out.text).toMatch(/^Liveness agent: agent_OK_/m);
    expect(out.text).not.toMatch(/protected|enforcing/);
  });

  it("coverage UNAVAILABLE with wall OK is not constructible over every fixture row", () => {
    for (const row of STATES.rows) {
      const envelope = evaluateLiveness(patched(row.patches));
      if (envelope.wall.state.startsWith("wall_OK_")) expect(envelope.coverage.state, row.name).not.toBe("coverage_UNAVAILABLE");
      if (envelope.coverage.state === "coverage_UNAVAILABLE") expect(envelope.exit_code, row.name).not.toBe(0);
    }
  });

  it("the default text output prints exactly the three Liveness lines", async () => {
    const f = fortressFrom([]);
    const out = new Capture();
    expect(await runLivenessStatus(["--fortress", f.root], { ...f.ctx, out })).toBe(0);
    expect(out.text.split("\n").filter(Boolean).map(line => line.split(":")[0])).toEqual(["Liveness wall", "Liveness agent", "Liveness coverage"]);
  });

  it("refuses a relative --fortress and an unknown argument with the usage exit, printing no envelope", async () => {
    for (const argv of [["--fortress", "relative/fortress"], ["--verbose"], ["--fortress"]]) {
      const out = new Capture(), err = new Capture();
      expect(await runLivenessStatus(argv, { platform: "darwin", out, err }), argv.join(" ")).toBe(2);
      expect(out.text).toBe("");
      expect(err.text).toContain("castle-wall liveness-status:");
    }
  });

  it("an evaluation that cannot build an envelope prints nothing and exits 70", async () => {
    const f = fortressFrom([]);
    const out = new Capture();
    const throwing = { ...f.ctx, now: () => { throw new Error("fixture clock failure"); } };
    expect(await runLivenessStatus(["--json", "--fortress", f.root], { ...throwing, out })).toBe(LIVENESS_STATUS_INTERNAL_EXIT_CODE);
    expect(out.text).toBe("");
  });

  it("off darwin the wall reads unsupported_adapter and exits 1 without consulting the boot provider", async () => {
    const f = fortressFrom([]);
    let reads = 0;
    const out = new Capture();
    const code = await runLivenessStatus(["--json", "--fortress", f.root], { ...f.ctx, platform: "linux", hostClock: { read: async () => { reads++; return { ok: false }; } }, out });
    expect(code).toBe(1);
    expect(JSON.parse(out.text).wall.reasons).toContain("unsupported_adapter");
    expect(reads).toBe(0);
  });
});

describe("the reader writes nothing", () => {
  it("liveness-status leaves every liveness file byte-identical and mode-identical, including a misowned-mode record", async () => {
    const f = fortressFrom([]);
    // A group-readable record is refused, and the reader must not repair its mode.
    chmodSync(join(f.root, "liveness", "config.json"), 0o640);
    const before = snapshotLiveness(f.root);
    for (const argv of [["--json", "--fortress", f.root], ["--fortress", f.root]]) {
      await runLivenessStatus(argv, { ...f.ctx, out: new Capture() });
      expect(snapshotLiveness(f.root)).toEqual(before);
    }
  });
});

describe("compiled dispatch", () => {
  function emptyFortress(): string {
    const root = mkdtempSync(join(tmpdir(), "lv-cli-dist-"));
    roots.push(root);
    return root;
  }
  const childEnv = (root: string) => ({ HOME: root, SANCTUARY_STORAGE_PATH: root, SANCTUARY_CASTLE_HOSTAPP: "/nonexistent/CastleWallHostApp" });

  it("liveness-status --json through dist/cli.js exits 1 with a non-OK wall, unsupported_adapter off darwin", async () => {
    const root = emptyFortress();
    const { code, stdout } = await runCliRaw(["castle-wall", "liveness-status", "--json", "--fortress", root], { env: childEnv(root) });
    expect(code).toBe(1);
    const envelope = JSON.parse(stdout);
    expect(envelope.wall.state.startsWith("wall_OK_")).toBe(false);
    if (process.platform !== "darwin") expect(envelope.wall.reasons).toEqual(["unsupported_adapter"]);
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("castle-wall status through dist/cli.js exits 1 with a non-OK Liveness wall line", async () => {
    const root = emptyFortress();
    const { code, stdout } = await runCliRaw(["castle-wall", "status", "--fortress", root], { env: childEnv(root) });
    expect(code).toBe(1);
    expect(stdout).toMatch(/^Liveness wall: wall_/m);
    expect(stdout).not.toMatch(/^Liveness wall: wall_OK_/m);
    if (process.platform !== "darwin") expect(stdout).toContain("Liveness wall: wall_DOWN (unsupported_adapter)");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  // On darwin the compiled full-status reads the real launchctl job, which tests never run; the non-darwin host proves this case.
  it.skipIf(process.platform === "darwin")("castle-wall full-status through dist/cli.js exits 1 off darwin", async () => {
    const root = emptyFortress();
    const { code, stdout } = await runCliRaw(["castle-wall", "full-status", "--fortress", root], { env: childEnv(root) });
    expect(code).toBe(1);
    expect(stdout).not.toMatch(/^Liveness wall: wall_OK_/m);
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it.each(["liveness-status", "full-status", "status"])("castle-wall %s --help and -h exit 0 through the early help path and print no Liveness line", async command => {
    const root = emptyFortress();
    for (const flag of ["--help", "-h"]) {
      const { code, stdout } = await runCliRaw(["castle-wall", command, flag], { env: childEnv(root) });
      expect(code, `${command} ${flag}`).toBe(0);
      expect(stdout).toContain("liveness-status");
      expect(stdout).not.toContain("Liveness wall:");
    }
    expect(readdirSync(root).includes("liveness")).toBe(false);
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
