/** Process census: strict ps parsing, gateway selection and generation, the MCP stale-child check, and the two-read collector. */
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CENSUS_REREAD, LABEL_BYTES, MAX_STALE_CHILDREN, PROCESS_BYTES, PROCESS_ROWS } from "../../../src/castle-wall/liveness/constants.js";
import {
  checkMcpStaleChild,
  gatewayGeneration,
  parseProcessRead,
  selectGateway,
  type ProcessRow,
} from "../../../src/castle-wall/liveness/process-census.js";
import { BoundedChildRunner, createWatchCollectors, type WatchChild, type WatchSpawn } from "../../../src/cli/castle-wall-watch-collectors.js";

const FIXTURE = JSON.parse(readFileSync(join(__dirname, "fixtures", "process-census.json"), "utf8")) as {
  agent_uid: number; gateway_process_name: string; harness_pid: number; mcp_script: string; full_agent_pid: number; text: string;
};
const rows = (text = FIXTURE.text): ProcessRow[] => {
  const parsed = parseProcessRead(text);
  if (parsed.status !== "ok") throw new Error(parsed.detail);
  return parsed.rows;
};
const line = (pid: number, ppid: number, uid: number, lstart: string, command: string) => `${pid} ${ppid} ${uid} ${lstart} ${command}`;
const SELECTOR = { agentUid: FIXTURE.agent_uid, processName: FIXTURE.gateway_process_name };
const MCP = { agentUid: FIXTURE.agent_uid, mcp: { harness_label: "ai.sanctuaryprotocol.agent-harness", script_paths: [FIXTURE.mcp_script] } };

describe("ps parser", () => {
  it("parses pid, ppid, uid, the five lstart tokens with single spaces, and argv", () => {
    const gateway = rows().find(row => row.pid === 75399)!;
    expect(gateway).toMatchObject({ ppid: 75400, uid: 502, lstart: "Sun Nov 9 07:57:01 2026", argv: ["/opt/agent-fixture/venv/bin/Python", "-m", "agent_fixture.gateway"] });
    expect(gateway.lstartMs).toBe(Date.UTC(2026, 10, 9, 7, 57, 1));
  });

  it("fails the whole read over the byte or row cap, or on any malformed row", () => {
    const filler = `${line(9, 1, 0, "Sun Nov  9 07:40:00 2026", "/bin/x")}\n`;
    expect(parseProcessRead(filler.repeat(PROCESS_ROWS + 1)).status).toBe("failed");
    expect(parseProcessRead(filler.repeat(PROCESS_ROWS)).status).toBe("ok");
    expect(parseProcessRead(`${line(9, 1, 0, "Sun Nov  9 07:40:00 2026", "/bin/" + "x".repeat(PROCESS_BYTES))}\n`).status).toBe("failed");
    expect(parseProcessRead(`${FIXTURE.text}garbage line\n`).status).toBe("failed");
    expect(parseProcessRead(`${FIXTURE.text}${line(9, 1, 0, "Sun Foo  9 07:40:00 2026", "/bin/x")}\n`).status).toBe("failed");
  });
});

describe("gateway selection", () => {
  it("selects one match by argv[0] basename and agent uid in both reads, with a deterministic generation", () => {
    const g = selectGateway([rows(), rows()], SELECTOR, null);
    expect(g).toEqual({ pid: 75399, uid: 502, start_identity: "Sun Nov 9 07:57:01 2026", generation: gatewayGeneration(75399, "Sun Nov 9 07:57:01 2026"), alive: true });
    expect(g!.generation).toHaveLength(LABEL_BYTES);
    expect(gatewayGeneration(75399, "Sun Nov 9 07:57:01 2026")).toBe(g!.generation);
  });

  it("reads two matches as unknown, never the first", () => {
    const two = rows(`${FIXTURE.text}${line(75398, 1, 502, "Sun Nov  9 07:58:00 2026", "/opt/x/Python -m other")}\n`);
    expect(selectGateway([two, two], SELECTOR, null)).toBeNull();
  });

  it("never selects a same-name row under another uid", () => {
    const g = selectGateway([rows(), rows()], { agentUid: 503, processName: "Python" }, null);
    expect(g!.pid).toBe(80001);
    const onlyOther = rows().filter(row => row.pid !== 75399);
    expect(selectGateway([onlyOther, onlyOther], SELECTOR, null)).toBeNull();
  });

  it("reads zero matches with a known prior as that gateway dead", () => {
    const prior = selectGateway([rows(), rows()], SELECTOR, null)!;
    const gone = rows().filter(row => row.pid !== 75399);
    expect(selectGateway([gone, gone], SELECTOR, prior)).toEqual({ ...prior, alive: false });
  });

  it("reads a pid or lstart change between the reads as unknown", () => {
    const restarted = rows(FIXTURE.text.replace("75399  75400   502 Sun Nov  9 07:57:01", "75399  75400   502 Sun Nov  9 07:59:01"));
    expect(selectGateway([rows(), restarted], SELECTOR, null)).toBeNull();
    const repid = rows(FIXTURE.text.replace(" 75399  75400", " 75390  75400"));
    expect(selectGateway([rows(), repid], SELECTOR, null)).toBeNull();
  });

  it("selects nothing for an executable path containing a space, so a socket owned by another pid never qualifies", () => {
    const spaced = rows(FIXTURE.text.replace("/opt/agent-fixture/venv/bin/Python -m agent_fixture.gateway", "/opt/agent fixture/venv/bin/Python -m agent_fixture.gateway"));
    expect(selectGateway([spaced, spaced], SELECTOR, null)).toBeNull();
  });
});

describe("MCP stale child", () => {
  it("reads a clean harness, one current child and unrelated node processes as not stale", () => {
    expect(checkMcpStaleChild([rows(), rows()], FIXTURE.harness_pid, MCP)).toEqual({ status: "ok", stale_child: false });
  });

  it.each([
    ["reparented to pid 1", (t: string) => t.replace(" 75500  75400", " 75500      1")],
    ["under an old harness pid", (t: string) => t.replace(" 75500  75400", " 75500  70000")],
    ["older than the harness", (t: string) => t.replace("75400   502 Sun Nov  9 07:51:00", "75400   502 Sun Nov  9 07:49:00")],
  ])("reads a child %s as stale", (_case, edit) => {
    const text = edit(FIXTURE.text);
    expect(text).not.toBe(FIXTURE.text);
    expect(checkMcpStaleChild([rows(text), rows(text)], FIXTURE.harness_pid, MCP)).toEqual({ status: "ok", stale_child: true });
  });

  it("reads a child under a harness pid reused with a later start as stale", () => {
    const reused = FIXTURE.text.replace(" 75400      1   502 Sun Nov  9 07:50:00", " 75400      1   502 Sun Nov  9 07:55:00");
    expect(checkMcpStaleChild([rows(reused), rows(reused)], FIXTURE.harness_pid, MCP)).toEqual({ status: "ok", stale_child: true });
  });

  it("refuses more than MAX_STALE_CHILDREN candidates, an unreadable harness, and a harness identity change", () => {
    const extra = Array.from({ length: MAX_STALE_CHILDREN + 1 }, (_, i) => line(90000 + i, 1, 502, "Sun Nov  9 08:01:00 2026", `/bin/node ${FIXTURE.mcp_script}`)).join("\n");
    const many = rows(`${FIXTURE.text}${extra}\n`);
    expect(checkMcpStaleChild([many, many], FIXTURE.harness_pid, MCP).status).toBe("invalid");
    expect(checkMcpStaleChild([rows(), rows()], null, MCP).status).toBe("invalid");
    const restarted = rows(FIXTURE.text.replace(" 75400      1   502 Sun Nov  9 07:50:00", " 75400      1   502 Sun Nov  9 07:50:30"));
    expect(checkMcpStaleChild([rows(), restarted], FIXTURE.harness_pid, MCP).status).toBe("invalid");
  });
});

describe("two-read process collector", () => {
  afterEach(() => { vi.useRealTimers(); });

  function spawnAnswering(texts: string[], argv: string[][]): WatchSpawn {
    let n = 0;
    return (file, args) => {
      argv.push([file, ...args]);
      const child = Object.assign(new EventEmitter(), { pid: 2000 + argv.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter };
      child.kill = () => true;
      const text = texts[Math.min(n++, texts.length - 1)]!;
      queueMicrotask(() => { child.stdout.emit("data", Buffer.from(text)); child.emit("exit", 0, null); child.emit("close", 0, null); });
      return child;
    };
  }

  it("takes two ps reads CENSUS_REREAD apart, only through ps and launchctl print argv, and sends no signal", async () => {
    vi.useFakeTimers();
    const argv: string[][] = [];
    const timers = { setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) };
    const runner = new BoundedChildRunner({ spawn: spawnAnswering([FIXTURE.text], argv), timers });
    const collectors = createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501 });
    let done = false;
    const reads = collectors.readProcesses().then(value => { done = true; return value; });
    await vi.advanceTimersByTimeAsync(CENSUS_REREAD - 1);
    expect(argv).toHaveLength(1);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const [a, b] = await reads;
    expect(argv).toEqual([["/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,lstart=,command="], ["/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,lstart=,command="]]);
    expect(a).toHaveLength(b.length);
    const harnessArgv: string[][] = [];
    const harnessRunner = new BoundedChildRunner({ spawn: spawnAnswering([JSON.parse(readFileSync(join(__dirname, "fixtures", "launchctl-print.json"), "utf8")).entries.harness_system.stdout], harnessArgv), timers });
    const pid = await createWatchCollectors({ runner: harnessRunner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501 }).printHarness(MCP.mcp.harness_label);
    expect(pid).toBe(75400);
    expect(checkMcpStaleChild([a, b], pid, MCP)).toEqual({ status: "ok", stale_child: false });
    for (const call of [...argv, ...harnessArgv]) expect(["/bin/ps", "/bin/launchctl"]).toContain(call[0]);
    for (const call of harnessArgv) expect(call[1]).toBe("print");
  });

  it("refuses the census when either read is over the row cap, so a single read never stands", async () => {
    vi.useFakeTimers();
    const argv: string[][] = [];
    const timers = { setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) };
    const over = `${line(9, 1, 0, "Sun Nov  9 07:40:00 2026", "/bin/x")}\n`.repeat(PROCESS_ROWS + 1);
    const runner = new BoundedChildRunner({ spawn: spawnAnswering([FIXTURE.text, over], argv), timers });
    const reads = createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501 }).readProcesses();
    const settled = reads.then(() => "ok", () => "failed");
    await vi.advanceTimersByTimeAsync(CENSUS_REREAD);
    expect(await settled).toBe("failed");
    expect(argv).toHaveLength(2);
  });
});
