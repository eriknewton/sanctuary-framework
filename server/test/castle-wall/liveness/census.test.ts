/** The passive census parser over real macOS 26 netstat fixtures: header binding, row tokenization and fail-closed refusals. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CENSUS_INPUT_BYTES, CENSUS_INPUT_ROWS, CENSUS_PID_ROWS } from "../../../src/castle-wall/liveness/constants.js";
import {
  CENSUS_HEADER_SIGNATURE,
  CENSUS_PREAMBLE,
  buildStoredSample,
  parseCensus,
  parseIpv4Prefix,
  type CensusRow,
} from "../../../src/castle-wall/liveness/census.js";

const FIXTURES = join(__dirname, "fixtures", "census");
const MACOS26 = readFileSync(join(FIXTURES, "netstat-anv-macos26.txt"), "utf8");
const IDLE = readFileSync(join(FIXTURES, "netstat-anv-reference-host-idle.txt"), "utf8");
const GATEWAY_PID = 75399;
const SEPARATOR = /^=== SAMPLE \d+ observed_at=\S+ observed_uptime_ms=\d+\n/m;

/** Split the reference-host series on its separator lines; the parser never sees a separator. */
function idleSamples(): string[] {
  return IDLE.split(SEPARATOR).filter(block => block.length > 0);
}
const [PREAMBLE_LINE, HEADER_LINE] = MACOS26.split("\n") as [string, string];
const GATEWAY_ROW = idleSamples()[0]!.split("\n").find(line => line.includes("ESTABLISHED") && line.includes(`:${GATEWAY_PID}`))!;
const sampleText = (...rows: string[]) => [PREAMBLE_LINE, HEADER_LINE, ...rows].join("\n") + "\n";
function rowsOf(text: string, pid = GATEWAY_PID): CensusRow[] {
  const parsed = parseCensus(text, { gatewayPid: pid });
  if (parsed.status !== "ok") throw new Error(`unexpected ${parsed.detail}`);
  return parsed.rows;
}

describe("census fixtures", () => {
  it("are byte-identical copies whose manifest names the one macOS 26 header", () => {
    const manifest = JSON.parse(readFileSync(join(FIXTURES, "MANIFEST.json"), "utf8")) as { files: Record<string, { os: string; build: string }> };
    expect(Object.values(manifest.files).map(file => `${file.os} ${file.build}`)).toEqual(["macOS 26.6.2 25G83", "macOS 26.6.2 25G83"]);
    expect(PREAMBLE_LINE).toBe(CENSUS_PREAMBLE);
    for (const block of idleSamples()) expect(block.split("\n")[1]).toBe(HEADER_LINE);
  });

  it("parse all seven netstat outputs", () => {
    const outputs = [MACOS26, ...idleSamples()];
    expect(outputs).toHaveLength(7);
    for (const output of outputs) expect(parseCensus(output, { gatewayPid: GATEWAY_PID }).status).toBe("ok");
    expect(parseCensus(MACOS26, { gatewayPid: 7779 }).status).toBe("ok");
  });

  it("binds the qualifying row's columns from the left and the right", () => {
    const row = rowsOf(idleSamples()[0]!).find(item => item.local === "192.0.2.1.64719")!;
    expect(row).toMatchObject({ proto: "tcp4", foreign: "203.0.113.10.443", tcp_state: "ESTABLISHED", rxbytes: 49560, txbytes: 42247, gencnt: "0000000000968d6d", process: "Python", pid: GATEWAY_PID });
    expect(row.foreignEndpoint).toMatchObject({ host: "203.0.113.10", portNumber: 443, ipv6: false });
    expect(idleSamples().map(text => rowsOf(text).find(item => item.local === "192.0.2.1.64719")!.rxbytes)).toEqual([49560, 51412, 52338, 54190, 55116, 56968]);
  });

  it("keeps the TCP state (state) and the socket state distinct", () => {
    const row = rowsOf(idleSamples()[0]!).find(item => item.local === "192.0.2.1.64719")!;
    expect(row.tcp_state).toBe("ESTABLISHED");
    expect(row.socket_state).toBe("00102");
    const closeWait = rowsOf(idleSamples()[0]!).filter(item => item.tcp_state === "CLOSE_WAIT");
    expect(closeWait.map(item => item.socket_state)).toEqual(["00122", "00122", "00122"]);
  });

  it("takes the pid after the last colon of a process name with spaces and colons", () => {
    const rows = rowsOf(MACOS26, 7779);
    expect(rows.find(item => item.local === "192.0.2.1.64680")).toMatchObject({ process: "Google Chrome He", pid: 2308 });
    expect(rows.find(item => item.local === "192.0.2.3.64696")).toMatchObject({ process: "", pid: 10433 });
    const spaced = GATEWAY_ROW.replace(`Python:${GATEWAY_PID}`, `My App: v2:${GATEWAY_PID}`);
    expect(rowsOf(sampleText(spaced))[0]).toMatchObject({ process: "My App: v2", pid: GATEWAY_PID, rxbytes: 49560, gencnt: "0000000000968d6d" });
  });

  it("parses a LISTEN *.* row and a truncated IPv6 row as non-qualifying rows", () => {
    const rows = rowsOf(MACOS26, 7779);
    const listen = rows.find(item => item.local === "192.0.2.2.3501")!;
    expect(listen.tcp_state).toBe("LISTEN");
    expect(listen.foreignEndpoint).toMatchObject({ host: "*", port: "*", portNumber: null });
    const truncated = rows.find(item => item.local === "2001:db8::2:0:0:.64434")!;
    expect(truncated.localEndpoint.ipv6).toBe(true);
    expect(truncated.foreignEndpoint.ipv4).toBeNull();
    const prefix = parseIpv4Prefix("203.0.113.0/24")!;
    const stored = buildStoredSample({ status: "ok", rows: [listen, truncated].map(row => ({ ...row, pid: GATEWAY_PID })) }, {
      gateway: { pid: GATEWAY_PID, start_identity: "s", uid: 502, generation: "g" }, ipv4Set: [prefix],
      observed_at: "2026-11-09T04:58:09Z", observed_uptime_ms: 1, boot_id: "b",
    });
    expect(stored.status === "ok" && stored.sample.rows).toEqual([]);
    expect(stored.status === "ok" && stored.sample.other_rows).toBe(2);
  });
});

describe("header refusals", () => {
  const swap = (a: string, b: string) => HEADER_LINE.replace(a, "\u0000").replace(b, a).replace("\u0000", b);
  it("refuses the same names in another order", () => {
    const reordered = swap("rxbytes", "txbytes");
    expect(reordered).not.toBe(HEADER_LINE);
    expect(parseCensus([PREAMBLE_LINE, reordered, GATEWAY_ROW].join("\n"), { gatewayPid: GATEWAY_PID }))
      .toEqual({ status: "census_unavailable", detail: "header_signature" });
  });

  it.each(["gencnt", "rxbytes", "(state)", "process:pid", "txbytes"])("refuses a header missing %s", column => {
    const header = HEADER_LINE.replace(column, "");
    expect(parseCensus([PREAMBLE_LINE, header, GATEWAY_ROW].join("\n"), { gatewayPid: GATEWAY_PID }).status).toBe("census_unavailable");
  });

  it("refuses an unknown header signature", () => {
    expect(parseCensus([PREAMBLE_LINE, `${HEADER_LINE} extra`, GATEWAY_ROW].join("\n"), { gatewayPid: GATEWAY_PID }).status).toBe("census_unavailable");
    expect(CENSUS_HEADER_SIGNATURE).toHaveLength(19);
  });

  it("accepts the preamble once and refuses any other line before the header", () => {
    expect(parseCensus([HEADER_LINE, GATEWAY_ROW].join("\n"), { gatewayPid: GATEWAY_PID }).status).toBe("ok");
    expect(parseCensus(["unexpected banner", HEADER_LINE, GATEWAY_ROW].join("\n"), { gatewayPid: GATEWAY_PID }).status).toBe("census_unavailable");
    expect(parseCensus([PREAMBLE_LINE, PREAMBLE_LINE, HEADER_LINE].join("\n"), { gatewayPid: GATEWAY_PID }).status).toBe("census_unavailable");
  });
});

describe("row refusals", () => {
  it("fails the whole sample when the gateway's own row has a non-hex gencnt", () => {
    const bad = GATEWAY_ROW.replace("0000000000968d6d", "00000000zz968d6d");
    expect(parseCensus(sampleText(bad), { gatewayPid: GATEWAY_PID })).toEqual({ status: "census_unavailable", detail: "row_invalid" });
  });

  it("skips another process's failed row and keeps the sample", () => {
    const other = GATEWAY_ROW.replace("0000000000968d6d", "00000000zz968d6d").replace(`Python:${GATEWAY_PID}`, "Python:75400");
    expect(rowsOf(sampleText(other, GATEWAY_ROW)).map(row => row.pid)).toEqual([GATEWAY_PID]);
  });

  it.each([
    ["an unknown proto", (row: string) => row.replace("tcp4", "udp4")],
    ["an unknown TCP state", (row: string) => row.replace("ESTABLISHED", "ESTABLISHING")],
    ["a non-decimal rxbytes", (row: string) => row.replace("49560", "4956x")],
    ["a non-decimal pid", (row: string) => row.replace(`Python:${GATEWAY_PID}`, "Python:7539x")],
    ["an empty process residual", (row: string) => row.replace(`Python:${GATEWAY_PID}`, "")],
  ] as const)("fails an unattributable or gateway row with %s", (_name, edit) => {
    expect(parseCensus(sampleText(edit(GATEWAY_ROW)), { gatewayPid: GATEWAY_PID }).status).toBe("census_unavailable");
  });

  it("refuses input over the byte and row caps", () => {
    expect(parseCensus("x".repeat(CENSUS_INPUT_BYTES + 1), { gatewayPid: GATEWAY_PID })).toEqual({ status: "census_unavailable", detail: "input_bytes" });
    expect(parseCensus("\n".repeat(CENSUS_INPUT_ROWS), { gatewayPid: GATEWAY_PID })).toEqual({ status: "census_unavailable", detail: "input_rows" });
  });

  it("refuses more than CENSUS_PID_ROWS qualifying rows for the gateway", () => {
    const rows = Array.from({ length: CENSUS_PID_ROWS + 1 }, (_, index) => GATEWAY_ROW.replace("192.0.2.1.64719", `192.0.2.1.${64000 + index}`));
    const stored = buildStoredSample(parseCensus(sampleText(...rows), { gatewayPid: GATEWAY_PID }), {
      gateway: { pid: GATEWAY_PID, start_identity: "s", uid: 502, generation: "g" }, ipv4Set: [parseIpv4Prefix("203.0.113.0/24")!],
      observed_at: "2026-11-09T04:58:09Z", observed_uptime_ms: 1, boot_id: "b",
    });
    expect(stored).toEqual({ status: "census_unavailable", detail: "pid_rows" });
  });
});
