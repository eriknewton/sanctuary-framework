/**
 * Capability: the production entry points of the credential surrogate helper
 * are reached without injected transports. The operator CLI's own unlock-socket
 * client talks to a real helper over a real Unix-domain socket and classifies
 * every answer it can get (armed, absent, a reply to some other request, a
 * second frame); the argv entry the launchd job runs applies the same uid
 * refusals as the parser and refuses to serve without a readable table; and the
 * `castle-wall surrogate-helper-daemon` verb in the built CLI dispatches to that
 * entry.
 *
 * Host-free: every socket lives in a per-test temp directory, `chown` is
 * injected for the helper the client talks to, no keychain is opened and no
 * `security` subprocess runs. The CLI case uses an argv the parser refuses
 * before any filesystem read, so the spawned process touches nothing. The test
 * value is generated here.
 *
 * Defect id: SURROGATE-OPERATOR-CLIENT, SURROGATE-HELPER-ENTRY.
 */

import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm as rmReal, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createSurrogateUnlockSocketTransport,
  probeSurrogateHelperArmed,
} from "../../src/cli/secrets.js";
import { renderSurrogateBindingsFile } from "../../src/credential-surrogate/artifacts.js";
import type { MintedSurrogateBinding } from "../../src/credential-surrogate/binding.js";
import { mintSurrogatePlaceholder } from "../../src/credential-surrogate/placeholder.js";
import { SURROGATE_WIRE_VERSION, newSurrogateCorrelationId } from "../../src/credential-surrogate/wire.js";
import {
  GATE_SURROGATE_DIR,
  SurrogateHelperArgvError,
  SurrogateHelperStartError,
  runSurrogateHelperDaemon,
  runSurrogateHelperDaemonFromArgv,
  surrogateBindingsPath,
  surrogateUnlockSocketPath,
  type SurrogateHelperFsOps,
} from "../../src/egress-gate/surrogate-helper-daemon.js";
import { CLI_SUBPROCESS_TEST_TIMEOUT_MS, runCliRaw } from "../cli/helpers/run-cli.js";

const AGENT_UID = 611;
const GATE_UID = 612;
const OPERATOR_UID = 501;
const GENERATION = 9;

const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  // Every listener and temp directory is reaped even when an assertion failed.
  while (cleanups.length > 0) await cleanups.pop()!().catch(() => undefined);
});

async function tempDir(): Promise<string> {
  // Short prefix: a Unix-domain socket path is capped near 104 bytes on macOS.
  const dir = await mkdtemp(join(tmpdir(), "sg-wire-"));
  cleanups.push(() => rmReal(dir, { recursive: true, force: true }));
  return dir;
}

function binding(): MintedSurrogateBinding {
  return {
    ordinal: 0,
    placeholder: mintSurrogatePlaceholder(),
    secret: "secret-0",
    agent: "hermes",
    env: "SECRET_0",
    header: "Authorization",
    destinations: [{ host: "api0.example.com", port: 443 }],
  };
}

/** Real fs, except `chown`, which would fail with EPERM for a uid this process does not own. */
const fsOps: SurrogateHelperFsOps = {
  async mkdir(): Promise<void> {},
  async chmod(): Promise<void> {},
  async chown(): Promise<void> {},
  async rm(path): Promise<void> {
    await rmReal(path, { force: true });
  },
  async readFile(path): Promise<string> {
    return readFile(path, "utf8");
  },
};

/** A stand-in listener at the helper's unlock path; `reply` sees the request's own id. */
async function fakeUnlockListener(
  dir: string,
  agentUid: number,
  reply: (requestId: string) => string,
): Promise<void> {
  const server: Server = createServer((socket) => {
    socket.once("data", (chunk: Buffer) => {
      const { id } = JSON.parse(chunk.toString("utf8").trimEnd()) as { id: string };
      socket.end(reply(id));
    });
  });
  await new Promise<void>((resolve) => server.listen(surrogateUnlockSocketPath(agentUid, dir), resolve));
  cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
}

describe("the operator's real unlock-socket client against a real helper", () => {
  it("probes armed, unlocks and locks over the wire, reads ENOENT as unarmed, and discards replies that are not its own", async () => {
    const dir = await tempDir();
    const b = binding();
    await writeFile(surrogateBindingsPath(AGENT_UID, dir), renderSurrogateBindingsFile(GENERATION, [b]), "utf8");
    const handle = await runSurrogateHelperDaemon({
      agentUid: AGENT_UID,
      gateUid: GATE_UID,
      operatorUid: OPERATOR_UID,
      generation: GENERATION,
      surrogateDir: dir,
      fsOps,
      onEvent: () => undefined,
    });
    cleanups.push(() => handle.close());

    // The production transport, pointed at the temp directory only.
    const transport = createSurrogateUnlockSocketTransport(dir);

    expect(await probeSurrogateHelperArmed(transport, AGENT_UID)).toEqual({
      state: "armed",
      generationId: GENERATION,
    });

    const unlockId = newSurrogateCorrelationId();
    const unlocked = await transport.send(AGENT_UID, {
      v: SURROGATE_WIRE_VERSION,
      id: unlockId,
      kind: "unlock",
      generation_id: GENERATION,
      ttl_seconds: 60,
      secret: b.secret,
      value: `t-${randomBytes(12).toString("hex")}`,
    });
    expect(unlocked).toMatchObject({ outcome: "answered", response: { id: unlockId, kind: "ok" } });

    const lockId = newSurrogateCorrelationId();
    const locked = await transport.send(AGENT_UID, { v: SURROGATE_WIRE_VERSION, id: lockId, kind: "lock" });
    expect(locked).toMatchObject({ outcome: "answered", response: { id: lockId } });

    // No socket for this uid: the one outcome that means "no helper".
    expect(await probeSurrogateHelperArmed(transport, AGENT_UID + 100)).toEqual({ state: "unarmed" });

    // A well-formed status reply carrying some OTHER request's id is not an
    // answer to ours, so the probe is indeterminate, never armed or unarmed.
    const statusFrame = (id: string): string =>
      JSON.stringify({ v: SURROGATE_WIRE_VERSION, id, kind: "status", generation_id: GENERATION, bindings: [] });
    await fakeUnlockListener(dir, AGENT_UID + 200, () => `${statusFrame(newSurrogateCorrelationId())}\n`);
    expect(await probeSurrogateHelperArmed(transport, AGENT_UID + 200)).toEqual({
      state: "indeterminate",
      failureClass: "malformed_reply",
    });

    // The same reply with the CORRECT id is armed, which proves the fake is a
    // valid status answer and the two refusals around it are the client's own.
    await fakeUnlockListener(dir, AGENT_UID + 250, (id) => `${statusFrame(id)}\n`);
    expect(await probeSurrogateHelperArmed(transport, AGENT_UID + 250)).toEqual({
      state: "armed",
      generationId: GENERATION,
    });

    // A correct answer followed by a second frame breaks one-frame-each-way:
    // indeterminate, never armed.
    await fakeUnlockListener(dir, AGENT_UID + 300, (id) => `${statusFrame(id)}\n${statusFrame(id)}\n`);
    expect(await probeSurrogateHelperArmed(transport, AGENT_UID + 300)).toEqual({
      state: "indeterminate",
      failureClass: "malformed_reply",
    });
  });
});

describe("runSurrogateHelperDaemonFromArgv, the entry the launchd job runs", () => {
  it("applies the argv uid refusals before reading anything", async () => {
    await expect(
      runSurrogateHelperDaemonFromArgv([
        "--agent-uid", String(AGENT_UID),
        "--gate-uid", String(GATE_UID),
        "--operator-uid", "0",
        "--generation", String(GENERATION),
      ]),
    ).rejects.toMatchObject({ name: SurrogateHelperArgvError.name, refusal: "operator_uid_is_root" });
  });

  it("refuses to serve when the root-owned table for its uid is absent", async () => {
    // A uid no real host provisions, so the production table path does not
    // exist and the entry stops at its read: no socket is created and nothing
    // is written. Guarded so a host that somehow holds this path is never
    // driven further.
    const unusedUid = 4_242_424;
    expect(existsSync(surrogateBindingsPath(unusedUid, GATE_SURROGATE_DIR))).toBe(false);
    await expect(
      runSurrogateHelperDaemonFromArgv([
        "--agent-uid", String(unusedUid),
        "--gate-uid", String(unusedUid + 1),
        "--operator-uid", String(OPERATOR_UID),
        "--generation", String(GENERATION),
      ]),
    ).rejects.toMatchObject({ name: SurrogateHelperStartError.name, refusal: "bindings_unreadable" });
  });
});

describe("the castle-wall surrogate-helper-daemon verb in the built CLI", () => {
  it(
    "dispatches to the argv entry and exits non-zero on a refused argv",
    async () => {
      const result = await runCliRaw([
        "castle-wall", "surrogate-helper-daemon",
        "--agent-uid", "4242424",
        "--gate-uid", "4242425",
        "--operator-uid", "0",
        "--generation", "1",
      ]);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain(
        "surrogate helper daemon failed to start: surrogate helper argv refused: operator_uid_is_root",
      );
    },
    CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  );
});
