// fail-before-exempt: doctor now also reads the Hermes launch entry, so each doctor run here is given a Hermes config path that does not exist; no assertion changes.
// fail-before-exempt: new session-binding CLI module has no base implementation; config validation and boot persistence have separate behavioral witnesses.
/** The operator can explicitly choose default binding for an existing fortress. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import * as readline from "node:readline/promises";
import { resolveCliMasterKey, withCliMasterKeySession } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";
import * as harnessPaths from "../../src/wrap/config-reader.js";
import { runSessionBindingCommand } from "../../src/cli/session-binding.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { ABSENT_HERMES_CONFIG } from "../helpers/absent-hermes-config.js";
let fortress: Awaited<ReturnType<typeof createTempFortress>>;
let path: string;
beforeEach(async () => {
  fortress = await createTempFortress("cli-session-binding");
  await mkdir(fortress.storagePath, { recursive: true });
  path = join(fortress.storagePath, "sanctuary.json");
  const platforms = harnessPaths.getPlatformPaths();
  for (const platform of Object.keys(platforms) as Array<keyof typeof platforms>) platforms[platform] = [];
  vi.spyOn(harnessPaths, "getPlatformPaths").mockReturnValue(platforms);
});
afterEach(async () => { vi.restoreAllMocks(); await fortress.cleanup(); });
const disk = async () => JSON.parse(await readFile(path, "utf8"));
const write = async (value: unknown) => writeFile(path, JSON.stringify(value));
it("enable writes true and disable writes false, each leaving every other key unchanged", async () => {
  const preserved = { custom: { nested: "keep" }, storage_path: fortress.storagePath };
  await write(preserved);
  const out = new Writable({ write(_chunk, _encoding, done) { done(); } });
  for (const command of ["enable", "disable"]) {
    expect(await runSessionBindingCommand({ argv: [command, "--yes", "--fortress", fortress.storagePath], out, err: out })).toBe(0);
    expect(await disk()).toEqual({ ...preserved, session_binding: { sole_identity: command === "enable" } });
  }
});

it("enable without a terminal requires --yes", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: false });
  const out = new Writable({ write(_chunk, _encoding, done) { done(); } });
  try {
    expect(await runSessionBindingCommand({ argv: ["enable", "--fortress", fortress.storagePath], out, err: out })).toBe(2);
    expect(await readdir(fortress.storagePath)).toEqual([]);
  } finally {
    if (descriptor) Object.defineProperty(process.stdin, "isTTY", descriptor);
    else Reflect.deleteProperty(process.stdin, "isTTY");
  }
});


it("a missing fortress is refused without creating it", async () => {
  const missing = join(fortress.storagePath, "missing");
  const out = new Writable({ write(_chunk, _encoding, done) { done(); } });
  expect(await runSessionBindingCommand({ argv: ["enable", "--yes", "--fortress", missing], out, err: out })).toBe(2);
  expect(await readdir(fortress.storagePath)).toEqual([]);
});
it("status reports the absolute path without writing", async () => {
  let text = "";
  const out = new Writable({ write(chunk, _encoding, done) { text += chunk; done(); } });
  expect(await runSessionBindingCommand({ argv: ["status", "--fortress", fortress.storagePath], out, err: out })).toBe(0);
  expect(text).toContain(path);
  expect(text).toContain("absent (off)");
  // The temp fortress moved HOME, so status reads the Hermes entry under the temp home only.
  const hermesConfigPath = join(fortress.home, ".hermes", "config.yaml");
  expect(text.split("\n").filter(line => line.startsWith("Hermes entry"))).toEqual([
    `Hermes entry sanctuary (${hermesConfigPath}): fortress path not set or empty`,
    `Hermes entry sanctuary (${hermesConfigPath}): SANCTUARY_SESSION_IDENTITY_ID not set or empty`,
  ]);
  expect(await readdir(fortress.storagePath)).toEqual([]);
});

it.each(["yes", "no"])("a terminal confirmation controls the binding write (%s)", async answer => {
  await write({ keep: "operator" });
  const before = await readFile(path, "utf8");
  const descriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true });
  const terminal = { question: vi.fn(async () => answer), close: vi.fn() };
  const out = new Writable({ write(_chunk, _encoding, done) { done(); } });
  try {
    vi.spyOn(readline, "createInterface").mockReturnValue(terminal as unknown as ReturnType<typeof readline.createInterface>);
    expect(await runSessionBindingCommand({ argv: ["enable", "--fortress", fortress.storagePath], out, err: out }))
      .toBe(answer === "yes" ? 0 : 2);
    expect(terminal.question).toHaveBeenCalledOnce();
    expect(terminal.close).toHaveBeenCalledOnce();
    if (answer === "yes") expect(await disk()).toEqual({ keep: "operator", session_binding: { sole_identity: true } });
    else expect(await readFile(path, "utf8")).toBe(before);
  } finally {
    if (descriptor) Object.defineProperty(process.stdin, "isTTY", descriptor);
    else Reflect.deleteProperty(process.stdin, "isTTY");
  }
});

it("status preserves custody before and after a read-only master is available", async () => {
  const storage = new FilesystemStorage(join(fortress.storagePath, "state"));
  const derived = await deriveMasterKey(TEST_PASSPHRASE);
  const identityKey = derivePurposeKey(derived.key, "identity-encryption");
  try {
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));
    const { storedIdentity } = createIdentity("status-subject", identityKey, "passphrase");
    await persistStoredIdentity(storage, derived.key, storedIdentity);
    await write({ session_binding: { sole_identity: true } });
    const before = await readdir(fortress.storagePath, { recursive: true });
    const writes = vi.spyOn(FilesystemStorage.prototype, "write");
    let output = "";
    const out = new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } });
    expect(await runSessionBindingCommand({ argv: ["status", "--fortress", fortress.storagePath], out, err: out })).toBe(0);
    expect(output).toContain("cannot predict: identities are encrypted and no key is available");
    expect(writes.mock.calls.map(([namespace, key]) => ({ namespace, key }))).toEqual([]);
    expect(await readdir(fortress.storagePath, { recursive: true })).toEqual(before);
    writes.mockRestore();
    // Normal key resolution enrolls the legacy fixture before the next read-only status call.
    const session = await resolveCliMasterKey(storage, { passphrase: TEST_PASSPHRASE, storagePathHint: fortress.storagePath });
    await withCliMasterKeySession(session, async () => {});
    const enrolled = await readdir(fortress.storagePath, { recursive: true });
    const enrolledWrites = vi.spyOn(FilesystemStorage.prototype, "write");
    output = "";
    expect(await runSessionBindingCommand({ argv: ["status", "--fortress", fortress.storagePath], out, err: out })).toBe(0);
    expect(output).toContain(`A server started now would be: bound by default to ${storedIdentity.identity_id}`);
    expect(enrolledWrites.mock.calls.map(([namespace, key]) => ({ namespace, key }))).toEqual([]);
    expect(await readdir(fortress.storagePath, { recursive: true })).toEqual(enrolled);
    expect(await disk()).toEqual({ session_binding: { sole_identity: true } });
  } finally { identityKey.fill(0); derived.key.fill(0); }
});


vi.mock("node:readline/promises", async importOriginal => ({
  ...await importOriginal<typeof import("node:readline/promises")>(),
}));


it("status keeps an invalid config in place and reports failure", async () => {
  await write({ session_binding: { sole_identity: "true" } });
  const before = await readFile(path, "utf8");
  let output = "";
  const out = new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } });
  expect(await runSessionBindingCommand({ argv: ["status", "--fortress", fortress.storagePath], out, err: out })).toBe(1);
  expect(output).toContain(path);
  expect(output).toContain("session binding config cannot be read");
  expect(await readFile(path, "utf8")).toBe(before);
});

it("doctor and status share every next-start prediction alternative", async () => {
  const { runDoctorChecks } = await import("../../src/cli/doctor.js");
  const bindingPredictions = await import("../../src/agent-native/session-binding.js");
  const storagePath = fortress.storagePath;
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const derived = await deriveMasterKey(TEST_PASSPHRASE);
  const identityKey = derivePurposeKey(derived.key, "identity-encryption");
  const { storedIdentity } = createIdentity("prediction-subject", identityKey, "passphrase");
  try {
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));
    await persistStoredIdentity(storage, derived.key, storedIdentity);
  } finally { identityKey.fill(0); derived.key.fill(0); }
  const prediction = vi.spyOn(bindingPredictions, "predictNextStartBinding");
  const id = storedIdentity.identity_id;
  const alternatives = [
    { flag: true, named: undefined, line: `A server started now would be: bound by default to ${id}` },
    { flag: false, named: id, line: `A server started now would be: bound to ${id} by the launch variable` },
    { flag: false, named: undefined, line: "A server started now would be: not bound: default binding is off" },
  ];
  const doctorLines: string[] = [];
  const statusLines: string[] = [];
  try {
    for (const alternative of alternatives) {
      await writeFile(path, JSON.stringify({ session_binding: { sole_identity: alternative.flag } }));
      const env = { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE, SANCTUARY_SESSION_IDENTITY_ID: alternative.named };
      prediction.mockClear();
      const check = (await runDoctorChecks({ hermesConfigPath: ABSENT_HERMES_CONFIG, storagePath, env, platform: "linux" })).find(row => row.name === "session binding");
      expect(prediction).toHaveBeenCalledOnce();
      doctorLines.push(check!.message.split("\n").find(line => line.startsWith("A server started now"))!);
      prediction.mockClear();
      let text = "";
      const output = new Writable({ write(chunk, _encoding, done) { text += chunk; done(); } });
      expect(await runSessionBindingCommand({ argv: ["status", "--fortress", storagePath], env, out: output, err: output })).toBe(0);
      expect(prediction).toHaveBeenCalledOnce();
      statusLines.push(text.split("\n").find(line => line.startsWith("A server started now"))!);
    }
    expect(doctorLines).toEqual(alternatives.map(alternative => alternative.line));
    expect(statusLines).toEqual(doctorLines);
  } finally { prediction.mockRestore(); }
});
