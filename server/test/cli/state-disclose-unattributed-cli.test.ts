/**
 * CAPABILITY (STATE-DISCLOSE-UNATTRIB-01), CLI half: `sanctuary
 * state_disclose_unattributed` is a WIRED consumer of the disclosure surface,
 * not a module with tests of its own.
 *
 * This is the test AGENTS.md assurance rule 4 asks for. It seeds a real
 * keychain-free fortress on disk, plants the one persisted shape whose writer
 * cannot be established, and drives the shipped command function end to end, so
 * a change that leaves the surface intact while unhooking the operator's route
 * to it reds here rather than passing.
 *
 * THE RENDERING CONTRACT UNDER TEST is the receipt+file design: the terminal
 * NEVER carries the disclosed content (the human path prints a bounded,
 * printable-ASCII receipt naming a file), the file carries the stored value
 * byte-for-byte, and `--json` refuses a TTY and stays verbatim off one. The
 * old contract (render the content to the terminal, escaped and framed) is
 * gone; both headline assertions here were run against the pre-change code and
 * failed there, which is what makes them assertions about the change.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import {
  disclosureFileBody,
  runStateDiscloseUnattributedCommand,
} from "../../src/cli/state-disclose.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";
import { UNATTRIBUTED_DISCLOSURE_NOTICE } from "../../src/cognitive/state-store.js";
import { UNATTRIBUTED_DISCLOSURE_OPERATION } from "../../src/cognitive/unattributed-disclosure.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StateEntry } from "../../src/cognitive/state-store.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

const NAMESPACE = "memories";
const RESERVED_NAMESPACE = "_reputation";
const KEY = "orphaned";
const CONTENT = "the-owner-must-still-reach-this-through-the-cli";

/**
 * Whole-stdout shape of the human path: printable ASCII and LF, nothing else.
 * This is the receipt design's testable core - not "these named bad sequences
 * are absent" (a denylist assertion, weaker than it reads) but "nothing
 * outside this set is present at all".
 */
const PRINTABLE_ASCII_AND_LF = /^[\x20-\x7e\n]*$/;

// ── Keychain-free fortress seeding (mirrors test/cli/file-grant-revoke-error-handling.test.ts) ──

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`)
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}

function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const stored = new Map<string, string>();
  const keyFor = (account: string, service: string): string =>
    `${account}:${service}`;
  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        keyFor(readSecurityToken(input, "-a"), readSecurityToken(input, "-s")),
        readSecurityToken(input, "-w")
      );
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec };
}

async function runInit(
  options: InitOptions
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}

function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

class FixedChannel implements ApprovalChannel {
  calls = 0;
  constructor(private readonly decision: "approve" | "deny") {}
  async requestApproval(): Promise<ApprovalResponse> {
    this.calls += 1;
    return {
      decision: this.decision,
      decided_at: "2026-08-18T00:00:04.000Z",
      decided_by: "human",
    };
  }
}

describe("sanctuary state_disclose_unattributed (CLI)", () => {
  let tmp: string;
  let fortressPath: string;
  let recoveryKey: string;

  /** The receipt names the content file; this reads the path off it. */
  function contentFilePathFrom(stdout: string): string {
    const match = stdout.match(/^content written to: (.+)$/m);
    expect(match, "receipt names the content file").not.toBeNull();
    return match![1]!;
  }

  async function plantEntry(overrides: Partial<Record<string, unknown>> = {}, content: string = CONTENT, namespace: string = NAMESPACE): Promise<void> {
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const plaintext = stringToBytes(content);
    const entry = {
      v: 1,
      payload: encrypt(plaintext, deriveNamespaceKey(masterKey, namespace)),
      ver: 1,
      // ED25519_SIGNATURE_BYTES = 64; the value is irrelevant because no key
      // resolves for `kid`, which is the point of this fixture.
      sig: toBase64url(new Uint8Array(64)),
      kid: "sanctuary-no-such-writer-identity",
      integrity_hash: hashToString(plaintext),
      metadata: { written_at: "2026-08-18T00:00:05.000Z" },
      ...overrides,
    } as unknown as StateEntry;
    await storage.write(namespace, KEY, stringToBytes(JSON.stringify(entry)));
    masterKey.fill(0);
  }

  async function runCommand(options: {
    namespace?: string;
    key?: string;
    json?: boolean;
    isTTY?: boolean;
    decision?: "approve" | "deny";
    fileNameSeam?: { now: Date; randomHex: string };
  } = {}): Promise<{ code: number; out: string; err: string; channel: FixedChannel }> {
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const out = new StringWritable() as StringWritable & { isTTY?: boolean };
    if (options.isTTY !== undefined) out.isTTY = options.isTTY;
    const err = new StringWritable();
    const channel = new FixedChannel(options.decision ?? "approve");
    const code = await runStateDiscloseUnattributedCommand({
      argv: [
        "--fortress",
        fortressPath,
        "--namespace",
        options.namespace ?? NAMESPACE,
        "--key",
        options.key ?? KEY,
        ...(options.json ? ["--json"] : []),
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      approvalChannel: channel,
      ...(options.fileNameSeam ? { fileNameSeam: options.fileNameSeam } : {}),
    });
    return { code, out: out.text, err: err.text, channel };
  }

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-state-disclose-cli-"));
    fortressPath = join(tmp, "fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: false,
    });
    recoveryKey = extractRecoveryKey(
      await readFile(result.recoveryKeyDisclosurePath, "utf-8")
    );
    // Plant the one persisted shape whose writer cannot be established: a
    // legacy (schema-1) entry whose `kid` resolves to no stored identity and to
    // no authenticated registry key.
    await plantEntry();
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  it("registers the subcommand so the dispatcher and completion agree it exists", () => {
    expect([...TOP_LEVEL_SUBCOMMANDS]).toContain(
      UNATTRIBUTED_DISCLOSURE_OPERATION
    );
  });

  it("writes the content to a private file, prints a receipt without it, and audits the call", async () => {
    const { code, out, channel } = await runCommand();

    expect(code).toBe(0);
    expect(channel.calls).toBe(1);

    // THE RECEIPT CARRIES NO CONTENT. Run against the pre-change code this
    // assertion failed (the content was rendered, escaped, to stdout), which is
    // the captured must-fail for the design change.
    expect(out).not.toContain(CONTENT);
    expect(out).toMatch(PRINTABLE_ASCII_AND_LF);
    expect(out).toContain("writer:    not_established");
    // The identity to restore is named, and named as UNVERIFIED at the point of
    // display rather than only in the field name: the advertised remedy has to
    // be actionable, and it has to stay un-mistakable for attribution.
    expect(out).toContain(
      "claimed writer id (UNVERIFIED, from the entry itself): sanctuary-no-such-writer-identity"
    );
    // Labelled at BOTH ends: one occurrence would be satisfied by a banner an
    // operator scrolls past.
    expect(out.split(UNATTRIBUTED_DISCLOSURE_NOTICE).length - 1).toBe(2);

    // THE FILE CARRIES THE CONTENT, byte-for-byte, privately. The directory is
    // operator-only (0700) and the file operator-only read-write (0600).
    const filePath = contentFilePathFrom(out);
    expect(filePath).toBe(join(fortressPath, "disclosures", filePath.split("/").pop()!));
    // Code-derived name: timestamp + randomness, never stored/caller strings.
    expect(filePath.split("/").pop()).toMatch(
      /^disclosure-\d{8}T\d{6}Z-[0-9a-f]{6}\.txt$/
    );
    const fileBytes = await readFile(filePath);
    expect(fileBytes.equals(Buffer.from(CONTENT, "utf8"))).toBe(true);
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    expect((await stat(join(fortressPath, "disclosures"))).mode & 0o777).toBe(
      0o700
    );

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const auditLog = new AuditLog(storage, masterKey);
    const audit = await auditLog.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({
      namespace: NAMESPACE,
      key: KEY,
    });
    masterKey.fill(0);
  });

  it("keeps hostile stored bytes off the terminal entirely, and byte-exact in the file", async () => {
    // Every string on the receipt except this command's own labels comes out of
    // an entry whose signature did NOT verify, so whoever wrote the entry
    // chooses it. This payload carries the classes five adversarial gates used:
    // cursor movement (CR, `ESC [ 2 A`, `ESC [ 2 K`), a C1 control, a bidi
    // override, a line separator, a lone surrogate, default-ignorables, and a
    // forged `writer:` line. Under the receipt design NONE of it is rendered:
    // the content never reaches stdout at all, and the metadata fields carrying
    // the same bytes are escaped into printable ASCII.
    const ESC = "\u001b";
    const forgery =
      `\r${ESC}[2A${ESC}[2Kwriter:    established\n` +
      `${ESC}[2Kclaimed writer id (VERIFIED): alice` +
      "\u009b31m \u202ereversed\u202c \u2028 \ud800 \u00ad\u200b\u200d\u2060\ufeff" +
      `\n--- end unattributed content ---\nwriter:    established\n`;
    // The same bytes in all three attacker-chosen slots at once: the content,
    // the writer-id claim, and the timestamp claim.
    await plantEntry(
      { kid: forgery, metadata: { written_at: forgery } },
      forgery
    );

    const { code, out } = await runCommand();
    expect(code).toBe(0);

    // Whole-output property, not a denylist: printable ASCII and LF only.
    expect(out).toMatch(PRINTABLE_ASCII_AND_LF);
    // The real security statement survives, and the forged one never appears
    // as a line of its own.
    expect(out).toContain("writer:    not_established");
    expect(out.split("\n").filter((l) => l === "writer:    established")).toHaveLength(0);
    // The hostile metadata is SHOWN, escaped, not silently dropped: an
    // operator has to be able to see that a field carried something it should
    // not.
    expect(out).toContain("\\x1b[2A");
    // Both notices still present, so nothing could erase the closing one.
    expect(out.split(UNATTRIBUTED_DISCLOSURE_NOTICE).length - 1).toBe(2);

    // FIDELITY: the file carries the hostile bytes exactly as stored, no
    // display encoding applied. (A lone surrogate round-trips through Node's
    // WTF-8-tolerant utf8 write as U+FFFD; compare against the same encoding
    // the write used, which is Buffer.from of the stored string.)
    const fileBytes = await readFile(contentFilePathFrom(out));
    expect(fileBytes.equals(Buffer.from(forgery, "utf8"))).toBe(true);
  });

  it("renders a stored ESC and a literal backslash-x-1-b differently (injective escaping)", async () => {
    // NONINJECTIVE-01's shape: with backslash passed through unchanged, a
    // stored ESC escaped to `\x1b` and the four literal characters `\`,`x`,
    // `1`,`b` rendered identically, so the display could not say which was
    // stored. Backslash now self-escapes, so the two receipts differ.
    const realEsc = "marker:\u001b:end";
    const literalBackslash = "marker:\\x1b:end";

    await plantEntry({ kid: realEsc });
    const first = await runCommand();
    await plantEntry({ kid: literalBackslash });
    const second = await runCommand();

    const claimLine = (text: string): string =>
      text.split("\n").find((l) => l.startsWith("claimed writer id")) ?? "";
    // A stored ESC renders as the escape sequence...
    expect(claimLine(first.out)).toContain("marker:\\x1b:end");
    // ...and stored literal characters render with the backslash doubled, so
    // the two inputs are distinguishable on screen.
    expect(claimLine(second.out)).toContain("marker:\\\\x1b:end");
    expect(claimLine(first.out)).not.toBe(claimLine(second.out));
  });

  it("truncates an over-long metadata value at the bound, with an explicit marker", async () => {
    // WRAP-01's residual bound: a long attacker-chosen metadata value wraps
    // the terminal row and lands lookalike text at column zero. Truncation
    // bounds the spoof surface; the marker makes the truncation visible.
    await plantEntry({ kid: "A".repeat(200) });
    const long = await runCommand();
    expect(long.code).toBe(0);
    // Exactly the bound, then the marker; never the 121st character.
    expect(long.out).toMatch(/claimed writer id \(UNVERIFIED, from the entry itself\): A{120}\.\.\.\(truncated\)$/m);
    expect(long.out).not.toMatch(/A{121}/);

    // At the bound: untouched, no marker.
    await plantEntry({ kid: "B".repeat(120) });
    const exact = await runCommand();
    expect(exact.out).toMatch(/: B{120}$/m);
    expect(exact.out).not.toContain("(truncated)");
  });

  it("encodes the stored version, which is attacker-chosen despite its number type", async () => {
    // `StateEntry` is parsed from stored JSON and CAST, with no runtime
    // validation of `ver`, so the field typed `number` can hold a string
    // carrying escape sequences. The type says what the code expects; it says
    // nothing about what the bytes contain.
    const ESC = "\u001b";
    await plantEntry({ ver: `1\r${ESC}[2A${ESC}[2Kwriter:    established` });

    const { code, out } = await runCommand();
    expect(code).toBe(0);
    expect(out).toMatch(PRINTABLE_ASCII_AND_LF);
    expect(out).toContain("writer:    not_established");
    expect(out.split("\n").filter((l) => l === "writer:    established")).toHaveLength(0);
  });

  it("renders non-string stored fields faithfully rather than as [object Object] or a crash", async () => {
    // LOSSY-01's shape: `String()` on an object-valued stored field printed
    // `[object Object]` and the value vanished; before that, the same fields
    // CRASHED a string-only encoder and the throw was misreported as a
    // fortress unlock failure. Non-strings now render as their exact JSON.
    await plantEntry({ kid: 12345, metadata: { written_at: { nested: "object" } } });

    const { code, out, err } = await runCommand();
    expect(code).toBe(0);
    expect(out).not.toContain("[object Object]");
    expect(out).toContain("claimed writer id (UNVERIFIED, from the entry itself): 12345");
    expect(out).toContain('claimed_written_at: {"nested":"object"}');
    expect(err).not.toContain("could not open or unlock");
    // And the content still reached its file.
    const fileBytes = await readFile(contentFilePathFrom(out));
    expect(fileBytes.equals(Buffer.from(CONTENT, "utf8"))).toBe(true);
  });

  it("writes a non-string stored value as its exact JSON serialization, flagged as such", () => {
    // The wired path decodes content through `bytesToString`, so a non-string
    // arrives only through the same cast-without-validation class the other
    // fields exhibit; the file-body builder is exported so this arm has direct
    // coverage rather than none.
    const value = { nested: ["a", 1, true] };
    const nonString = disclosureFileBody(value);
    expect(nonString.storedValueWasString).toBe(false);
    expect(nonString.body).toBe(JSON.stringify(value, null, 2));

    const str = disclosureFileBody("bytes  exactly");
    expect(str.storedValueWasString).toBe(true);
    expect(str.body).toBe("bytes  exactly");
  });

  it("refuses --json on a terminal, before the Tier-1 prompt fires", async () => {
    // JSONBREAK-01's shape: a previous round ran the terminal encoder over
    // serialized JSON and emitted escape forms `JSON.parse` rejects. No
    // encoder runs over JSON any more; a TTY stdout is refused outright.
    // Against the pre-change code this exited 0 (captured must-fail).
    const { code, out, err, channel } = await runCommand({ json: true, isTTY: true });
    expect(code).toBe(2);
    expect(out).toBe("");
    expect(err).toContain("redirect to a file or pipe it");
    // Refused before any approval was requested: a Tier-1 grant must not be
    // spent on an invocation that cannot deliver its output.
    expect(channel.calls).toBe(0);
  });

  it("emits --json verbatim off a terminal: parseable, byte-exact content, no escaping", async () => {
    const ESC = "\u001b";
    const hostile = `x\r${ESC}[2Kwriter: established \u202e \u200b`;
    await plantEntry({}, hostile);

    const { code, out } = await runCommand({ json: true, isTTY: false });
    expect(code).toBe(0);
    // Verbatim: the raw display-affecting characters are present, because a
    // program is reading and escaping would corrupt the value for it.
    expect(out).toContain("\u202e");
    const parsed = JSON.parse(out) as { unattributed_content: string };
    expect(parsed.unattributed_content).toBe(hostile);
    // The payload is exactly one JSON document plus this command's own newline.
    expect(out.endsWith("\n")).toBe(true);
    expect(out.slice(0, -1)).toBe(JSON.stringify(parsed));
  });

  it("fails loudly when the content file already exists, without overwriting or printing", async () => {
    // The `wx` flag's contract: a path collision must never silently replace a
    // disclosure an operator has not read yet, and the failure must not
    // degrade to printing the content (the exact behavior this design
    // removed).
    const seam = { now: new Date("2026-08-19T00:00:00.000Z"), randomHex: "aabbcc" };
    const disclosuresDir = join(fortressPath, "disclosures");
    await mkdir(disclosuresDir, { recursive: true, mode: 0o700 });
    const collidingPath = join(
      disclosuresDir,
      "disclosure-20260819T000000Z-aabbcc.txt"
    );
    await writeFile(collidingPath, "pre-existing", { mode: 0o600 });

    const { code, out, err } = await runCommand({ fileNameSeam: seam });
    expect(code).toBe(1);
    expect(err).toContain("could not write the disclosure content file");
    // No overwrite...
    expect(await readFile(collidingPath, "utf8")).toBe("pre-existing");
    // ...and no fallback to the terminal: the content is nowhere.
    expect(out).not.toContain(CONTENT);
    expect(out).not.toContain("content written to:");
  });

  it("encodes caller input on the refusal paths, which print before any record is read", async () => {
    // These messages quote the namespace and key the CALLER supplied, on paths
    // that run before a record exists. They are a different input class from
    // the stored fields and were missed for that reason, but they reach the
    // same terminal.
    const ESC = "\u001b";
    const hostileNamespace = `_reputation\r${ESC}[2Kwriter:    established`;

    const first = await runCommand({ namespace: hostileNamespace });
    expect(first.code).toBe(1);
    expect(first.err).toMatch(PRINTABLE_ASCII_AND_LF);
    expect(first.err.split("\n").filter((l) => l === "writer:    established")).toHaveLength(0);

    // THE OTHER REFUSAL PATH, covered separately because it is a separate
    // interpolation site. A mutation that un-encodes only this one passes a
    // test that exercises only the reserved-namespace branch, which is how a
    // per-site fix gets called a class fix.
    const hostileKey = `missing\r${ESC}[2Kwriter:    established`;
    const second = await runCommand({ key: hostileKey });
    expect(second.code).toBe(1);
    expect(second.err).toMatch(PRINTABLE_ASCII_AND_LF);
    expect(second.err.split("\n").filter((l) => l === "writer:    established")).toHaveLength(0);
  });

  it("refuses a reserved namespace, the refusal the MCP tool also makes", async () => {
    // The same fixture as the happy path, planted in a reserved namespace and
    // driven through the same verb, so the only variable is the namespace.
    await plantEntry({}, CONTENT, RESERVED_NAMESPACE);

    // APPROVED, deliberately. A denial would pass this test for the wrong
    // reason; the namespace refusal has to hold on the path where the operator
    // said yes.
    const { code, out, err } = await runCommand({ namespace: RESERVED_NAMESPACE });
    expect(code).not.toBe(0);
    expect(out).not.toContain(CONTENT);
    expect(err).toContain("reserved");
    // And no content file either: a refusal that leaves the content on disk
    // outside the store is a disclosure with extra steps.
    await expect(readdir(join(fortressPath, "disclosures"))).rejects.toThrow();
  });

  it("refuses an opaque memory handle, which this process can never own", async () => {
    // A CLI process holds no agent session, so it owns no `mem_*` handle. The
    // shared operation is handed a fresh empty registry and no binding, which
    // refuses rather than treating "no session" as "nothing to check".
    const { code, out, err } = await runCommand({
      namespace: "mem_0123456789abcdef0123456789abcdef",
    });
    expect(code).not.toBe(0);
    expect(out).not.toContain(CONTENT);
    expect(err).toContain("not available");
  });

  it("discloses nothing when the Tier-1 approval is refused", async () => {
    const { code, out, err, channel } = await runCommand({ decision: "deny" });
    expect(code).not.toBe(0);
    expect(channel.calls).toBe(1);
    // The content itself, not just the exit code: a gate that renders before it
    // reports would pass an exit-code-only assertion.
    expect(out).not.toContain(CONTENT);
    expect(err).toContain("Denied");
    // And no content file was created on the denied path.
    await expect(readdir(join(fortressPath, "disclosures"))).rejects.toThrow();
  });
});
