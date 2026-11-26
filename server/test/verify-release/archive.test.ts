/**
 * The archive step over synthetic tarballs built in memory: accepted shapes,
 * every refused entry type and path, duplicates, conflicts, case-fold
 * collisions, truncation, each cap, and the deadline during parsing.
 */
import { createGzip, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_EXPANDED_BYTES, MAX_ARCHIVE_FILE_BYTES, MAX_ARCHIVE_PATH_LENGTH, RUN_DEADLINE_MS } from "../../src/verify-release/constants.js";
import { Deadline, type Clock } from "../../src/verify-release/deadline.js";
import { archiveKey, state_ARCHIVE } from "../../src/verify-release/archive.js";
import { simpleFold } from "../../src/verify-release/names.js";
import { ManualClock, denyAllNetwork, sha256Hex, tarBytes, tgz, type TarEntrySpec } from "./helpers.js";

denyAllNetwork();

const parse = (bytes: Buffer, clock: Clock = new ManualClock()) => {
  const deadline = new Deadline(clock, RUN_DEADLINE_MS);
  return state_ARCHIVE(bytes, deadline).finally(() => deadline.dispose());
};
const file = (path: string, body = path): TarEntrySpec => ({ path, body });

describe("accepted archives", () => {
  it("maps regular files under package/ to sha256 and size, with implicit and explicit directories", async () => {
    const result = await parse(tgz([
      { path: "package/", type: "5" },
      file("package/package.json", "{}"),
      file("package/dist/cli.js", "#!/usr/bin/env node\n"),
      { path: "package/empty/", type: "5" },
      { path: "package/old.txt", type: "\0", body: "pre-POSIX regular file" },
    ]));
    expect(result.ok).toBe(true);
    const evidence = (result as any).evidence;
    expect([...evidence.files.keys()].sort()).toEqual(["dist/cli.js", "old.txt", "package.json"]);
    expect(evidence.files.get("package.json")).toEqual({ sha256: sha256Hex(Buffer.from("{}")), size: 2 });
    expect([...evidence.directories].sort()).toEqual(["dist", "empty"]);
  });

  it("keys names in NFC", async () => {
    const nfd = "package/café.txt";
    const result = await parse(tgz([file(nfd, "x")]));
    expect([...(result as any).evidence.files.keys()]).toEqual(["café.txt"]);
  });

  it("follows a pax path record for a long name", async () => {
    const long = `package/${"d/".repeat(60)}file.txt`;
    const result = await parse(tgz([file(long, "x")]));
    expect([...(result as any).evidence.files.keys()]).toEqual([long.slice("package/".length)]);
  });
});

describe("refused entry types", () => {
  it.each([
    ["symlink", { path: "package/link", type: "2", linkpath: "../../etc/passwd" }],
    ["hardlink", { path: "package/hard", type: "1", linkpath: "package/a" }],
    ["character device", { path: "package/tty", type: "3" }],
    ["block device", { path: "package/disk", type: "4" }],
    ["fifo", { path: "package/pipe", type: "6" }],
    ["contiguous file", { path: "package/contig", type: "7", body: "x" }],
  ] as const)("a %s refuses archive-entry-type with its path", async (_label, entry) => {
    const result = await parse(tgz([file("package/a"), entry as TarEntrySpec]));
    expect(result).toEqual({ ok: false, reason: `archive-entry-type:${entry.path}` });
  });
});

describe("refused paths", () => {
  it.each([
    ["a .. segment", "package/../escape", "archive-invalid:dot-dot-segment"],
    ["an inner .. segment", "package/a/../b", "archive-invalid:dot-dot-segment"],
    ["an absolute path", "/etc/passwd", "archive-invalid:absolute-path"],
    ["a path outside package/", "other/file", "archive-invalid:outside-package"],
    ["an empty segment", "package//file", "archive-invalid:empty-segment"],
    ["a . segment", "package/./file", "archive-invalid:empty-segment"],
  ])("%s refuses", async (_label, path, reason) => {
    expect(await parse(tgz([file(path)]))).toEqual({ ok: false, reason });
  });

  it("archiveKey removes exactly one package/ prefix", () => {
    expect(archiveKey("package/package/x", false)).toEqual({ ok: true, key: "package/x" });
    expect(archiveKey("package/d/", true)).toEqual({ ok: true, key: "d" });
    expect(archiveKey("package/", true)).toEqual({ ok: true, key: "" });
    // A regular file cannot be the package root itself (node-tar already rejects that header shape).
    expect(archiveKey("package/", false)).toEqual({ ok: false, reason: "archive-invalid:empty-segment" });
  });
});

describe("duplicates, conflicts and collisions", () => {
  it.each([
    ["a duplicate file", [file("package/a"), file("package/a")], "archive-invalid:duplicate"],
    ["a duplicate explicit directory", [{ path: "package/d/", type: "5" }, { path: "package/d/", type: "5" }], "archive-invalid:duplicate"],
    ["NFC and NFD spellings of one name", [file("package/café"), file("package/café")], "archive-invalid:duplicate"],
    ["a file under a file", [file("package/a"), file("package/a/b")], "archive-invalid:file-directory-conflict"],
    ["a file where a directory was implied", [file("package/a/b"), file("package/a")], "archive-invalid:file-directory-conflict"],
    ["a file where a directory was explicit", [{ path: "package/a/", type: "5" }, file("package/a")], "archive-invalid:file-directory-conflict"],
    ["a directory where a file was", [file("package/a"), { path: "package/a/", type: "5" }], "archive-invalid:file-directory-conflict"],
    ["a directory under a file", [file("package/a"), { path: "package/a/b/", type: "5" }], "archive-invalid:file-directory-conflict"],
    ["a case-fold file collision", [file("package/Read.md"), file("package/read.md")], "archive-invalid:case-fold-collision"],
    ["a case-fold collision of an implicit parent", [file("package/Dir/x"), file("package/dir/y")], "archive-invalid:case-fold-collision"],
    ["a collision through the long s", [file("package/ſtate"), file("package/state")], "archive-invalid:case-fold-collision"],
    ["a collision through the Kelvin sign", [file("package/Key"), file("package/key")], "archive-invalid:case-fold-collision"],
  ] as const)("%s refuses", async (_label, entries, reason) => {
    expect(await parse(tgz(entries as unknown as TarEntrySpec[]))).toEqual({ ok: false, reason });
  });

  it("folds without a locale and keeps sharp s distinct from ss", () => {
    expect(simpleFold("I")).toBe("i");
    expect(simpleFold("İ")).toBe("İ");
    expect(simpleFold("ß")).toBe("ß");
    expect(simpleFold("ẞ")).toBe("ß");
    expect(simpleFold("ς")).toBe(simpleFold("Σ"));
  });
});

describe("damaged archives", () => {
  it("a tar truncated inside a file body refuses archive-invalid", async () => {
    const whole = tarBytes([file("package/a", "x".repeat(2000))], { endBlocks: false });
    const result = await parse(gzipSync(whole.subarray(0, 1024)));
    expect((result as { reason: string }).reason).toMatch(/^archive-invalid:/);
  });
  it("a truncated gzip stream refuses archive-invalid:gzip", async () => {
    const whole = tgz([file("package/a", "x".repeat(5000))]);
    expect(await parse(whole.subarray(0, whole.length - 10))).toEqual({ ok: false, reason: "archive-invalid:gzip" });
  });
  it("bytes that are not gzip refuse archive-invalid:gzip", async () => {
    expect(await parse(Buffer.from("not a tarball"))).toEqual({ ok: false, reason: "archive-invalid:gzip" });
  });
  it("gzip of bytes that are not tar refuses archive-invalid", async () => {
    const result = await parse(gzipSync(Buffer.alloc(4096, 0x41)));
    expect((result as { reason: string }).reason).toMatch(/^archive-invalid:/);
  });
  it("a header checksum failure refuses archive-invalid", async () => {
    const bytes = tarBytes([file("package/a")]);
    bytes[0] ^= 0x01;
    const result = await parse(gzipSync(bytes));
    expect((result as { reason: string }).reason).toMatch(/^archive-invalid:/);
  });
});

describe("caps", () => {
  it("more than MAX_ARCHIVE_ENTRIES entries refuses archive-oversize:entry-count", async () => {
    const entries = Array.from({ length: MAX_ARCHIVE_ENTRIES + 1 }, (_, i) => file(`package/f${i}`, ""));
    expect(await parse(tgz(entries))).toEqual({ ok: false, reason: "archive-oversize:entry-count" });
  });
  it("exactly MAX_ARCHIVE_ENTRIES entries passes", async () => {
    const entries = Array.from({ length: MAX_ARCHIVE_ENTRIES }, (_, i) => file(`package/f${i}`, ""));
    expect((await parse(tgz(entries))).ok).toBe(true);
  });
  it("a file declaring more than MAX_ARCHIVE_FILE_BYTES refuses archive-oversize:file-size before its body", async () => {
    const header = tarBytes([{ path: "package/big", body: "", size: MAX_ARCHIVE_FILE_BYTES + 1 }], { endBlocks: false });
    expect(await parse(gzipSync(header))).toEqual({ ok: false, reason: "archive-oversize:file-size" });
  });
  it("a path longer than MAX_ARCHIVE_PATH_LENGTH refuses archive-oversize:path-length", async () => {
    const long = `package/${"x".repeat(MAX_ARCHIVE_PATH_LENGTH)}`;
    expect(await parse(tgz([file(long, "")]))).toEqual({ ok: false, reason: "archive-oversize:path-length" });
  });
  it("a small compressed archive that inflates past MAX_ARCHIVE_EXPANDED_BYTES refuses archive-oversize:expanded-bytes", async () => {
    // Zero-filled files under the per-file cap, gzipped as a stream: about half a megabyte compressed.
    const perFile = MAX_ARCHIVE_FILE_BYTES - 1;
    const count = Math.ceil(MAX_ARCHIVE_EXPANDED_BYTES / perFile) + 1;
    const gzip = createGzip({ level: 9 });
    const out: Buffer[] = [];
    gzip.on("data", chunk => out.push(chunk));
    const done = new Promise(resolve => gzip.on("end", resolve));
    const zeros = Buffer.alloc(1024 * 1024);
    for (let i = 0; i < count; i++) {
      gzip.write(tarBytes([{ path: `package/z${i}`, body: "", size: perFile }], { endBlocks: false }));
      for (let left = perFile; left > 0; left -= zeros.length) {
        if (!gzip.write(zeros.subarray(0, Math.min(left, zeros.length)))) await new Promise(resolve => gzip.once("drain", resolve));
      }
      gzip.write(Buffer.alloc((512 - (perFile % 512)) % 512));
    }
    gzip.end();
    await done;
    const compressed = Buffer.concat(out);
    expect(compressed.length).toBeLessThan(2 * 1024 * 1024);
    expect(await parse(compressed)).toEqual({ ok: false, reason: "archive-oversize:expanded-bytes" });
  }, 120_000);
});

describe("deadline", () => {
  it("expiry during parsing refuses deadline-exceeded", async () => {
    const clock = new ManualClock();
    let reads = 0;
    // Time passes as the parser checks it: the deadline falls inside the archive.
    clock.now = () => (++reads > 20 ? RUN_DEADLINE_MS : 0);
    const entries = Array.from({ length: 100 }, (_, i) => file(`package/f${i}`, "x"));
    expect(await parse(tgz(entries), clock)).toEqual({ ok: false, reason: "deadline-exceeded" });
  });
  it("an expired deadline before parsing refuses deadline-exceeded", async () => {
    const clock = new ManualClock();
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    clock.advance(RUN_DEADLINE_MS);
    expect(await state_ARCHIVE(tgz([file("package/a")]), deadline)).toEqual({ ok: false, reason: "deadline-exceeded" });
  });
  it("an abort inside one large entry stops the parse at once, with no entry boundary to check at", async () => {
    const clock = new ManualClock();
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    const pending = state_ARCHIVE(tgz([{ path: "package/big", body: Buffer.alloc(80 * 1024 * 1024) }]), deadline);
    await new Promise(resolve => setTimeout(resolve, 20));
    clock.advance(RUN_DEADLINE_MS);
    expect(await pending).toEqual({ ok: false, reason: "deadline-exceeded" });
  }, 60_000);
  it("an abort of the run signal while parsing refuses deadline-exceeded", async () => {
    const clock = new ManualClock();
    const deadline = new Deadline(clock, RUN_DEADLINE_MS);
    const entries = Array.from({ length: 400 }, (_, i) => file(`package/f${i}`, "y".repeat(4000)));
    const pending = state_ARCHIVE(tgz(entries), deadline);
    clock.advance(RUN_DEADLINE_MS);
    expect(await pending).toEqual({ ok: false, reason: "deadline-exceeded" });
  });
});
