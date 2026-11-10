/** Liveness record publication and the read-only reader: custody, single flight, atomic replacement and strict reads. */
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LABEL_BYTES, STATUS_BYTES } from "../../../src/castle-wall/liveness/constants.js";
import { evaluateLiveness } from "../../../src/castle-wall/liveness/evaluate.js";
import { readLivenessRecords } from "../../../src/castle-wall/liveness/read-status.js";
import {
  LivenessRecordPublisher,
  nodePublisherFs,
  parsePublicationClaim,
  PUBLICATION_CLAIM_BYTES,
  serializePublicationClaim,
  type PublisherFs,
} from "../../../src/castle-wall/liveness/record-store.js";

const UID = process.getuid?.() ?? 0;
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { chmodSync(root, 0o700); rmSync(root, { recursive: true, force: true }); } });
function fortress(): string {
  const root = mkdtempSync(join(tmpdir(), "lv-store-"));
  roots.push(root);
  return root;
}
/** Every fixture publisher runs on one boot; a later start uptime is the newer instance. */
const BOOT = "boot-fixture";
const publisher = (fortressPath: string, instance = "aaaaaaaaaaaaaaaa", fs?: PublisherFs, startedUptimeMs = 1_000) =>
  new LivenessRecordPublisher({ fortressPath, fileName: "daemon.json", instance, bootId: BOOT, instanceStartedUptimeMs: startedUptimeMs, operatorUid: UID, fs });
const target = (root: string) => join(root, "liveness", "daemon.json");
/** After a settled publication only the record and the publication claim remain: no temp file. */
const SETTLED_ENTRIES = ["daemon.json", "daemon.json.publisher"];

describe("publication", () => {
  it("creates an owner-only directory and an owner-only record", async () => {
    const root = fortress();
    await publisher(root).publish({ sequence: 1 });
    expect(statSync(join(root, "liveness")).mode & 0o777).toBe(0o700);
    expect(statSync(target(root)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(target(root), "utf8"))).toEqual({ sequence: 1 });
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(SETTLED_ENTRIES);
    expect(statSync(join(root, "liveness", "daemon.json.publisher")).mode & 0o777).toBe(0o600);
  });

  it("is single flight: one write in flight and only the newest waiting record follows it", async () => {
    const root = fortress();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let renames = 0;
    // Only renames over the record count; the publication claim's own rename is not a record write.
    const fs: PublisherFs = { ...nodePublisherFs, rename: async (from, to) => { if (to !== target(root)) return nodePublisherFs.rename(from, to); renames++; if (renames === 1) await gate; return nodePublisherFs.rename(from, to); } };
    const p = publisher(root, "aaaaaaaaaaaaaaaa", fs);
    const first = p.publish({ sequence: 1 });
    await new Promise(resolve => setTimeout(resolve, 20));
    void p.publish({ sequence: 2 });
    const third = p.publish({ sequence: 3 });
    release();
    await Promise.all([first, third]);
    expect(renames).toBe(2);
    expect(JSON.parse(readFileSync(target(root), "utf8"))).toEqual({ sequence: 3 });
    expect(p.stats()).toEqual({ published: 2, failures: 0 });
  });

  it("keeps the old target and removes its temp when a write fails", async () => {
    const root = fortress();
    await publisher(root).publish({ sequence: 1 });
    const recordTemp = join(root, "liveness", "daemon.json.bbbbbbbbbbbbbbbb.tmp");
    const fs: PublisherFs = { ...nodePublisherFs, open: async (path, flags, mode) => {
      const handle = await nodePublisherFs.open(path, flags, mode);
      if (path !== recordTemp) return handle;
      return { stat: () => handle.stat(), read: (b, o, l, p) => handle.read(b, o, l, p), close: () => handle.close(), sync: () => handle.sync(), writeFile: async () => { throw new Error("fixture write failure"); } };
    } };
    // A newer instance on the same boot claims the record, then its record write fails.
    await expect(publisher(root, "bbbbbbbbbbbbbbbb", fs, 2_000).publish({ sequence: 2 })).rejects.toThrow("fixture write failure");
    expect(JSON.parse(readFileSync(target(root), "utf8"))).toEqual({ sequence: 1 });
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(SETTLED_ENTRIES);
  });

  it("removes the superseded instance's temps on its first publish and never trusts them", async () => {
    const root = fortress();
    mkdirSync(join(root, "liveness"), { mode: 0o700 });
    const earlier = "0000000000000000";
    writeFileSync(join(root, "liveness", "daemon.json.publisher"), serializePublicationClaim({ instance: earlier, boot_id: BOOT, instance_started_uptime_ms: 500 }), { mode: 0o600 });
    writeFileSync(join(root, "liveness", `daemon.json.${earlier}.tmp`), JSON.stringify({ sequence: 99 }), { mode: 0o600 });
    writeFileSync(join(root, "liveness", `daemon.json.${earlier}.publisher.tmp`), "{}\n", { mode: 0o600 });
    await publisher(root).publish({ sequence: 1 });
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(SETTLED_ENTRIES);
    expect(JSON.parse(readFileSync(target(root), "utf8"))).toEqual({ sequence: 1 });
    expect(parsePublicationClaim(readFileSync(join(root, "liveness", "daemon.json.publisher"), "utf8"))?.instance).toBe("aaaaaaaaaaaaaaaa");
  });

  it("parses only the canonical claim serialization, and the largest valid claim is PUBLICATION_CLAIM_BYTES", () => {
    const claim = { instance: "aaaaaaaaaaaaaaaa", boot_id: BOOT, instance_started_uptime_ms: 1_000 };
    const text = serializePublicationClaim(claim);
    expect(parsePublicationClaim(text)).toEqual(claim);
    expect(parsePublicationClaim(serializePublicationClaim({ ...claim, boot_id: null }))).toEqual({ ...claim, boot_id: null });
    for (const refused of [
      text.trimEnd(),
      ` ${text}`,
      `${JSON.stringify({ boot_id: BOOT, instance: claim.instance, instance_started_uptime_ms: 1_000 })}\n`,
      `${JSON.stringify({ ...claim, extra: true })}\n`,
      `${JSON.stringify({ instance: claim.instance, boot_id: BOOT })}\n`,
      `${JSON.stringify({ ...claim, instance: "" })}\n`,
      `${JSON.stringify({ ...claim, instance: "a/b" })}\n`,
      `${JSON.stringify({ ...claim, instance: "x".repeat(LABEL_BYTES + 1) })}\n`,
      `${JSON.stringify({ ...claim, instance_started_uptime_ms: -1 })}\n`,
      `${JSON.stringify({ ...claim, instance_started_uptime_ms: 1.5 })}\n`,
      "null\n",
      "[]\n",
    ]) expect(parsePublicationClaim(refused), refused).toBeNull();
    const largest = serializePublicationClaim({ instance: "x".repeat(LABEL_BYTES), boot_id: "y".repeat(LABEL_BYTES), instance_started_uptime_ms: Number.MAX_SAFE_INTEGER });
    expect(parsePublicationClaim(largest)).not.toBeNull();
    expect(Buffer.byteLength(largest)).toBe(PUBLICATION_CLAIM_BYTES);
  });

  it("refuses a liveness directory writable by group or other", async () => {
    const root = fortress();
    mkdirSync(join(root, "liveness"), { mode: 0o700 });
    chmodSync(join(root, "liveness"), 0o777);
    await expect(publisher(root).publish({ sequence: 1 })).rejects.toThrow("custody");
    expect(existsSync(target(root))).toBe(false);
    chmodSync(join(root, "liveness"), 0o700);
  });

  it("refuses a record above STATUS_BYTES", async () => {
    const root = fortress();
    await expect(publisher(root).publish({ pad: "x".repeat(STATUS_BYTES) })).rejects.toThrow("byte cap");
    expect(existsSync(target(root))).toBe(false);
  });
});

describe("reader", () => {
  const local = (root: string) => ({ fortressPath: root, operatorUid: UID });
  async function write(root: string, name: string, body: string, mode = 0o600) {
    mkdirSync(join(root, "liveness"), { recursive: true, mode: 0o700 });
    writeFileSync(join(root, "liveness", name), body, { mode });
    chmodSync(join(root, "liveness", name), mode);
  }

  it("reads absent records from a missing liveness directory", async () => {
    const result = await readLivenessRecords(local(fortress()));
    expect(result.directory).toEqual({ status: "absent" });
    expect(result.daemon).toEqual({ status: "absent" });
  });

  it("reads a present record and leaves every byte and mode unchanged", async () => {
    const root = fortress();
    await write(root, "daemon.json", JSON.stringify({ sequence: 1 }));
    const before = readFileSync(target(root));
    const result = await readLivenessRecords(local(root));
    expect(result.daemon).toEqual({ status: "present", value: { sequence: 1 } });
    expect(readFileSync(target(root))).toEqual(before);
    expect(statSync(target(root)).mode & 0o777).toBe(0o600);
  });

  it("refuses a record readable by group or other without repairing it", async () => {
    const root = fortress();
    await write(root, "daemon.json", "{}", 0o644);
    expect((await readLivenessRecords(local(root))).daemon).toEqual({ status: "custody_invalid", cause: "mode" });
    expect(statSync(target(root)).mode & 0o777).toBe(0o644);
  });

  it("refuses another owner", async () => {
    const root = fortress();
    await write(root, "daemon.json", "{}");
    expect((await readLivenessRecords({ fortressPath: root, operatorUid: UID + 1 })).directory).toEqual({ status: "custody_invalid", cause: "owner" });
  });

  it("refuses a liveness directory writable by group or other", async () => {
    const root = fortress();
    await write(root, "daemon.json", "{}");
    chmodSync(join(root, "liveness"), 0o777);
    expect((await readLivenessRecords(local(root))).directory).toEqual({ status: "custody_invalid", cause: "mode" });
    chmodSync(join(root, "liveness"), 0o700);
  });

  it("refuses an oversized record and reads invalid JSON as unparsable", async () => {
    const root = fortress();
    await write(root, "daemon.json", "x".repeat(STATUS_BYTES + 1));
    await write(root, "observer.json", "{not json");
    const result = await readLivenessRecords(local(root));
    expect(result.daemon).toEqual({ status: "custody_invalid", cause: "size" });
    expect(result.observer).toEqual({ status: "unparsable" });
  });

  it("a stored verdict field read from disk is observation_invalid on its component", async () => {
    const root = fortress();
    const states = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8"));
    const daemon = { ...states.base.daemon.value, raw: { ...states.base.daemon.value.raw, increased: true } };
    await write(root, "daemon.json", JSON.stringify(daemon));
    const read = await readLivenessRecords(local(root));
    const envelope = evaluateLiveness({ ...states.base, daemon: read.daemon });
    expect(envelope.wall.reasons).toContain("observation_invalid");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });
});
