// On the shipped file store, recall's newest-first order reads the modification times the host file system keeps
// for each passage's document file, as FilesystemStorage.list reports them. The times are set with utimes against
// key order, so a scan that fell back to key order commits the passages in the opposite order.
import { mkdtemp, readdir, rm, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { HermesRecallBudget, RECALL_READ_AHEAD_PASSAGES } from "../../src/hermes-memory-bridge/recall.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { decodeRawFilesystemStorageName } from "../../src/storage/filesystem-name-codec.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const CREATED = "2026-11-01T00:00:00.000Z";
const PASSAGES = 2 * RECALL_READ_AHEAD_PASSAGES; // Two read-ahead windows, so the order spans more than one fill.
const id = (n: number) => `p${n}`;
const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

/** Every stored file under root whose decoded key is a document key, by key. */
async function documentFiles(root: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".enc")) continue;
    const key = decodeRawFilesystemStorageName(entry.name.slice(0, -".enc".length), "key");
    if (key.startsWith("doc.")) files.set(key, join(entry.parentPath, entry.name));
  }
  return files;
}

/** Records the order the commit scored passages in; every passage matches, so it scores each one it decides. */
class ScoreOrderBudget extends HermesRecallBudget {
  readonly scored: string[] = [];
  override score(...args: Parameters<HermesRecallBudget["score"]>) { this.scored.push(args[0].passage_id); return super.score(...args); }
}

it("scans the most recently modified document files first on FilesystemStorage", async () => {
  const root = await mkdtemp(join(tmpdir(), "recall-newest-first-"));
  dirs.push(root);
  const storage = new FilesystemStorage(root);
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: new Uint8Array(32).fill(61), fortressId: "newest-first-fs",
    ownerRef: "agent", now: () => CREATED });
  for (let n = 0; n < PASSAGES; n++) await adapter.insertPassage({ passage_id: id(n), text: `alpha note ${n}` }, "user_content");
  const files = await documentFiles(root);
  expect(files.size).toBe(PASSAGES);
  // Against key order: the higher the passage number, the more recent its file's modification time, a minute apart.
  const base = Date.parse(CREATED) / 1000;
  for (let n = 0; n < PASSAGES; n++) {
    const at = base + 60 * n;
    await utimes(files.get(`doc.mem.agent.${id(n)}`)!, at, at);
  }
  const budget = new ScoreOrderBudget("alpha", () => 0, new AbortController().signal);
  await adapter.recallPassages(budget);
  expect(budget.scored).toEqual(Array.from({ length: PASSAGES }, (_, k) => id(PASSAGES - 1 - k)));
});
