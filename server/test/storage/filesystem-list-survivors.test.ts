import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, stat: vi.fn(actual.stat) };
});
let root: string;
beforeEach(async () => { root = await fs.mkdtemp(join(tmpdir(), "list-survivors-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await fs.rm(root, { recursive: true, force: true }); });
it("one per-file stat ENOENT retains every surviving candidate", async () => {
  const storage = new FilesystemStorage(root);
  for (const name of ["a", "b", "c"]) await storage.write("_audit", name, Buffer.from(name));
  const original = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  vi.mocked(fs.stat).mockImplementation((async (...args: Parameters<typeof fs.stat>) => {
    if (String(args[0]) === join(root, "_audit", "b.enc")) throw Object.assign(new Error("vanished"), { code: "ENOENT" });
    return original.stat(...args);
  }) as typeof fs.stat);
  expect((await storage.list("_audit")).map(({ key }) => key)).toEqual(["a", "c"]);
});
it("a successful enumeration without matching entries returns an empty list", async () => {
  const storage = new FilesystemStorage(root);
  await storage.write("_audit", "other", Buffer.from("body"));
  expect(await storage.list("_audit", "entry-")).toEqual([]);
});
