/**
 * A read fault on an installed file after its open and fstat succeeded: the
 * refusal must say the file could not be read, not that its bytes differ.
 * The fault is injected by wrapping `open` from `node:fs/promises`, so the
 * production walk and its descriptor checks run unchanged up to the read.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RUN_DEADLINE_MS } from "../../src/verify-release/constants.js";
import { Deadline } from "../../src/verify-release/deadline.js";
import { state_ARCHIVE } from "../../src/verify-release/archive.js";
import { state_INSTALLED } from "../../src/verify-release/installed.js";
import { ManualClock, denyAllNetwork, tgz } from "./helpers.js";

const fault = vi.hoisted(() => ({ name: undefined as string | undefined }));

vi.mock("node:fs/promises", async importOriginal => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      if (fault.name === undefined || basename(String(args[0])) !== fault.name) return handle;
      // The descriptor is real, so its fstat passes; only reading fails, as an I/O error would.
      return Object.assign(Object.create(handle) as typeof handle, {
        stat: () => handle.stat(),
        close: () => handle.close(),
        read: () => Promise.reject(Object.assign(new Error("injected read fault"), { code: "EIO" })),
      });
    },
  };
});

denyAllNetwork();

const roots: string[] = [];
afterEach(() => {
  fault.name = undefined;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const FILES: Record<string, string> = { "package.json": "{}", "README.md": "readme", "dist/cli.js": "x" };

async function run(): Promise<unknown> {
  const root = mkdtempSync(join(tmpdir(), "vr-read-fault-"));
  roots.push(root);
  for (const [path, body] of Object.entries(FILES)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  const deadline = new Deadline(new ManualClock(), RUN_DEADLINE_MS);
  try {
    const archive = await state_ARCHIVE(tgz(Object.entries(FILES).map(([path, body]) => ({ path: `package/${path}`, body }))), deadline);
    if (!archive.ok) throw new Error(`archive fixture refused: ${archive.reason}`);
    return await state_INSTALLED(root, archive.evidence, deadline);
  } finally {
    deadline.dispose();
  }
}

describe("read faults", () => {
  it("without a fault the install passes, so the wrapper alone changes nothing", async () => {
    expect(await run()).toEqual({ ok: true, evidence: { state: "state_INSTALLED", fileCount: 3 } });
  });

  it("a read error after a successful open and fstat refuses installed-file-unreadable, not installed-file-differs", async () => {
    fault.name = "README.md";
    expect(await run()).toEqual({ ok: false, reason: "installed-file-unreadable:README.md" });
  });
});
