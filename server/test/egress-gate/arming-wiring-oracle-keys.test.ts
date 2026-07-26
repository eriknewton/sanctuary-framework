/**
 * Fix-round-2 LOW-8: `ensureSupervisorOracleKeys` must write the oracle key
 * files ATOMICALLY (tmp + rename), never in place. The running gate daemon
 * pins + re-reads the PUBLIC key file; an in-place rewrite leaves a
 * partial-PEM window in which every per-CONNECT verify fails. This suite
 * mocks node:fs/promises wholesale (own file: the mock is module-global) and
 * pins that the final key paths are only ever RENAME destinations -- a
 * direct writeFile at a final path is the pre-fix defect.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";

const fsState: {
  files: Map<string, string>;
  writes: { path: string; mode?: number }[];
  renames: { from: string; to: string }[];
} = { files: new Map(), writes: [], renames: [] };

vi.mock("node:fs/promises", () => ({
  mkdir: vi.fn(async () => undefined),
  chmod: vi.fn(async () => undefined),
  readFile: vi.fn(async (path: string) => {
    const v = fsState.files.get(path);
    if (v === undefined) {
      const err = new Error(`ENOENT: ${path}`) as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    }
    return v;
  }),
  writeFile: vi.fn(async (path: string, content: string | Buffer, options?: { mode?: number }) => {
    fsState.files.set(path, content.toString());
    fsState.writes.push({ path, ...(options?.mode !== undefined ? { mode: options.mode } : {}) });
  }),
  rename: vi.fn(async (from: string, to: string) => {
    const v = fsState.files.get(from);
    if (v === undefined) throw new Error(`rename source missing: ${from}`);
    fsState.files.delete(from);
    fsState.files.set(to, v);
    fsState.renames.push({ from, to });
  }),
  rm: vi.fn(async (path: string) => void fsState.files.delete(path)),
  open: vi.fn(async () => ({ close: async () => undefined })),
  unlink: vi.fn(async () => undefined),
  access: vi.fn(async () => undefined),
}));

import {
  ensureSupervisorOracleKeys,
  GATE_ORACLE_PRIVATE_KEY_PATH,
} from "../../src/egress-gate/arming-wiring.js";
import { GATE_ORACLE_PUBLIC_KEY_PATH } from "../../src/egress-gate/gate-daemon.js";

beforeEach(() => {
  fsState.files.clear();
  fsState.writes.length = 0;
  fsState.renames.length = 0;
});

describe("ensureSupervisorOracleKeys (fix-round-2 LOW-8: atomic key writes)", () => {
  it("re-asserting the public key over an EXISTING private key uses tmp+rename, never an in-place write", async () => {
    const pair = generateKeyPairSync("ed25519");
    fsState.files.set(
      GATE_ORACLE_PRIVATE_KEY_PATH,
      pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    );
    const keys = await ensureSupervisorOracleKeys();
    expect(keys.publicKey.export({ type: "spki", format: "pem" }).toString()).toBe(
      pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    );
    // The pinned public-key path is ONLY ever a rename destination.
    expect(fsState.writes.map((w) => w.path)).not.toContain(GATE_ORACLE_PUBLIC_KEY_PATH);
    expect(fsState.renames.map((r) => r.to)).toContain(GATE_ORACLE_PUBLIC_KEY_PATH);
    // The healed file is a complete PEM (the rename landed the full content).
    expect(fsState.files.get(GATE_ORACLE_PUBLIC_KEY_PATH)).toContain("BEGIN PUBLIC KEY");
    // No tmp residue left behind.
    expect([...fsState.files.keys()].filter((p) => p.includes(".tmp-"))).toEqual([]);
  });

  it("fresh key generation writes BOTH halves atomically with the right modes (0600 private, 0644 public)", async () => {
    await ensureSupervisorOracleKeys();
    const renamedTo = fsState.renames.map((r) => r.to);
    expect(renamedTo).toContain(GATE_ORACLE_PRIVATE_KEY_PATH);
    expect(renamedTo).toContain(GATE_ORACLE_PUBLIC_KEY_PATH);
    // Neither final path was a direct writeFile target.
    const directWrites = fsState.writes.map((w) => w.path);
    expect(directWrites).not.toContain(GATE_ORACLE_PRIVATE_KEY_PATH);
    expect(directWrites).not.toContain(GATE_ORACLE_PUBLIC_KEY_PATH);
    // The tmp files carried the intended modes (rename preserves them).
    const privTmp = fsState.writes.find((w) => w.path.startsWith(GATE_ORACLE_PRIVATE_KEY_PATH));
    const pubTmp = fsState.writes.find((w) => w.path.startsWith(GATE_ORACLE_PUBLIC_KEY_PATH));
    expect(privTmp?.mode).toBe(0o600);
    expect(pubTmp?.mode).toBe(0o644);
    // Idempotent second call loads the persisted private key back.
    const again = await ensureSupervisorOracleKeys();
    expect(again.privateKey.export({ type: "pkcs8", format: "pem" }).toString()).toBe(
      fsState.files.get(GATE_ORACLE_PRIVATE_KEY_PATH),
    );
  });
});
