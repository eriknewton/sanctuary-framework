/**
 * Unit tests for the generation-bound, current-only bearer credential (Slice 5
 * S5-3). Authority + verify are pure over injected ops; a guarded FS round-trip
 * (self-uid, isolated tmpdir) covers the atomic-write/chown path.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GateCredentialAuthority,
  formatGateCredentialBasicHeader,
  formatGateCredentialHeader,
  GATE_PROXY_BASIC_USERNAME,
  parseGateCredentialHeader,
  verifyGateCredential,
  mintGateSecret,
  createFsGateCredentialAuthority,
  createFsGateAcceptSource,
  GATE_CREDENTIAL_VERSION,
  type GateCredentialAcceptRecord,
  type GateCredentialAuthorityOps,
} from "../../src/egress-gate/gate-credential.js";

function sha256Hex(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

/** A recording authority-ops mock over in-memory files. */
function recordingOps(secret = "abcd1234"): {
  ops: GateCredentialAuthorityOps;
  files: Map<string, string>;
  order: string[];
} {
  const files = new Map<string, string>();
  const order: string[] = [];
  const ops: GateCredentialAuthorityOps = {
    mintSecret: () => secret,
    writeAccept: (uid, payload) => {
      order.push(`accept:${uid}`);
      files.set(`${uid}.accept`, payload);
      return Promise.resolve();
    },
    writeToken: (uid, payload) => {
      order.push(`token:${uid}`);
      files.set(`${uid}.token`, payload);
      return Promise.resolve();
    },
    remove: (uid) => {
      order.push(`remove:${uid}`);
      files.delete(`${uid}.accept`);
      files.delete(`${uid}.token`);
      return Promise.resolve();
    },
  };
  return { ops, files, order };
}

describe("egress-gate/gate-credential parse/format", () => {
  it("round-trips a formatted header", () => {
    const header = formatGateCredentialHeader({ generation_id: 7, secret: "deadbeef" });
    expect(header).toBe("Sanctuary-Gate 7.deadbeef");
    expect(parseGateCredentialHeader(header)).toEqual({ generation_id: 7, secret: "deadbeef" });
  });

  it("round-trips a standard Basic proxy credential with the fixed username and same password payload", () => {
    const header = formatGateCredentialBasicHeader({ generation_id: 7, secret: "deadbeef" });
    expect(header).toBe(`Basic ${Buffer.from(`${GATE_PROXY_BASIC_USERNAME}:7.deadbeef`, "utf8").toString("base64")}`);
    expect(parseGateCredentialHeader(header)).toEqual({ generation_id: 7, secret: "deadbeef" });
  });

  it("rejects absent, wrong-scheme, array, and malformed headers (fail-closed parse)", () => {
    expect(parseGateCredentialHeader(undefined)).toBeNull();
    expect(parseGateCredentialHeader(["Sanctuary-Gate 1.aa", "x"])).toBeNull(); // duplicated header
    expect(parseGateCredentialHeader("Bearer 1.aa")).toBeNull();
    expect(parseGateCredentialHeader("Sanctuary-Gate 1")).toBeNull(); // no dot
    expect(parseGateCredentialHeader("Sanctuary-Gate .aa")).toBeNull(); // empty gen
    expect(parseGateCredentialHeader("Sanctuary-Gate 1.")).toBeNull(); // empty secret
    expect(parseGateCredentialHeader("Sanctuary-Gate x.aa")).toBeNull(); // non-numeric gen
    expect(parseGateCredentialHeader("Sanctuary-Gate 1.NOThex")).toBeNull(); // non-hex secret
    expect(parseGateCredentialHeader("Sanctuary-Gate 1.aAbB")).toBeNull(); // uppercase hex rejected
  });

  it("rejects malformed Basic credentials before verification", () => {
    const basic = (value: string): string => `Basic ${Buffer.from(value, "utf8").toString("base64")}`;
    expect(parseGateCredentialHeader("Basic not@@base64")).toBeNull();
    expect(parseGateCredentialHeader(basic(`${GATE_PROXY_BASIC_USERNAME}7.deadbeef`))).toBeNull(); // no colon
    expect(parseGateCredentialHeader(basic(`wrong-user:7.deadbeef`))).toBeNull();
    expect(parseGateCredentialHeader(basic(`${GATE_PROXY_BASIC_USERNAME}:7deadbeef`))).toBeNull(); // no dot
    expect(parseGateCredentialHeader(basic(`${GATE_PROXY_BASIC_USERNAME}:7.DEADBEEF`))).toBeNull();
  });

  it("rejects lenient-but-decodable Basic base64 variants of an otherwise valid credential", () => {
    const canonical = Buffer.from(`${GATE_PROXY_BASIC_USERNAME}:7.deadbeef`, "utf8").toString("base64");
    const variants = [
      canonical.slice(0, 4) + " " + canonical.slice(4), // whitespace is ignored by lenient decoders
      canonical.slice(0, 4) + "@@" + canonical.slice(4), // non-base64 alphabet ignored by Node's decoder
      canonical.replace(/==$/, "="), // non-canonical padding still decodes leniently
    ];
    for (const variant of variants) {
      expect(Buffer.from(variant, "base64").toString("utf8")).toBe(`${GATE_PROXY_BASIC_USERNAME}:7.deadbeef`);
      expect(parseGateCredentialHeader(`Basic ${variant}`)).toBeNull();
    }
  });
});

describe("egress-gate/gate-credential verify (constant-time, current-only)", () => {
  const accept: GateCredentialAcceptRecord = {
    version: GATE_CREDENTIAL_VERSION,
    generation_id: 7,
    secret_sha256: sha256Hex("deadbeef"),
  };

  it("accepts a current-generation matching secret", () => {
    expect(verifyGateCredential(accept, { generation_id: 7, secret: "deadbeef" })).toEqual({ ok: true });
  });

  it("denies with no_accept_state when the gate has no accept-state", () => {
    expect(verifyGateCredential(null, { generation_id: 7, secret: "deadbeef" })).toEqual({
      ok: false,
      reason: "no_accept_state",
    });
  });

  it("denies with no_credential when nothing is presented", () => {
    expect(verifyGateCredential(accept, null)).toEqual({ ok: false, reason: "no_credential" });
  });

  it("denies a stale generation BEFORE comparing the secret (no old-token replay)", () => {
    // The secret here is correct for gen 7 but presented under gen 6.
    expect(verifyGateCredential(accept, { generation_id: 6, secret: "deadbeef" })).toEqual({
      ok: false,
      reason: "stale_generation",
    });
  });

  it("denies a wrong secret at the current generation with bad_secret", () => {
    expect(verifyGateCredential(accept, { generation_id: 7, secret: "00000000" })).toEqual({
      ok: false,
      reason: "bad_secret",
    });
  });
});

describe("egress-gate/gate-credential authority (mint/rotate/revoke)", () => {
  it("mints accept BEFORE token, returns the accept record, and binds the hash", async () => {
    const { ops, files, order } = recordingOps("cafef00d");
    const authority = new GateCredentialAuthority(ops);
    const accept = await authority.mint({ agentUid: 502, generationId: 7 });
    expect(accept).toEqual({
      version: GATE_CREDENTIAL_VERSION,
      generation_id: 7,
      secret_sha256: sha256Hex("cafef00d"),
    });
    // accept written first, then token (gate accept-state ready before the token is readable).
    expect(order).toEqual(["accept:502", "token:502"]);
    // the token file carries the raw secret; the accept file carries only the hash.
    expect(JSON.parse(files.get("502.token")!).secret).toBe("cafef00d");
    expect(JSON.parse(files.get("502.accept")!).secret_sha256).toBe(sha256Hex("cafef00d"));
    expect(JSON.parse(files.get("502.accept")!)).not.toHaveProperty("secret");
  });

  it("rotation to a new generation makes the prior token stale (stale_generation on the new accept)", async () => {
    // Mint gen 7, then rotate to gen 8 with a fresh secret. A lingering process
    // presenting the gen-7 token is rejected as stale against the gen-8 accept.
    const g7 = recordingOps("1111");
    const authority7 = new GateCredentialAuthority(g7.ops);
    await authority7.mint({ agentUid: 502, generationId: 7 });
    const oldToken = JSON.parse(g7.files.get("502.token")!) as { generation_id: number; secret: string };

    const g8 = recordingOps("2222");
    const authority8 = new GateCredentialAuthority(g8.ops);
    const newAccept = await authority8.mint({ agentUid: 502, generationId: 8 });

    expect(verifyGateCredential(newAccept, oldToken)).toEqual({ ok: false, reason: "stale_generation" });
    // and the new token is accepted at the new generation
    const newToken = JSON.parse(g8.files.get("502.token")!) as { generation_id: number; secret: string };
    expect(verifyGateCredential(newAccept, newToken)).toEqual({ ok: true });
  });

  it("refuses to mint for a root/zero uid or an invalid generation", async () => {
    const { ops } = recordingOps();
    const authority = new GateCredentialAuthority(ops);
    await expect(authority.mint({ agentUid: 0, generationId: 1 })).rejects.toThrow(/non-positive\/root/);
    await expect(authority.mint({ agentUid: 502, generationId: -1 })).rejects.toThrow(/invalid generation/);
  });

  it("refuses to write a weak (non-hex/empty) secret from a broken mintSecret", async () => {
    const { ops } = recordingOps();
    const authority = new GateCredentialAuthority({ ...ops, mintSecret: () => "" });
    await expect(authority.mint({ agentUid: 502, generationId: 1 })).rejects.toThrow(/weak credential/);
  });

  it("revoke removes both credential files", async () => {
    const { ops, files, order } = recordingOps();
    const authority = new GateCredentialAuthority(ops);
    await authority.mint({ agentUid: 502, generationId: 1 });
    await authority.revoke(502);
    expect(files.has("502.accept")).toBe(false);
    expect(files.has("502.token")).toBe(false);
    expect(order).toContain("remove:502");
  });
});

describe("egress-gate/gate-credential default mint + FS round-trip", () => {
  it("mintGateSecret yields fresh 64-hex-char secrets", () => {
    const a = mintGateSecret();
    const b = mintGateSecret();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(b);
  });

  it("FS authority writes 0600 files a same-uid accept-source can read + verify", async () => {
    const uid = process.getuid?.() ?? 0;
    const dir = await mkdtemp(join(tmpdir(), "s53-cred-"));
    try {
      const authority = createFsGateCredentialAuthority({ gateUid: uid, dir });
      const accept = await authority.mint({ agentUid: uid, generationId: 3 });
      const source = createFsGateAcceptSource(dir);
      const read = await source.current(uid);
      expect(read).toEqual(accept);
      // token is readable and matches the accept hash
      const token = JSON.parse(await readFile(join(dir, `${uid}.token`), "utf8")) as {
        generation_id: number;
        secret: string;
      };
      expect(token.generation_id).toBe(3);
      expect(verifyGateCredential(read, token)).toEqual({ ok: true });
      // mode is 0600
      const mode = (await stat(join(dir, `${uid}.accept`))).mode & 0o777;
      expect(mode).toBe(0o600);
      // absent uid -> null (fail-closed)
      expect(await source.current(uid + 99999)).toBeNull();
      await authority.revoke(uid);
      expect(await source.current(uid)).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("FS accept-source throws on a malformed accept file (gate turns it into a deny)", async () => {
    const uid = process.getuid?.() ?? 0;
    const dir = await mkdtemp(join(tmpdir(), "s53-cred-bad-"));
    try {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(join(dir, `${uid}.accept`), "{not json", "utf8");
      const source = createFsGateAcceptSource(dir);
      await expect(source.current(uid)).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fix-round BLOCKER-2: the FS authority's COMPUTED ownership/mode sequence is pinned via a recorder (0711 traversal dir; per-file chown-to-reader + 0600 strictly before the rename)", async () => {
    const calls: string[] = [];
    const fsOps = {
      open: async (path: string, flags: string, mode: number) => {
        calls.push(`open ${path} ${flags} 0o${mode.toString(8)}`);
        return {
          writeFile: async () => void calls.push(`write ${path}`),
          chown: async (uid: number, gid: number) => void calls.push(`fchown ${path} ${uid}:${gid}`),
          chmod: async (mode2: number) => void calls.push(`fchmod ${path} 0o${mode2.toString(8)}`),
          close: async () => void calls.push(`close ${path}`),
        };
      },
      mkdir: async (path: string, options: { recursive: boolean; mode: number }) => {
        calls.push(`mkdir ${path} 0o${options.mode.toString(8)}`);
      },
      chmod: async (path: string, mode: number) => {
        calls.push(`chmod ${path} 0o${mode.toString(8)}`);
      },
      rename: async (from: string, to: string) => void calls.push(`rename ${to}`),
      rm: async (path: string) => void calls.push(`rm ${path}`),
    };
    const authority = createFsGateCredentialAuthority({
      gateUid: 511,
      dir: "/var/db/sanctuary/gate-cred",
      mintSecret: () => "ab".repeat(32),
      fsOps,
    });
    await authority.mint({ agentUid: 502, generationId: 9 });

    // Per-write shape: mkdir(0711) -> EXPLICIT chmod(dir, 0711) -> open tmp
    // wx 0600 -> write -> fchown(reader) -> fchmod(0600) -> close -> rename.
    const acceptIdx = calls.findIndex((c) => c.startsWith("fchown") && c.includes(".accept"));
    const tokenIdx = calls.findIndex((c) => c.startsWith("fchown") && c.includes(".token"));
    expect(calls[acceptIdx]).toMatch(/^fchown \/var\/db\/sanctuary\/gate-cred\/502\.accept\.tmp-\S+ 511:-1$/);
    expect(calls[tokenIdx]).toMatch(/^fchown \/var\/db\/sanctuary\/gate-cred\/502\.token\.tmp-\S+ 502:-1$/);
    // Accept (gate-readable) is written strictly BEFORE the agent token.
    expect(acceptIdx).toBeLessThan(tokenIdx);
    // The dir traversal mode is asserted explicitly (0711), not left to mkdir/umask.
    expect(calls).toContain("mkdir /var/db/sanctuary/gate-cred 0o711");
    expect(calls).toContain("chmod /var/db/sanctuary/gate-cred 0o711");
    // Ownership binds before the file appears at its final path.
    const acceptRename = calls.findIndex((c) => c === "rename /var/db/sanctuary/gate-cred/502.accept");
    const tokenRename = calls.findIndex((c) => c === "rename /var/db/sanctuary/gate-cred/502.token");
    expect(acceptRename).toBeGreaterThan(acceptIdx);
    expect(tokenRename).toBeGreaterThan(tokenIdx);
    // Tmp files are opened exclusive-create 0600.
    expect(calls.filter((c) => c.startsWith("open")).every((c) => c.includes(" wx 0o600"))).toBe(true);
  });
});
