/** Workstation-only, owner-supplied descriptor adapter for the existing Linux producer. */
import { constants, closeSync, fstatSync, openSync, readSync, writeFileSync, fsyncSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize } from "../mesh/canonical-json.js";
import { castleWallSigningKeyId, verifyManifestSignature } from "../castle-wall/allowlist/parse.js";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import { composeEffectiveRules } from "../castle-wall/allowlist/habeas-port.js";
import { validateRule, type AllowlistRule } from "../castle-wall/allowlist/schema.js";
import type { SignedManifest } from "../castle-wall/allowlist/manifest.js";
import { publishLinuxCompatiblePolicy } from "../castle-wall/runtime/linux-policy-compatibility.js";
import type { BuildSignedManifestInput } from "../castle-wall/runtime/manifest-publisher.js";

const KIB = 1024;
const BUNDLE_MAX = 160 * KIB; // Must match manifest/store.rs::MAX_PUBLISH_BUNDLE_BYTES.
const KEY_BYTES = 32; // Ed25519 seed representation, exactly 32 raw bytes, never PEM/JSON or argv.
/** Must match PolicyBundle in castle-wall-daemon/src/linux_install/policy.rs. */
export interface PolicyBundle { public_key_hex: string; manifest_b64url: string; rules: Array<{ file: string; body_b64url: string }> }

/** Sign only an explicit valid uid origin; malformed producer input must never become omitted origin. */
export async function buildInstallBundle(input: BuildSignedManifestInput, publicKey: Uint8Array): Promise<PolicyBundle> {
  const origin = validateAgentOrigin(input.agentOrigin);
  if (!origin || origin.mode !== "uid" || origin.agent_uid === undefined || origin.gate_uid !== undefined) throw new Error("explicit uid agent_origin required");
  if (origin.agent_uid <= origin.system_uid_allow_ceiling) throw new Error("agent uid must exceed system uid ceiling");
  if (!/^[a-f0-9]{8,64}$/.test(input.fortressId)) throw new Error("invalid fortress id");
  if (!Number.isSafeInteger(input.generation) || (input.generation ?? 0) <= 0) throw new Error("positive safe integer generation required");
  for (const rule of input.rules) if (validateRule(rule).length !== 0) throw new Error("invalid policy rule");
  const bundle: PolicyBundle = { public_key_hex: Buffer.from(publicKey).toString("hex"), manifest_b64url: "", rules: [] };
  const rules = composeEffectiveRules({ operatorRules: input.rules, resolvers: [], createdAt: input.issuedAt });
  await publishLinuxCompatiblePolicy({ ...input, rules, agentOrigin: origin }, {
    async writeRule(file, bytes) { bundle.rules.push({ file, body_b64url: Buffer.from(bytes).toString("base64url") }); },
    async atomicRenameManifest(bytes) {
      const signed = JSON.parse(Buffer.from(bytes).toString("utf8")) as SignedManifest;
      // Verify emitted semantics as well as authenticity; a producer omission cannot authorize an unconfined install.
      if (canonicalize(signed.manifest.agent_origin) !== canonicalize(origin) || !verifyManifestSignature(signed, publicKey).ok) throw new Error("emitted manifest identity refused");
      bundle.manifest_b64url = Buffer.from(bytes).toString("base64url");
    },
    async listRules() { return []; },
    async removeRule() { throw new Error("unexpected producer removal"); },
  });
  if (Buffer.byteLength(JSON.stringify(bundle)) > BUNDLE_MAX) throw new Error("policy bundle exceeds quota");
  return bundle;
}
function exactFd(fd: number, max: number, key: boolean): Buffer {
  const before = fstatSync(fd);
  // Regular files give a finite read; pipes/devices cannot detach a timed-out read holding key material.
  if (!before.isFile() || before.nlink !== 1 || before.size > max || (key && (before.size !== KEY_BYTES || (before.mode & 0o077) !== 0))) throw new Error("descriptor custody or size refused");
  const bytes = Buffer.alloc(max + 1);
  try {
    let count = 0;
    while (count < bytes.length) { const n = readSync(fd, bytes, count, bytes.length - count, count); if (n === 0) break; count += n; }
    const after = fstatSync(fd);
    if (count !== before.size || count > max || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("descriptor changed during read");
    return Buffer.from(bytes.subarray(0, count));
  } finally { bytes.fill(0); }
}
function options(argv: string[]): Map<string, string> {
  const names = ["--fortress-id", "--agent-uid", "--system-uid-ceiling", "--generation", "--rules", "--key-fd", "--output"];
  if (argv.length !== names.length * 2) throw new Error("exact signing options required");
  const out = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) { if (!names.includes(argv[i]) || out.has(argv[i])) throw new Error("unknown or duplicate option"); out.set(argv[i], argv[i + 1]); }
  return out;
}
/** The packaged entry sets both core limits before Node exists; direct invocation verifies both. */
export async function main(argv: string[]): Promise<void> {
  const args = options(argv);
  // A child inherits this process's core limit; never trust an environment marker claiming dumps are disabled.
  const core = execFileSync("/bin/sh", ["-c", "ulimit -S -c; ulimit -H -c"], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" }, timeout: 1000, maxBuffer: KIB }).trim();
  if (core !== "0\n0") throw new Error("use the packaged sanctuary-linux-policy-sign entry to disable core dumps");
  const number = (name: string): number => { const raw = args.get(name)!; if (!/^(0|[1-9][0-9]*)$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("invalid integer option"); return Number(raw); };
  const fd = number("--key-fd");
  if (fd < 3) throw new Error("key descriptor must be separate from standard streams");
  const ruleFd = openSync(args.get("--rules")!, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let rules: AllowlistRule[];
  try { const parsed: unknown = JSON.parse(exactFd(ruleFd, BUNDLE_MAX, false).toString("utf8")); if (!Array.isArray(parsed)) throw new Error("rules must be an array"); rules = parsed as AllowlistRule[]; } finally { closeSync(ruleFd); }
  let seed: Buffer | undefined;
  try {
    seed = exactFd(fd, KEY_BYTES, true);
    const publicKey = ed25519.getPublicKey(seed);
    const key = seed;
    const bundle = await buildInstallBundle({ fortressId: args.get("--fortress-id")!, generation: number("--generation"), issuedAt: new Date().toISOString(), rules, agentOrigin: { mode: "uid", agent_uid: number("--agent-uid"), system_uid_allow_ceiling: number("--system-uid-ceiling") }, signer: { signingKeyId: castleWallSigningKeyId(publicKey), sign: bytes => ed25519.sign(bytes, key) } }, publicKey);
    // Exclusive output creation refuses to overwrite an existing signed artifact or follow a symlink.
    const out = openSync(args.get("--output")!, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(out, JSON.stringify(bundle)); fsyncSync(out); } finally { closeSync(out); }
  } finally { seed?.fill(0); closeSync(fd); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // SAFETY: stderr is the operator CLI contract; emit a fixed refusal without key, policy, or error contents.
  main(process.argv.slice(2)).catch(() => { console.error("sanctuary-linux-policy-sign: signing refused"); process.exitCode = 1; });
}
