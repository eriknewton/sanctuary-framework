import { execSync as nodeExecSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { bytesToString, concatBytes, fromBase64url, stringToBytes } from "../core/encoding.js";
import { encrypt } from "../core/encryption.js";
import { randomBytes } from "../core/random.js";
import { resolveStoragePath } from "../paths.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { FilesystemStorage } from "../storage/filesystem.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";

export interface CastleWallCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  execSyncFn?: (command: string) => string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function fingerprintFromPublicKey(publicKey: Uint8Array): string {
  return createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 16);
}

function parseCastleWallState(raw: string): "[activated enabled]" | "[activated waiting for user]" | "not loaded" {
  if (raw.includes("[activated enabled]")) return "[activated enabled]";
  if (raw.includes("[activated waiting for user]")) {
    return "[activated waiting for user]";
  }
  return "not loaded";
}

async function resolveMasterKey(
  storagePath: string,
  env: NodeJS.ProcessEnv
): Promise<Uint8Array> {
  if (env.SANCTUARY_RECOVERY_KEY) {
    const key = fromBase64url(env.SANCTUARY_RECOVERY_KEY);
    if (key.length !== 32) {
      throw new Error("SANCTUARY_RECOVERY_KEY must decode to 32 bytes.");
    }
    return key;
  }

  const storage = new FilesystemStorage(join(storagePath, "state"));
  const passphrase =
    env.SANCTUARY_PASSPHRASE ??
    (await getOrCreatePassphrase({ storagePath })).value;

  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) existingParams = JSON.parse(bytesToString(raw));
  } catch {
    // first run
  }

  const { key: masterKey, params } = await deriveMasterKey(
    passphrase,
    existingParams
  );
  if (!existingParams) {
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
  }
  return masterKey;
}

export async function runProvisionPin(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const storagePath = resolveStoragePath(env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);
  const privPath = join(storagePath, CASTLE_PINNED_PRIVKEY);

  try {
    await mkdir(storagePath, { recursive: true, mode: 0o700 });

    try {
      const existingPub = await readFile(pubPath);
      if (existingPub.length !== 32) {
        throw new Error(
          `Pinned public key at ${pubPath} must be 32 bytes (found ${existingPub.length}).`
        );
      }
      const fingerprint = fingerprintFromPublicKey(existingPub);
      write(out, `${fingerprint}\n`);
      write(
        out,
        "Pinned key already provisioned; leaving existing key in place.\n"
      );
      return 0;
    } catch (readError) {
      if (
        !(readError instanceof Error) ||
        !("code" in readError) ||
        (readError as NodeJS.ErrnoException).code !== "ENOENT"
      ) {
        throw readError;
      }
    }

    const masterKey = await resolveMasterKey(storagePath, env);
    const privateSeed = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateSeed);
    const privateKey = concatBytes(privateSeed, publicKey);
    const encryptedPrivateKey = encrypt(privateKey, masterKey);
    const fingerprint = fingerprintFromPublicKey(publicKey);

    await writeFile(pubPath, publicKey, { mode: 0o600 });
    await chmod(pubPath, 0o600);
    await writeFile(privPath, JSON.stringify(encryptedPrivateKey), {
      mode: 0o600,
    });
    await chmod(privPath, 0o600);

    privateSeed.fill(0);
    privateKey.fill(0);
    masterKey.fill(0);

    write(out, `${fingerprint}\n`);
    return 0;
  } catch (error) {
    write(
      err,
      `Error: ${
        error instanceof Error ? error.message : String(error)
      }\n`
    );
    return 1;
  }
}

export async function runStatus(
  ctx: CastleWallCommandContext = {}
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const execSyncFn =
    ctx.execSyncFn ??
    ((command: string) =>
      nodeExecSync(`sh -lc '${command.replace(/'/g, "'\\''")}'`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim());
  const storagePath = resolveStoragePath(env);
  const pubPath = join(storagePath, CASTLE_PINNED_PUBKEY);

  try {
    const publicKey = await readFile(pubPath);
    if (publicKey.length !== 32) {
      throw new Error(
        `Pinned public key at ${pubPath} must be 32 bytes (found ${publicKey.length}).`
      );
    }
    write(out, `Pinned key fingerprint: ${fingerprintFromPublicKey(publicKey)}\n`);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      write(
        out,
        "No pinned key provisioned. Run: sanctuary castle-wall provision-pin\n"
      );
    } else {
      throw error;
    }
  }

  if (platform !== "darwin") {
    write(out, "Castle Wall sysext: not applicable (non-macOS)\n");
    return 0;
  }

  let sysextState: "[activated enabled]" | "[activated waiting for user]" | "not loaded" = "not loaded";
  try {
    const raw = execSyncFn(
      "systemextensionsctl list 2>/dev/null | grep castle-wall"
    );
    sysextState = parseCastleWallState(raw);
  } catch {
    sysextState = "not loaded";
  }

  write(out, `Castle Wall sysext: ${sysextState}\n`);
  return 0;
}
