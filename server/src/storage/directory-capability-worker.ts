/**
 * Darwin directory-capability worker.
 *
 * macOS cannot traverse `/dev/fd/<dirfd>/child`, and Node has no openat(2).
 * This short-lived child is therefore spawned with the protected directory as
 * its cwd. The kernel pins cwd to that inode for the process lifetime; every
 * storage operation is relative to `.` and reuses the ordinary reviewed
 * FilesystemStorage implementation. The parent owns the custody lock and kills
 * this worker when the bounded ceremony ends.
 */

import { lstat, mkdir, open, unlink } from "node:fs/promises";
import { Writable } from "node:stream";
import { isAbsolute, join, normalize, sep } from "node:path";

import { FilesystemStorage } from "./filesystem.js";
import {
  cleanupFreshInitRecoveryResidue,
  isFreshFortressOrExactLockScaffold,
  restoreFreshFortressLockScaffold,
} from "./fresh-fortress.js";
import { tightenStoragePermissions } from "./permissions.js";
import { writeRecoveryKeyFile } from "../wrap/recovery-key-disclosure.js";
import { runProvisionPinAlreadyLocked } from "../cli/castle-wall.js";
import { readFileCustody, writeFileCustody } from "./custody-fs.js";

interface Request {
  id: number;
  op: string;
  args: unknown[];
}

const DARWIN_BOUND_NAMESPACE_TOKEN = "\0sanctuary-bound-namespace\0";

function namespaceArg(value: unknown): string {
  const namespace = String(value);
  return namespace === DARWIN_BOUND_NAMESPACE_TOKEN ? "." : namespace;
}

function bytes(value: unknown): Uint8Array {
  if (typeof value !== "string") throw new Error("capability payload is not base64");
  return new Uint8Array(Buffer.from(value, "base64"));
}

function singleFileName(value: unknown): string {
  const name = String(value);
  if (
    name.length === 0 ||
    isAbsolute(name) ||
    normalize(name) !== name ||
    name.includes(sep) ||
    name === "." ||
    name === ".."
  ) {
    throw new Error("directory-capability file name must be one relative component");
  }
  return name;
}

async function syncCwd(): Promise<void> {
  const handle = await open(".", "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function mkdirRelative(relativePath: string, mode: number): Promise<void> {
  if (
    isAbsolute(relativePath) ||
    normalize(relativePath) !== relativePath ||
    relativePath.split(sep).some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error("directory-capability mkdir path must be normalized and relative");
  }
  let cursor = ".";
  for (const part of relativePath.split(sep)) {
    cursor = join(cursor, part);
    try {
      const current = await lstat(cursor);
      if (current.isSymbolicLink() || !current.isDirectory()) {
        throw new Error(`directory-capability mkdir refused non-directory ${cursor}`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(cursor, { mode });
      const created = await lstat(cursor);
      if (created.isSymbolicLink() || !created.isDirectory()) {
        throw new Error(`directory-capability mkdir lost path identity at ${cursor}`, {
          cause: error,
        });
      }
    }
  }
}

async function perform(
  storage: FilesystemStorage,
  owner: { uid: number; gid: number } | undefined,
  request: Request,
): Promise<unknown> {
  const a = request.args;
  switch (request.op) {
    case "write":
      await storage.write(namespaceArg(a[0]), String(a[1]), bytes(a[2]));
      return null;
    case "writeDurable":
      await storage.writeDurable(namespaceArg(a[0]), String(a[1]), bytes(a[2]));
      return null;
    case "writeIfAbsent":
      return storage.writeIfAbsent(namespaceArg(a[0]), String(a[1]), bytes(a[2]));
    case "replaceIfEquals":
      return storage.replaceIfEquals(
        namespaceArg(a[0]),
        String(a[1]),
        bytes(a[2]),
        bytes(a[3]),
      );
    case "read": {
      const value = await storage.read(namespaceArg(a[0]), String(a[1]));
      return value === null ? null : Buffer.from(value).toString("base64");
    }
    case "delete":
      return storage.delete(namespaceArg(a[0]), String(a[1]), Boolean(a[2]));
    case "list":
      return storage.list(namespaceArg(a[0]), a[1] === undefined ? undefined : String(a[1]));
    case "exists":
      return storage.exists(namespaceArg(a[0]), String(a[1]));
    case "listNamespaces":
      return storage.listNamespaces();
    case "totalSize":
      return storage.totalSize();
    case "tighten":
      await tightenStoragePermissions(".");
      return null;
    case "mkdir":
      await mkdirRelative(String(a[0]), Number(a[1]));
      return null;
    case "isFreshExceptLockScaffold":
      return isFreshFortressOrExactLockScaffold(".", String(a[0]));
    case "cleanupFreshInitRecoveryResidue":
      return cleanupFreshInitRecoveryResidue(
        ".",
        String(a[0]),
        owner?.uid ?? process.getuid!(),
      );
    case "writeRecoveryKey": {
      const result = await writeRecoveryKeyFile({
        storagePath: ".",
        recoveryKey: String(a[0]),
        ...(a[1] === undefined ? {} : { fortressId: String(a[1]) }),
        ...(owner ? { owner, ownerBase: "." } : {}),
      });
      return { written: result.written };
    }
    case "provisionPin": {
      const input = a[0];
      if (typeof input !== "object" || input === null || Array.isArray(input)) {
        throw new Error("provisionPin requires a credential object");
      }
      const credential = input as Record<string, unknown>;
      const masterKeyPayload = credential.masterKey;
      const globalPinnedPublicKeyPath = credential.globalPinnedPublicKeyPath;
      if (!(masterKeyPayload instanceof Uint8Array)) {
        throw new Error("provisionPin masterKey must be a byte array");
      }
      if (
        globalPinnedPublicKeyPath !== undefined &&
        typeof globalPinnedPublicKeyPath !== "string"
      ) {
        throw new Error("provisionPin global pin path must be a string");
      }
      const masterKey = Buffer.from(masterKeyPayload);
      if (masterKey.length !== 32) {
        masterKey.fill(0);
        throw new Error("provisionPin masterKey must decode to 32 bytes");
      }
      try {
        let stdout = "";
        let stderr = "";
        const warnings: string[] = [];
        const capture = (sink: (text: string) => void) => new Writable({
          write(chunk, _encoding, callback) {
            sink(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
            callback();
          },
        });
        const code = await runProvisionPinAlreadyLocked([], {
          out: capture((text) => { stdout += text; }),
          err: capture((text) => { stderr += text; }),
          warn: (message) => { warnings.push(message); },
          env: {
            ...process.env,
            SANCTUARY_STORAGE_PATH: ".",
            ...(owner
              ? { SUDO_UID: String(owner.uid), SUDO_GID: String(owner.gid) }
              : {}),
          },
          __resolvedProvisionMasterKey: masterKey,
          ...(globalPinnedPublicKeyPath === undefined
            ? {}
            : { globalPinnedPublicKeyPath }),
        });
        return { code, stdout, stderr, warnings };
      } finally {
        masterKey.fill(0);
        masterKeyPayload.fill(0);
      }
    }
    case "readFile": {
      const name = singleFileName(a[0]);
      try {
        const value = await readFileCustody(name, {
          mode: { rejectGroupOrOther: true },
          verifyPathIdentity: true,
        });
        return Buffer.from(value).toString("base64");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    }
    case "writeFile":
      await writeFileCustody(singleFileName(a[0]), bytes(a[1]), {
        mode: a[2] === undefined ? 0o600 : Number(a[2]),
        createParent: false,
        ...(owner ? { owner, ownerBase: ".", stableDirectoryCapability: true } : {}),
      });
      return null;
    case "deleteFile": {
      const name = singleFileName(a[0]);
      try {
        const current = await lstat(name);
        if (current.isSymbolicLink() || !current.isFile()) {
          throw new Error("directory-capability delete refused non-regular file");
        }
        await unlink(name);
        await syncCwd();
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
        throw error;
      }
    }
    case "restoreFreshLockScaffold":
      await restoreFreshFortressLockScaffold(".", singleFileName(a[0]));
      return null;
    case "ensureRoot":
      await mkdir(".", { recursive: true, mode: Number(a[0]) });
      return null;
    default:
      throw new Error(`unknown directory-capability operation: ${request.op}`);
  }
}

async function main(): Promise<void> {
  const expectedDev = process.argv[2];
  const expectedIno = process.argv[3];
  const ownerUid = process.argv[4];
  const ownerGid = process.argv[5];
  if (!expectedDev || !expectedIno) throw new Error("missing directory identity");
  const actual = await import("node:fs/promises").then(({ stat }) =>
    stat(".", { bigint: true }),
  );
  if (String(actual.dev) !== expectedDev || String(actual.ino) !== expectedIno) {
    throw new Error("directory identity changed before capability worker started");
  }

  const owner = ownerUid && ownerGid
    ? { uid: Number(ownerUid), gid: Number(ownerGid) }
    : undefined;
  if (owner && (!Number.isSafeInteger(owner.uid) || !Number.isSafeInteger(owner.gid))) {
    throw new Error("invalid directory-capability owner identity");
  }
  const storage = new FilesystemStorage(".", owner ? { owner } : {});
  process.on("message", (raw: Request) => {
    void (async () => {
      try {
        const value = await perform(storage, owner, raw);
        process.send?.({ id: raw.id, ok: true, value });
      } catch (error) {
        process.send?.({
          id: raw.id,
          ok: false,
          error: {
            message: error instanceof Error ? error.message : String(error),
            code:
              error instanceof Error && "code" in error
                ? String((error as NodeJS.ErrnoException).code)
                : undefined,
          },
        });
      }
    })();
  });
  process.send?.({ ready: true });
}

void main().catch((error) => {
  process.stderr.write(
    `directory-capability worker failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
