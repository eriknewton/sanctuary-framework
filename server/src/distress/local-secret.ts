/**
 * HABEAS PORT — local-listener shared secret.
 *
 * The local distress listener (binds 127.0.0.1:8741) and the in-process
 * distress emitter live in DIFFERENT long-lived processes on an operator
 * machine: the listener runs inside the standalone dashboard service
 * (launchd/systemd), the emitter runs inside the on-demand MCP server. They
 * cannot share an in-memory secret, so sender authentication is anchored to a
 * file in the fortress dir that only the operator uid can read.
 *
 * Why a file secret is the right boundary (codex anti-spoof core):
 *
 *   ANY local process can open a TCP connection to 127.0.0.1:8741 — including
 *   the wrapped agent's own process tree. So the listener cannot trust the
 *   peer just because it is loopback. Every delivery is HMAC-SHA256 signed
 *   over the canonical envelope bytes with this secret; the listener rejects
 *   any frame whose signature does not verify. A spoofer therefore needs the
 *   secret, and the secret is a 0600 file owned by the operator uid.
 *
 *   The wrapped agent runs under the same uid as the operator in the common
 *   single-user deployment, BUT the agent has no filesystem path to the
 *   fortress dir through its MCP surface (same boundary that protects
 *   `distress.json`'s webhook secret and the master custody envelope). It
 *   speaks MCP, not raw FS. So it cannot read this secret to forge a frame,
 *   exactly as it cannot read the webhook HMAC secret to forge a webhook POST.
 *
 *   This is a tamper/spoof boundary, not a confidentiality boundary against a
 *   hostile operator: an operator who can read their own fortress dir can of
 *   course forge a frame to their own listener. That is fine — the listener
 *   surfaces distress TO the operator. The threat it closes is a non-operator
 *   local process (or the agent) injecting a spoofed signal.
 *
 * Lifecycle: minted lazily, 0600, in the operator-owned policy dir alongside
 * `distress.json`. Both processes call `loadOrCreateLocalListenerSecret`; the
 * first to run mints it, the rest read it. A present-but-wrong-mode file is
 * rejected (fail closed) rather than trusted, mirroring the distress.json
 * secret-mode check.
 */

import { randomBytes } from "node:crypto";
import { mkdir, readFile, stat, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";

/** File name of the local-listener shared secret in the egress policy dir. */
export const DISTRESS_LOCAL_SECRET_FILENAME = "distress-local-secret";

/** Secret length in bytes (256-bit HMAC key). */
export const DISTRESS_LOCAL_SECRET_BYTES = 32;

export class DistressLocalSecretError extends Error {
  constructor(message: string) {
    super(`distress local secret: ${message}`);
    this.name = "DistressLocalSecretError";
  }
}

function secretPath(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", DISTRESS_LOCAL_SECRET_FILENAME);
}

/**
 * Load the local-listener shared secret, minting it on first use.
 *
 * The secret is stored hex-encoded in a 0600 file. If the file exists but is
 * group/world-readable, this throws (fail closed): a secret another local
 * principal can read is no longer a sender-authentication boundary, and
 * silently re-chmod'ing it could mask a real exposure. The operator must
 * `chmod 600` it (or delete it to re-mint).
 *
 * Returns the raw secret bytes. Callers must not log them.
 */
export async function loadOrCreateLocalListenerSecret(
  fortressPath: string,
): Promise<Uint8Array> {
  const filePath = secretPath(fortressPath);

  let hex: string | undefined;
  try {
    const raw = await readFile(filePath, "utf8");
    hex = raw.trim();
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code !== "ENOENT") throw err;
  }

  if (hex !== undefined) {
    // Present: enforce 0600 before trusting it.
    const fileStat = await stat(filePath);
    if ((fileStat.mode & 0o077) !== 0) {
      throw new DistressLocalSecretError(
        `${filePath} is readable by non-owner (mode ${(fileStat.mode & 0o777).toString(8)}); ` +
          `chmod 600 it (or delete it to re-mint) — a group/world-readable secret ` +
          `defeats local sender authentication`,
      );
    }
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length !== DISTRESS_LOCAL_SECRET_BYTES * 2) {
      throw new DistressLocalSecretError(
        `${filePath} is malformed; delete it to re-mint a fresh secret`,
      );
    }
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }

  // Mint. Create the policy/egress dir if it does not exist yet (operator may
  // not have configured a webhook), with restrictive perms.
  const secret = randomBytes(DISTRESS_LOCAL_SECRET_BYTES);
  await mkdir(join(fortressPath, "policy", "egress"), {
    recursive: true,
    mode: 0o700,
  });
  await writeFile(filePath, secret.toString("hex"), { mode: 0o600 });
  // writeFile honors `mode` only on create; chmod defensively in case a
  // pre-existing umask/inherited mode left it looser on some platforms.
  await chmod(filePath, 0o600);
  return Uint8Array.from(secret);
}
