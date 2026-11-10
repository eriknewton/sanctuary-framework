import { stat } from "node:fs/promises";
import { homedir } from "node:os";

/** Optional discovery overrides keep callers on the same signer path precedence. */
export interface SignerClientPathContext {
  signerClientPath?: string;
  signerClientCandidates?: string[];
  fileExistsFn?: (path: string) => Promise<boolean>;
  getuid?: () => number;
}

// Resolver precedence must match resolveSignerClientPath in server/src/cli/castle-wall.ts.
// Resolver precedence must match resolveSignerClientPath in server/src/cli/castle-wall-full-agent.ts.
// Resolver precedence must match resolveSignerClientPath in server/src/cli/transparency.ts.
/** Bundled path of the signer-client shim inside the installed host app. */
const SIGNER_CLIENT_RELATIVE_BINARY =
  "Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client";

/**
 * Known on-disk locations of the bundled signer-client shim, in probe order.
 * The shim ships inside the installed host app, so a normally-installed box
 * can discover it when SANCTUARY_CASTLE_SIGNER_CLIENT is unset.
 */
function defaultSignerClientCandidates(env: NodeJS.ProcessEnv): string[] {
  const home = env.HOME ?? homedir();
  return [
    `/Applications/${SIGNER_CLIENT_RELATIVE_BINARY}`,
    `${home}/Applications/${SIGNER_CLIENT_RELATIVE_BINARY}`,
  ];
}

/**
 * Resolve the signing client for installation, the daemon, re-pin and checkpoints.
 * Precedence: explicit `ctx.signerClientPath` → `SANCTUARY_CASTLE_SIGNER_CLIENT`
 * env → (darwin only) auto-discovered bundled shim → `undefined`. Auto-discovery
 * is test-injectable via `ctx.signerClientCandidates` / `ctx.fileExistsFn`,
 * mirroring the host-app `hostAppCandidates` seam, so tests never depend on a
 * real `/Applications` install.
 *
 * The DEFAULT discovery predicate is `isOwnerTrustedExecutable` (the same
 * owner-trust check `resolveHostAppBinary` uses to guard the arming surface):
 * a probed candidate must be a regular file owned by root, the current uid, or
 * (for a root process launched via sudo) SUDO_UID. The sudo case is required
 * for `sudo sanctuary protect --hermes`: privileged account/launchd steps run
 * as root, while the installed and user-consented Castle Wall app can be owned
 * by the operator who invoked sudo.
 * This brings the signer-client surface to PARITY with the host-app surface.
 * NOTE: stronger same-UID hardening (designated-requirement / codesign
 * validation) is a broader follow-up that, if pursued, must apply UNIFORMLY to
 * BOTH the host-app and signer-client surfaces - deliberately out of scope here
 * to stay consistent with the established owner-trust model.
 */
export async function resolveSignerClientPath(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  ctx: SignerClientPathContext,
): Promise<string | undefined> {
  if (ctx.signerClientPath) return ctx.signerClientPath;
  if (env.SANCTUARY_CASTLE_SIGNER_CLIENT) {
    return env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  }
  if (platform !== "darwin") return undefined;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const exists =
    ctx.fileExistsFn ?? ((path: string) => isOwnerTrustedExecutable(path, getuid, env));
  const candidates = ctx.signerClientCandidates ?? defaultSignerClientCandidates(env);
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Three-state observation of one candidate binary. "absent" is reserved for
 * the ONE case that actually proves nothing is installed there (ENOENT);
 * every other outcome, including an untrusted owner and an unreadable parent
 * directory, is "undetermined". A caller that turns an observation into a
 * security decision must never read a failed observation as absence
 * (AGENTS.md rule 1: absent, indeterminate and unproven are distinct).
 */
const ROOT_UID = 0; // POSIX root identity.
type OwnerTrustedExecutableObservation = "trusted" | "absent" | "undetermined";

async function observeOwnerTrustedExecutable(
  path: string,
  getuid: (() => number) | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<OwnerTrustedExecutableObservation> {
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(path);
  } catch (error) {
    // Only "there is nothing at this path" is absence. An EACCES on an
    // ancestor means the app may well be installed and this account simply
    // cannot see it.
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? "absent"
      : "undetermined";
  }
  // Something exists at the app's path. Whether or not we trust its owner, we
  // cannot claim the machine has no Castle Wall app installed.
  if (!info.isFile()) return "undetermined";
  const uid = getuid?.();
  const trusted = new Set<number>([ROOT_UID]);
  if (uid !== undefined) {
    trusted.add(uid);
    if (uid === ROOT_UID && env.SUDO_UID !== undefined && /^\d+$/.test(env.SUDO_UID)) {
      const sudoUid = Number(env.SUDO_UID);
      if (Number.isSafeInteger(sudoUid) && sudoUid > ROOT_UID) {
        trusted.add(sudoUid);
      }
    }
  }
  // Discovery can select only a file owned by a principal this process trusts.
  return trusted.has(info.uid) ? "trusted" : "undetermined";
}

/**
 * True iff `path` is an existing regular file owned by root or the current
 * user (mirrors SanctuaryServerBridge.isOwnerTrustedExecutable on the Swift
 * side): prevents invoking a binary an attacker dropped at a probed path.
 * Invocation sites need a two-state answer ("may I exec this?"), so an
 * undetermined observation collapses to false here; presence questions must
 * use observeOwnerTrustedExecutable instead and keep the third state.
 */
export async function isOwnerTrustedExecutable(
  path: string,
  getuid: (() => number) | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  return (await observeOwnerTrustedExecutable(path, getuid, env)) === "trusted";
}
