/** Environment variables sshd sets in a remote login; any one non-empty marks the command as running over SSH. */
export const SSH_SESSION_VARIABLES = Object.freeze(["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"] as const);

/**
 * An accident guard, not a boundary: over SSH a keychain prompt opens on the Mac's screen with no one to
 * answer it, so the Hermes commands that could reach the keychain check this first. Anyone can unset these.
 */
export function isSshSession(env: NodeJS.ProcessEnv): boolean {
  return SSH_SESSION_VARIABLES.some(name => env[name] !== undefined && env[name] !== "");
}
