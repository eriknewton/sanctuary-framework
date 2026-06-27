/**
 * Sanctuary wrap - shared command-executor result shape.
 *
 * The wrap keyring code (passphrase.ts, keychain-custody.ts) runs `security`
 * (macOS) / `secret-tool` (Linux) through an injectable executor so tests can
 * mock the OS keyring. Both modules need the executor's result type, and
 * keychain-custody.ts reuses passphrase.ts's failure classifiers, so the type
 * lives here in a leaf module rather than in either of them. That keeps the
 * dependency one-directional (passphrase.ts -> keychain-custody.ts for the
 * classifiers; both -> exec-result.ts for the shape) with no import cycle.
 */

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}
