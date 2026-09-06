/**
 * Complete external credential registry for one fortress.
 *
 * Destructive reset is the only caller today, but keeping the composition in
 * one module prevents passphrase, custody-key, and recovery-escrow identities
 * from drifting into separate hand-written deletion lists.
 */

import { homedir } from "node:os";

import { fortressKeychainReadServices } from "./passphrase.js";
import { fortressCustodyCredentialServices } from "./keychain-custody.js";

export function allFortressKeychainCredentialServices(
  storagePath: string,
  home: string = homedir(),
): string[] {
  const ordered = [
    ...fortressKeychainReadServices(storagePath, home),
    ...fortressCustodyCredentialServices(storagePath, home),
  ];
  return ordered.filter((name, index) => ordered.indexOf(name) === index);
}
