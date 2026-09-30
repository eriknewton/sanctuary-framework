/**
 * Sanctuary MCP Server — L3: the surrogate value store
 *
 * WHAT THIS IS. The keychain home of every secret bound as a surrogate. It is
 * the SAME keychain file the broker uses, so the operator still unlocks one
 * store with one fortress passphrase, under a DIFFERENT service label.
 *
 * WHY A SEPARATE LABEL RATHER THAN A POLICY RULE (design v2.1 section 3.3,
 * round-2 finding A2-B2). An earlier design kept bindings inside
 * `broker-policy.json` and relied on an old broker failing to parse them. The
 * pre-existing `secrets grant` writer can rewrite such an entry to `read`, and
 * an old broker would then have served the value. Storage is the boundary
 * instead: every broker read, list and delete filters by the broker's own
 * service, and `openBroker` always constructs its backend with the broker
 * identity, so a broker handed ANY grant for a bound name looks under
 * `sanctuary-broker*`, finds nothing, and raises `SecretNotFoundError`. That
 * holds for an old broker, a new one, and one whose policy file was tampered
 * with, because none of them name this service.
 *
 * WHAT THIS MUST NEVER DO. It must never be handed to `Broker`, `TokenIssuer`
 * or anything on the token path. Its only callers are the operator verbs
 * `sanctuary secrets surrogate add|remove|unlock`, which run as the operator and
 * never inside an agent's process.
 */

import { KeychainBackend, brokerKeychainIdentityFor } from "./keychain-backend.js";
import type { Backend } from "./backend-interface.js";

/**
 * Service prefix for every value stored under the surrogate label.
 *
 * PIN: must DIFFER from `SERVICE` ("sanctuary-broker") in `keychain-backend.ts`,
 * and the broker must never be constructed with it. This literal is declared
 * here and nowhere else; `test/structure/surrogate-keychain-label.test.ts`
 * asserts both halves (sole declaration, and `openBroker` passing no service
 * override), because a second copy of the string is how the two labels would
 * silently converge back into one.
 *
 * Shape matches the broker's exactly: the bare prefix for the legacy
 * single-tenant fortress, `<prefix>-<digest>` for a per-fortress one, so a host
 * with two fortresses keeps two surrogate labels for the same reason it keeps
 * two broker labels.
 */
const SURROGATE_SERVICE_PREFIX = "sanctuary-surrogate";

/** The broker service prefix this one must differ from. Local copy used only to
 * derive the surrogate service from the broker's derivation; see the pin above.
 * `keychain-backend.ts` does not export its `SERVICE` constant, and that file is
 * not ours to widen, so the derivation below rewrites the prefix of the identity
 * the broker's own function returned rather than re-deriving the digest. That
 * keeps ONE digest derivation (`brokerKeychainIdentityFor`) in the tree: if the
 * broker's tenant scoping ever changes, the surrogate label follows it without a
 * second edit. */
const BROKER_SERVICE_PREFIX = "sanctuary-broker";

export interface SurrogateKeychainIdentity {
  keychainPath: string;
  service: string;
  accountNamespace: string;
}

/**
 * Derive the surrogate identity from the broker's, sharing the keychain FILE and
 * the account namespace, changing ONLY the service prefix.
 *
 * Sharing the file is deliberate: one passphrase, one unlock, one thing for the
 * operator to back up. Confidentiality between the two labels does not come from
 * separate files, it comes from the service filter every keychain query carries.
 */
export function surrogateKeychainIdentityFor(
  storagePath: string,
  home?: string,
): SurrogateKeychainIdentity {
  // `brokerKeychainIdentityFor` already returns the legacy single-tenant
  // identity when the path IS the default fortress, so there is one call here
  // and no second branch to keep in step.
  const broker = brokerKeychainIdentityFor(storagePath, home);
  if (!broker.service.startsWith(BROKER_SERVICE_PREFIX)) {
    // Fails closed rather than guessing a label. Reaching here means
    // `brokerKeychainIdentityFor` changed shape, and a wrong guess would either
    // collide with the broker's label or strand every stored value under a name
    // nothing else looks up.
    throw new Error("surrogate identity derivation is out of step with the broker identity");
  }
  return {
    keychainPath: broker.keychainPath,
    service: `${SURROGATE_SERVICE_PREFIX}${broker.service.slice(BROKER_SERVICE_PREFIX.length)}`,
    accountNamespace: broker.accountNamespace,
  };
}

export interface SurrogateValueStoreOptions {
  /** Fortress storage path; the surrogate identity is derived from it. */
  storagePath: string;
  /** Home directory override for tests. */
  home?: string;
  /** Injected backend for tests, so no `security` subprocess runs. */
  backend?: Backend;
}

/**
 * The surrogate label's value store.
 *
 * A thin, deliberately NARROW facade over the keychain: bind, read, drop, list.
 * There is no rotate and no token path, because the only readers are the
 * operator verbs and every read is followed immediately by handing the value to
 * the root helper over the unlock socket.
 */
export class SurrogateValueStore {
  private readonly backend: Backend;
  readonly identity: SurrogateKeychainIdentity;

  constructor(opts: SurrogateValueStoreOptions) {
    this.identity = surrogateKeychainIdentityFor(opts.storagePath, opts.home);
    this.backend =
      opts.backend ??
      new KeychainBackend({
        storagePath: opts.storagePath,
        home: opts.home,
        // The ONLY service override in the tree. `openBroker` passes none, which
        // is what keeps the broker on its own label no matter what happens here.
        service: this.identity.service,
      });
  }

  async ensureInitialized(passphrase: string): Promise<void> {
    await this.backend.ensureInitialized(passphrase);
  }

  async unlock(passphrase: string): Promise<void> {
    await this.backend.unlock(passphrase);
  }

  /** Store a value under the surrogate label. Throws if the name already exists there. */
  async bindValue(name: string, value: string): Promise<void> {
    await this.backend.addSecret(name, value);
  }

  /** Read a bound value. The caller hands it straight to the helper and drops it. */
  async readValue(name: string): Promise<string> {
    return this.backend.readSecret(name);
  }

  /** Remove a bound value. `SecretNotFoundError` is reported, never swallowed:
   * a remove that silently succeeds on an absent name would let an operator
   * believe a value was destroyed when the name was merely misspelled. */
  async removeValue(name: string): Promise<void> {
    await this.backend.deleteSecret(name);
  }

  /** Names under the surrogate label only. Never returns values. */
  async listBoundNames(): Promise<string[]> {
    return this.backend.listSecretNames();
  }

  /** Whether a name already exists under the surrogate label.
   * Answered from the NAME list, never by reading the value: an existence check
   * must not be a way to materialize a credential in this process's memory. */
  async hasValue(name: string): Promise<boolean> {
    return (await this.backend.listSecretNames()).includes(name);
  }
}
