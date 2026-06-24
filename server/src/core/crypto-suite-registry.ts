/**
 * Signature-suite registry for new versioned signing surfaces.
 *
 * Slice 1 intentionally enables only crypto-agility infrastructure. It does not
 * add a hybrid or PQC algorithm; the registry is seeded with ed25519-v1 only.
 */

import { fromBase64url, stringToBytes, toBase64url } from "./encoding.js";
import { sign as identitySign, verify as identityVerify } from "./identity.js";
import type { EncryptedPayload } from "./encryption.js";

export const SIGNATURE_BUNDLE_VERSION = "sanctuary.signature-bundle.v1";
export const SIGNED_SURFACE_DOMAIN = "sanctuary.signed-surface.v1";
export const ED25519_SIGNATURE_SUITE_ID = "ed25519-v1";

export type SignatureSuiteId = typeof ED25519_SIGNATURE_SUITE_ID;

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalJsonValue[]
  | { readonly [key: string]: CanonicalJsonValue | undefined };

/** One signature component inside a versioned signature bundle. */
export interface SignatureBundleComponent {
  readonly alg: string;
  readonly key_ref: string;
  readonly sig: string;
}

/**
 * Versioned, suite-tagged signature container for new signing surfaces.
 *
 * A verifier accepts a bundle only when `signature_suite` exactly matches the
 * selected suite and the component list exactly matches that suite's component
 * policy. Future hybrid suites therefore fail closed if any component is
 * stripped, added, reordered, or relabeled.
 */
export interface SignatureBundle {
  readonly bundle_version: typeof SIGNATURE_BUNDLE_VERSION;
  readonly signature_suite: string;
  readonly components: readonly SignatureBundleComponent[];
}

/** Descriptor required to sign or verify a new versioned surface. */
export interface SignedSurfaceDescriptor {
  readonly surface_id: string;
  readonly surface_version: string;
  readonly signature_suite: string;
  readonly payload: CanonicalJsonValue;
}

/** Ed25519 signing capability used by the ed25519-v1 suite. */
export interface Ed25519SuiteSigner {
  readonly key_ref: string;
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** Signing capabilities keyed by algorithm family for suite dispatch. */
export interface SuiteSigner {
  readonly ed25519?: Ed25519SuiteSigner;
}

/** Ed25519 public key used by the ed25519-v1 suite. */
export interface Ed25519SuitePublicKey {
  readonly key_ref: string;
  readonly public_key: Uint8Array;
}

/** Public keys keyed by algorithm family for suite dispatch. */
export interface SuitePublicKeys {
  readonly ed25519?: Ed25519SuitePublicKey;
}

/** Public registry metadata for one configured signature suite. */
export interface SignatureSuiteMetadata {
  readonly id: string;
  readonly components: readonly string[];
  readonly maxSignatureBytes: number;
  readonly maxPublicKeyBytes: number;
}

interface RegisteredSignatureSuite extends SignatureSuiteMetadata {
  sign(bytes: Uint8Array, signer: SuiteSigner): Promise<SignatureBundle>;
  verify(
    bytes: Uint8Array,
    bundle: SignatureBundle,
    keys: SuitePublicKeys
  ): Promise<boolean>;
}

export class CryptoSuiteRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoSuiteRegistryError";
  }
}

/**
 * Registry for named signature suites.
 *
 * New signing surfaces use `signSurface` and `verifySurface`, which construct
 * the signed preimage from a descriptor that must include `surface_version` and
 * `signature_suite`. Legacy frozen serializers remain on their existing direct
 * Ed25519 paths until they get explicit versioned replacements.
 */
export class CryptoSuiteRegistry {
  private readonly suites = new Map<string, RegisteredSignatureSuite>();

  constructor() {
    this.addSuite(createEd25519Suite());
  }

  /** Return configured suite metadata without exposing raw suite signers. */
  listSuites(): readonly SignatureSuiteMetadata[] {
    return Array.from(this.suites.values(), (suite) => ({
      id: suite.id,
      components: suite.components,
      maxSignatureBytes: suite.maxSignatureBytes,
      maxPublicKeyBytes: suite.maxPublicKeyBytes,
    }));
  }

  /** True when the registry has an exact suite-id match. */
  hasSuite(id: string): boolean {
    return this.suites.has(id);
  }

  /**
   * Sign a new versioned surface with the descriptor-bound canonical preimage.
   */
  async signSurface(
    descriptor: SignedSurfaceDescriptor,
    signer: SuiteSigner
  ): Promise<SignatureBundle> {
    const suite = this.getSuiteOrThrow(descriptor.signature_suite);
    const bytes = signedSurfaceBytes(descriptor);
    return suite.sign(bytes, signer);
  }

  /**
   * Verify a new versioned surface with the descriptor-bound canonical preimage.
   */
  async verifySurface(
    descriptor: SignedSurfaceDescriptor,
    bundle: SignatureBundle,
    keys: SuitePublicKeys
  ): Promise<boolean> {
    try {
      if (bundle.signature_suite !== descriptor.signature_suite) return false;
      const suite = this.suites.get(descriptor.signature_suite);
      if (!suite) return false;
      const bytes = signedSurfaceBytes(descriptor);
      return suite.verify(bytes, bundle, keys);
    } catch {
      return false;
    }
  }

  private addSuite(suite: RegisteredSignatureSuite): void {
    if (this.suites.has(suite.id)) {
      throw new CryptoSuiteRegistryError(
        `duplicate signature_suite '${suite.id}'`
      );
    }
    this.suites.set(suite.id, suite);
  }

  private getSuiteOrThrow(id: string): RegisteredSignatureSuite {
    const suite = this.suites.get(id);
    if (!suite) {
      throw new CryptoSuiteRegistryError(`unknown signature_suite '${id}'`);
    }
    return suite;
  }
}

/** Shared default registry seeded with ed25519-v1 only. */
export const cryptoSuiteRegistry = new CryptoSuiteRegistry();

/**
 * Build the canonical bytes signed by a new versioned surface.
 *
 * The signed object always includes the surface version and signature suite at
 * the top level, which prevents unsigned suite metadata substitution.
 */
export function signedSurfaceBytes(
  descriptor: SignedSurfaceDescriptor
): Uint8Array {
  return stringToBytes(canonicalSignedSurface(descriptor));
}

/** Return the canonical JSON string for the descriptor-bound signed preimage. */
export function canonicalSignedSurface(
  descriptor: SignedSurfaceDescriptor
): string {
  assertNonEmpty("surface_id", descriptor.surface_id);
  assertNonEmpty("surface_version", descriptor.surface_version);
  assertNonEmpty("signature_suite", descriptor.signature_suite);
  return canonicalize({
    domain: SIGNED_SURFACE_DOMAIN,
    surface_id: descriptor.surface_id,
    surface_version: descriptor.surface_version,
    signature_suite: descriptor.signature_suite,
    payload: descriptor.payload,
  });
}

/** Create a suite signer backed by the existing encrypted identity signer. */
export function createEd25519IdentitySuiteSigner(params: {
  readonly key_ref: string;
  readonly encryptedPrivateKey: EncryptedPayload;
  readonly encryptionKey: Uint8Array;
}): SuiteSigner {
  assertNonEmpty("key_ref", params.key_ref);
  return {
    ed25519: {
      key_ref: params.key_ref,
      sign: (bytes) =>
        identitySign(bytes, params.encryptedPrivateKey, params.encryptionKey),
    },
  };
}

/** Create ed25519-v1 public keys for suite verification. */
export function createEd25519SuitePublicKeys(params: {
  readonly key_ref: string;
  readonly publicKey: Uint8Array;
}): SuitePublicKeys {
  assertNonEmpty("key_ref", params.key_ref);
  if (params.publicKey.length !== 32) {
    throw new CryptoSuiteRegistryError(
      "ed25519-v1 public key must be 32 bytes"
    );
  }
  return {
    ed25519: {
      key_ref: params.key_ref,
      public_key: params.publicKey,
    },
  };
}

function createEd25519Suite(): RegisteredSignatureSuite {
  return {
    id: ED25519_SIGNATURE_SUITE_ID,
    components: [ED25519_SIGNATURE_SUITE_ID],
    maxSignatureBytes: 64,
    maxPublicKeyBytes: 32,
    async sign(bytes, signer) {
      const ed25519Signer = signer.ed25519;
      if (!ed25519Signer) {
        throw new CryptoSuiteRegistryError("ed25519-v1 signer is required");
      }
      assertNonEmpty("key_ref", ed25519Signer.key_ref);
      const sig = await ed25519Signer.sign(bytes);
      if (sig.length !== 64) {
        throw new CryptoSuiteRegistryError(
          "ed25519-v1 signer returned a non-64-byte signature"
        );
      }
      return {
        bundle_version: SIGNATURE_BUNDLE_VERSION,
        signature_suite: ED25519_SIGNATURE_SUITE_ID,
        components: [
          {
            alg: ED25519_SIGNATURE_SUITE_ID,
            key_ref: ed25519Signer.key_ref,
            sig: toBase64url(sig),
          },
        ],
      };
    },
    async verify(bytes, bundle, keys) {
      if (!bundleMatchesSuitePolicy(bundle, this)) return false;
      const ed25519Key = keys.ed25519;
      if (!ed25519Key) return false;
      if (ed25519Key.public_key.length !== 32) return false;
      const component = bundle.components[0]!;
      if (component.key_ref !== ed25519Key.key_ref) return false;
      const sig = decodeCanonicalBase64url(component.sig);
      if (!sig || sig.length !== 64) return false;
      return identityVerify(bytes, sig, ed25519Key.public_key);
    },
  };
}

function bundleMatchesSuitePolicy(
  bundle: SignatureBundle,
  suite: RegisteredSignatureSuite
): boolean {
  if (bundle.bundle_version !== SIGNATURE_BUNDLE_VERSION) return false;
  if (bundle.signature_suite !== suite.id) return false;
  if (bundle.components.length !== suite.components.length) return false;

  const seen = new Set<string>();
  for (let i = 0; i < suite.components.length; i++) {
    const expectedAlg = suite.components[i]!;
    const component = bundle.components[i];
    if (!component) return false;
    if (component.alg !== expectedAlg) return false;
    if (seen.has(component.alg)) return false;
    seen.add(component.alg);
    if (!component.key_ref || !component.sig) return false;
  }
  return true;
}

function decodeCanonicalBase64url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = fromBase64url(value);
  if (toBase64url(decoded) !== value) return null;
  return decoded;
}

function assertNonEmpty(field: string, value: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new CryptoSuiteRegistryError(`${field} must be a non-empty string`);
  }
}

function canonicalize(value: CanonicalJsonValue | undefined): string {
  if (value === undefined) {
    throw new CryptoSuiteRegistryError(
      "canonicalize(): top-level undefined is not serializable"
    );
  }
  return encodeCanonical(value);
}

function encodeCanonical(value: CanonicalJsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CryptoSuiteRegistryError(
        `canonicalize(): non-finite number (${String(value)}) is not serializable`
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (isCanonicalJsonArray(value)) {
    return "[" + value.map((entry) => {
      if (entry === undefined) {
        throw new CryptoSuiteRegistryError(
          "canonicalize(): undefined array values are not serializable"
        );
      }
      return encodeCanonical(entry);
    }).join(",") + "]";
  }
  return encodeCanonicalObject(value);
}

function isCanonicalJsonArray(
  value: CanonicalJsonValue
): value is readonly CanonicalJsonValue[] {
  return Array.isArray(value);
}

function encodeCanonicalObject(value: {
  readonly [key: string]: CanonicalJsonValue | undefined;
}): string {
  return (
    "{" +
    Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${encodeCanonical(value[key]!)}`)
      .join(",") +
    "}"
  );
}
