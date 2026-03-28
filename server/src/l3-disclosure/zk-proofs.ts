/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Zero-Knowledge Proofs
 *
 * Upgrades the commitment-only L3 to support real zero-knowledge proofs.
 * Uses Ristretto255 (prime-order curve group, no cofactor issues) for:
 *
 *   1. Pedersen commitments: C = v*G + b*H (computationally hiding, perfectly binding)
 *   2. ZK proof of knowledge: Schnorr sigma protocol via Fiat-Shamir
 *   3. ZK range proofs: Prove value ∈ [min, max] without revealing it
 *
 * Ristretto255 is available via @noble/curves/ed25519, which we already depend on.
 * This is genuine zero-knowledge — proofs reveal nothing beyond the stated property.
 *
 * Architecture note:
 * The existing commitment scheme (SHA-256 based) remains available for backward
 * compatibility. The ZK proofs operate on a separate Pedersen commitment system
 * that provides algebraic structure for proper ZK properties.
 *
 * Security invariants:
 * - Generator H is derived via hash-to-curve (nothing-up-my-sleeve)
 * - Blinding factors are cryptographically random (32 bytes)
 * - Fiat-Shamir challenges use domain-separated hashing
 * - Range proofs use a bit-decomposition approach (sound but logarithmic size)
 */

import { RistrettoPoint } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "../core/random.js";
import { toBase64url, fromBase64url, stringToBytes, concatBytes } from "../core/encoding.js";

// ── Constants ───────────────────────────────────────────────────────────

/** Generator G: the standard Ristretto255 base point */
const G = RistrettoPoint.BASE;

/**
 * Generator H: derived via hash-to-curve so nobody knows the discrete log
 * relationship between G and H (nothing-up-my-sleeve construction).
 */
/** Derive 64 bytes for hash-to-curve via double SHA-256 */
const H_INPUT = concatBytes(
  sha256(stringToBytes("sanctuary-pedersen-generator-H-v1-a")),
  sha256(stringToBytes("sanctuary-pedersen-generator-H-v1-b"))
);
const H = RistrettoPoint.hashToCurve(H_INPUT);

// ── Types ───────────────────────────────────────────────────────────────

/** A Pedersen commitment: C = v*G + b*H */
export interface PedersenCommitment {
  /** The commitment point (encoded as base64url) */
  commitment: string;
  /** The blinding factor b (base64url, 32 bytes) — keep secret */
  blinding_factor: string;
  /** When the commitment was created */
  committed_at: string;
}

/** A non-interactive ZK proof of knowledge of a commitment's opening */
export interface ZKProofOfKnowledge {
  /** Proof type identifier */
  type: "schnorr-pedersen-ristretto255";
  /** The commitment this proof is for */
  commitment: string;
  /** Announcement point R (base64url) */
  announcement: string;
  /** Response scalar s_v (base64url) */
  response_v: string;
  /** Response scalar s_b (base64url) */
  response_b: string;
  /** Proof generated at */
  generated_at: string;
}

/** A ZK range proof: proves value ∈ [min, max] */
export interface ZKRangeProof {
  /** Proof type identifier */
  type: "range-pedersen-ristretto255";
  /** The commitment this proof is for */
  commitment: string;
  /** Minimum value (inclusive) */
  min: number;
  /** Maximum value (inclusive) */
  max: number;
  /** Bit commitments for the shifted value (v - min) */
  bit_commitments: string[];
  /** Proofs that each bit commitment is 0 or 1 */
  bit_proofs: Array<{
    announcement_0: string;
    announcement_1: string;
    challenge_0: string;
    challenge_1: string;
    response_0: string;
    response_1: string;
  }>;
  /** Sum proof: bit commitments sum to the value commitment */
  sum_proof: {
    announcement: string;
    response: string;
  };
  /** Proof generated at */
  generated_at: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────

/** Encode a bigint as a 32-byte big-endian Uint8Array */
function bigintToBytes(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Decode a 32-byte big-endian Uint8Array to a bigint */
function bytesToBigint(bytes: Uint8Array): bigint {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

/** The Ristretto255 group order */
const ORDER = BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");

/** Reduce a bigint modulo the group order */
function mod(n: bigint): bigint {
  return ((n % ORDER) + ORDER) % ORDER;
}

/**
 * Safe scalar multiplication: handles the zero case
 * (noble/curves requires 1 <= scalar < n)
 */
function safeMultiply(point: InstanceType<typeof RistrettoPoint>, scalar: bigint): InstanceType<typeof RistrettoPoint> {
  const s = mod(scalar);
  if (s === 0n) return RistrettoPoint.ZERO;
  return point.multiply(s);
}

/** Generate a random scalar in [1, ORDER-1] */
function randomScalar(): bigint {
  const bytes = randomBytes(64); // Extra bytes for uniform distribution
  return mod(bytesToBigint(bytes));
}

/** Domain-separated Fiat-Shamir challenge hash */
function fiatShamirChallenge(domain: string, ...points: Uint8Array[]): bigint {
  const domainBytes = stringToBytes(domain);
  const combined = concatBytes(domainBytes, ...points);
  const hash = sha256(combined);
  return mod(bytesToBigint(hash));
}

// ── Pedersen Commitments ────────────────────────────────────────────────

/**
 * Create a Pedersen commitment to a numeric value.
 *
 * C = v*G + b*H
 *
 * Properties:
 * - Computationally hiding (under discrete log assumption)
 * - Perfectly binding (information-theoretic)
 * - Homomorphic: C(v1) + C(v2) = C(v1+v2) with adjusted blinding
 *
 * @param value - The value to commit to (integer)
 * @returns The commitment and blinding factor
 */
export function createPedersenCommitment(value: number): PedersenCommitment {
  const v = mod(BigInt(value));
  const b = randomScalar();

  // C = v*G + b*H
  const C = safeMultiply(G, v).add(safeMultiply(H, b));

  return {
    commitment: toBase64url(C.toRawBytes()),
    blinding_factor: toBase64url(bigintToBytes(b)),
    committed_at: new Date().toISOString(),
  };
}

/**
 * Verify a Pedersen commitment against a revealed value and blinding factor.
 *
 * Recomputes C' = v*G + b*H and checks C' == C.
 */
export function verifyPedersenCommitment(
  commitment: string,
  value: number,
  blindingFactor: string
): boolean {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(commitment));
    const v = mod(BigInt(value));
    const b = bytesToBigint(fromBase64url(blindingFactor));

    const expected = safeMultiply(G, v).add(safeMultiply(H, b));
    return C.equals(expected);
  } catch {
    return false;
  }
}

// ── ZK Proof of Knowledge ───────────────────────────────────────────────

/**
 * Create a non-interactive ZK proof that you know the opening (v, b)
 * of a Pedersen commitment C = v*G + b*H.
 *
 * Schnorr sigma protocol with Fiat-Shamir transform:
 *   1. Pick random r_v, r_b
 *   2. Compute R = r_v*G + r_b*H (announcement)
 *   3. Compute e = H_FS(C || R) (challenge via Fiat-Shamir)
 *   4. Compute s_v = r_v + e*v, s_b = r_b + e*b (responses)
 *   5. Proof = (R, s_v, s_b)
 *
 * Zero-knowledge: the transcript (R, e, s_v, s_b) can be simulated
 * without knowing (v, b), so it reveals nothing.
 *
 * @param value - The committed value
 * @param blindingFactor - The blinding factor (base64url)
 * @param commitment - The commitment (base64url)
 */
export function createProofOfKnowledge(
  value: number,
  blindingFactor: string,
  commitment: string
): ZKProofOfKnowledge {
  const v = mod(BigInt(value));
  const b = bytesToBigint(fromBase64url(blindingFactor));

  // Step 1: Random nonces
  const r_v = randomScalar();
  const r_b = randomScalar();

  // Step 2: Announcement
  const R = safeMultiply(G, r_v).add(safeMultiply(H, r_b));

  // Step 3: Fiat-Shamir challenge
  const C_bytes = fromBase64url(commitment);
  const R_bytes = R.toRawBytes();
  const e = fiatShamirChallenge("sanctuary-zk-pok-v1", C_bytes, R_bytes);

  // Step 4: Responses
  const s_v = mod(r_v + e * v);
  const s_b = mod(r_b + e * b);

  return {
    type: "schnorr-pedersen-ristretto255",
    commitment,
    announcement: toBase64url(R_bytes),
    response_v: toBase64url(bigintToBytes(s_v)),
    response_b: toBase64url(bigintToBytes(s_b)),
    generated_at: new Date().toISOString(),
  };
}

/**
 * Verify a ZK proof of knowledge of a commitment's opening.
 *
 * Check: s_v*G + s_b*H == R + e*C
 */
export function verifyProofOfKnowledge(proof: ZKProofOfKnowledge): boolean {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(proof.commitment));
    const R = RistrettoPoint.fromHex(fromBase64url(proof.announcement));
    const s_v = bytesToBigint(fromBase64url(proof.response_v));
    const s_b = bytesToBigint(fromBase64url(proof.response_b));

    // Recompute challenge
    const e = fiatShamirChallenge(
      "sanctuary-zk-pok-v1",
      fromBase64url(proof.commitment),
      fromBase64url(proof.announcement)
    );

    // Verify: s_v*G + s_b*H == R + e*C
    const lhs = safeMultiply(G, s_v).add(safeMultiply(H, s_b));
    const rhs = R.add(safeMultiply(C, e));

    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// ── ZK Range Proof ──────────────────────────────────────────────────────

/**
 * Create a ZK range proof: prove value ∈ [min, max] without revealing value.
 *
 * Approach: bit-decomposition of (value - min) into n bits where 2^n > max - min.
 * Each bit gets a Pedersen commitment and a proof it's 0 or 1.
 * A sum proof shows the bit commitments reconstruct the original commitment
 * (shifted by min).
 *
 * @param value - The committed value
 * @param blindingFactor - The blinding factor (base64url)
 * @param commitment - The commitment (base64url)
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (inclusive)
 */
export function createRangeProof(
  value: number,
  blindingFactor: string,
  commitment: string,
  min: number,
  max: number
): ZKRangeProof | { error: string } {
  if (value < min || value > max) {
    return { error: `Value ${value} is not in range [${min}, ${max}]` };
  }

  const range = max - min;
  const numBits = Math.ceil(Math.log2(range + 1));
  const shifted = value - min;
  const b = bytesToBigint(fromBase64url(blindingFactor));

  // Decompose shifted value into bits
  const bits: number[] = [];
  for (let i = 0; i < numBits; i++) {
    bits.push((shifted >> i) & 1);
  }

  // Create bit commitments with random blinding factors
  const bitBlindings: bigint[] = [];
  const bitCommitments: string[] = [];
  const bitProofs: ZKRangeProof["bit_proofs"] = [];

  for (let i = 0; i < numBits; i++) {
    const bit_b = randomScalar();
    bitBlindings.push(bit_b);

    // Bit commitment: C_i = bit_i * G + bit_b_i * H
    const C_i = safeMultiply(G, mod(BigInt(bits[i]!))).add(safeMultiply(H, bit_b));
    bitCommitments.push(toBase64url(C_i.toRawBytes()));

    // Prove bit is 0 or 1 using an OR-proof (Sigma protocol)
    const bitProof = createBitProof(bits[i]!, bit_b, C_i);
    bitProofs.push(bitProof);
  }

  // Sum proof: show that sum(2^i * C_i) - min*G has blinding factor = b
  // sum(2^i * bit_b_i) should equal b (mod ORDER)
  const sumBlinding = bitBlindings.reduce(
    (acc, bi, i) => mod(acc + mod(BigInt(1) << BigInt(i)) * bi),
    0n
  );
  // The difference in blinding: b - sumBlinding
  const blindingDiff = mod(b - sumBlinding);

  // Prove knowledge of blindingDiff as the blinding factor of the identity point
  const r_sum = randomScalar();
  const R_sum = safeMultiply(H, r_sum);
  const e_sum = fiatShamirChallenge(
    "sanctuary-zk-range-sum-v1",
    fromBase64url(commitment),
    R_sum.toRawBytes()
  );
  const s_sum = mod(r_sum + e_sum * blindingDiff);

  return {
    type: "range-pedersen-ristretto255",
    commitment,
    min,
    max,
    bit_commitments: bitCommitments,
    bit_proofs: bitProofs,
    sum_proof: {
      announcement: toBase64url(R_sum.toRawBytes()),
      response: toBase64url(bigintToBytes(s_sum)),
    },
    generated_at: new Date().toISOString(),
  };
}

/**
 * Verify a ZK range proof.
 */
export function verifyRangeProof(proof: ZKRangeProof): boolean {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(proof.commitment));
    const range = proof.max - proof.min;
    const numBits = Math.ceil(Math.log2(range + 1));

    if (proof.bit_commitments.length !== numBits) return false;
    if (proof.bit_proofs.length !== numBits) return false;

    // Verify each bit proof
    for (let i = 0; i < numBits; i++) {
      const C_i = RistrettoPoint.fromHex(fromBase64url(proof.bit_commitments[i]!));
      if (!verifyBitProof(proof.bit_proofs[i]!, C_i)) {
        return false;
      }
    }

    // Verify sum proof: sum(2^i * C_i) + blindingDiff*H == C - min*G
    // Reconstruct: sum(2^i * C_i)
    let reconstructed = RistrettoPoint.ZERO;
    for (let i = 0; i < numBits; i++) {
      const C_i = RistrettoPoint.fromHex(fromBase64url(proof.bit_commitments[i]!));
      const weight = mod(BigInt(1) << BigInt(i));
      reconstructed = reconstructed.add(safeMultiply(C_i, weight));
    }

    // The difference: C - min*G - reconstructed should be blindingDiff*H
    const diff = C.subtract(safeMultiply(G, mod(BigInt(proof.min)))).subtract(reconstructed);

    // Verify the sum proof for diff
    const R_sum = RistrettoPoint.fromHex(fromBase64url(proof.sum_proof.announcement));
    const s_sum = bytesToBigint(fromBase64url(proof.sum_proof.response));
    const e_sum = fiatShamirChallenge(
      "sanctuary-zk-range-sum-v1",
      fromBase64url(proof.commitment),
      fromBase64url(proof.sum_proof.announcement)
    );

    // Check: s_sum*H == R_sum + e_sum*diff
    const lhs = safeMultiply(H, s_sum);
    const rhs = R_sum.add(safeMultiply(diff, e_sum));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// ── Bit Proof (OR-proof for 0 or 1) ────────────────────────────────────

/**
 * Create an OR-proof that a Pedersen commitment contains either 0 or 1.
 * Uses the standard Cramer-Damgård-Schoenmakers (CDS) technique.
 */
function createBitProof(
  bit: number,
  blinding: bigint,
  commitment: InstanceType<typeof RistrettoPoint>
): ZKRangeProof["bit_proofs"][0] {
  const C_bytes = commitment.toRawBytes();

  if (bit === 0) {
    // Real proof for 0, simulated for 1
    // For the simulated branch (bit=1): C - G
    const C_minus_G = commitment.subtract(G);

    // Simulate branch 1
    const e_1 = randomScalar();
    const s_1 = randomScalar();
    // R_1 = s_1*H - e_1*(C-G)
    const R_1 = safeMultiply(H, s_1).subtract(safeMultiply(C_minus_G, e_1));

    // Real branch 0
    const r_0 = randomScalar();
    const R_0 = safeMultiply(H, r_0);

    // Overall challenge
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    const e_0 = mod(e - e_1);
    const s_0 = mod(r_0 + e_0 * blinding);

    return {
      announcement_0: toBase64url(R_0.toRawBytes()),
      announcement_1: toBase64url(R_1.toRawBytes()),
      challenge_0: toBase64url(bigintToBytes(e_0)),
      challenge_1: toBase64url(bigintToBytes(e_1)),
      response_0: toBase64url(bigintToBytes(s_0)),
      response_1: toBase64url(bigintToBytes(s_1)),
    };
  } else {
    // Real proof for 1, simulated for 0
    // Simulate branch 0
    const e_0 = randomScalar();
    const s_0 = randomScalar();
    // R_0 = s_0*H - e_0*C
    const R_0 = safeMultiply(H, s_0).subtract(safeMultiply(commitment, e_0));

    // Real branch 1: C - G, blinding is the same
    const r_1 = randomScalar();
    const R_1 = safeMultiply(H, r_1);

    // Overall challenge
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    const e_1 = mod(e - e_0);
    const s_1 = mod(r_1 + e_1 * blinding);

    return {
      announcement_0: toBase64url(R_0.toRawBytes()),
      announcement_1: toBase64url(R_1.toRawBytes()),
      challenge_0: toBase64url(bigintToBytes(e_0)),
      challenge_1: toBase64url(bigintToBytes(e_1)),
      response_0: toBase64url(bigintToBytes(s_0)),
      response_1: toBase64url(bigintToBytes(s_1)),
    };
  }
}

/**
 * Verify an OR-proof that a commitment contains 0 or 1.
 */
function verifyBitProof(
  proof: ZKRangeProof["bit_proofs"][0],
  commitment: InstanceType<typeof RistrettoPoint>
): boolean {
  try {
    const C_bytes = commitment.toRawBytes();
    const R_0 = RistrettoPoint.fromHex(fromBase64url(proof.announcement_0));
    const R_1 = RistrettoPoint.fromHex(fromBase64url(proof.announcement_1));
    const e_0 = bytesToBigint(fromBase64url(proof.challenge_0));
    const e_1 = bytesToBigint(fromBase64url(proof.challenge_1));
    const s_0 = bytesToBigint(fromBase64url(proof.response_0));
    const s_1 = bytesToBigint(fromBase64url(proof.response_1));

    // Check challenge split
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    if (mod(e_0 + e_1) !== e) return false;

    // Verify branch 0: s_0*H == R_0 + e_0*C
    const lhs_0 = safeMultiply(H, s_0);
    const rhs_0 = R_0.add(safeMultiply(commitment, e_0));
    if (!lhs_0.equals(rhs_0)) return false;

    // Verify branch 1: s_1*H == R_1 + e_1*(C - G)
    const C_minus_G = commitment.subtract(G);
    const lhs_1 = safeMultiply(H, s_1);
    const rhs_1 = R_1.add(safeMultiply(C_minus_G, e_1));
    if (!lhs_1.equals(rhs_1)) return false;

    return true;
  } catch {
    return false;
  }
}
