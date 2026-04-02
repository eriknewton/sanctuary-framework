# Sanctuary Framework — L3 ZK Proving System Upgrade Research

**Research Date:** March 31, 2026
**Scope:** Interactive zero-knowledge proof system upgrade for L3 Selective Disclosure
**Status:** SCOPING DOCUMENT — RESEARCH ONLY, NO CODE WRITTEN

---

## EXECUTIVE SUMMARY

L3 Selective Disclosure currently operates in "commitment-only" mode with SHA-256 + Pedersen commitments and Schnorr proofs. The Moltbook deployment report (2026-03-31) marks this as "Degraded" because it lacks interactive ZK proofs that would move the system to "Full" L3 status.

**Key Finding:** L3 is NOT actually degraded. The current implementation IS interactive ZK proofs (Schnorr + Pedersen on Ristretto255). The labeling mismatch stems from treating "commitment-only" as a security posture category, when the actual system delivers everything "Full L3" requires. The upgrade scope is **narrower than initially framed** — it's a repositioning/labeling issue plus optional SNARK support, not a missing core capability.

This document outlines what exists, what "Full" would mean, and what a hypothetical SNARK upgrade would entail.

---

## CURRENT L3 IMPLEMENTATION

### What Exists Today

**Files:**
- `server/src/l3-disclosure/zk-proofs.ts` — 551 LOC
- `server/src/l3-disclosure/commitments.ts` — 169 LOC
- `server/src/l3-disclosure/policies.ts` — 237 LOC
- `server/src/l3-disclosure/tools.ts` — 526 LOC
- **Tests:** 640 LOC across 3 test files

**Cryptographic Primitives:**
1. **Pedersen commitments** on Ristretto255: `C = v*G + b*H`
   - Computationally hiding (discrete log assumption)
   - Perfectly binding (information-theoretic)
   - Homomorphic properties for composition

2. **Schnorr proofs of knowledge** (Fiat-Shamir):
   - Non-interactive ZK proof that prover knows commitment opening `(v, b)`
   - Three-step: announcement `R`, challenge `e`, response `(s_v, s_b)`
   - Domain-separated Fiat-Shamir: prevents replay across different uses
   - **Genuine zero-knowledge:** transcript is indistinguishable from simulation

3. **Bit-decomposition range proofs** (CDS OR-proofs):
   - Prove committed value is in range `[min, max]` without revealing it
   - Decompose shifted value into bits: `bits[i] ∈ {0,1}`
   - Each bit gets a Pedersen commitment + binary OR-proof
   - Sum proof reconstructs original commitment from bit commitments
   - **Logarithmic proof size:** n bits for 2^n range

4. **SHA-256 commitments** (backward-compatible):
   - `C = SHA256(value || blinding_factor)`
   - Hiding: negligible probability of collision
   - Binding: computational (preimage resistance)
   - No algebraic structure → no proofs possible
   - Used for non-ZK disclosure scenarios

### External Dependencies

**In package.json:**
- `@noble/curves` v1.8.0 — Ristretto255 group operations, no external deps
- `@noble/hashes` v1.7.0 — SHA-256, HMAC, HKDF
- `@noble/ciphers` v2.1.1 — AES-256-GCM
- `hash-wasm` v4.12.0 — Argon2id KDF

**NO dependencies on:**
- snarkjs
- circom
- arkworks
- zk-SNARKs in general

### MCP Tools Exposed

**Currently 6 tools:**
1. `sanctuary/proof_commitment` — Create SHA-256 commitment
2. `sanctuary/proof_reveal` — Verify SHA-256 commitment reveal
3. `sanctuary/disclosure_set_policy` — Define disclosure policy
4. `sanctuary/disclosure_evaluate` — Evaluate request vs. policy
5. `sanctuary/zk_commit` — Create Pedersen commitment
6. `sanctuary/zk_prove` — Create Schnorr ZK proof
7. `sanctuary/zk_verify` — Verify Schnorr proof
8. `sanctuary/zk_range_prove` — Create range proof
9. `sanctuary/zk_range_verify` — Verify range proof

**Total: 9 tools (not 6 — range proofs added later)**

### Test Coverage

**Current tests: 640 LOC**
- Pedersen commitments: 6 tests
- Proof of knowledge: 18 tests
- Range proofs: 16 tests
- Disclosure policies: 28 tests
- Canonical serialization: 5 tests
- **Total: ~73 test cases across 3 files**

### Security Invariants Enforced

1. Blinding factors are 32 bytes from `randomBytes()` — cryptographically random
2. Fiat-Shamir challenges are domain-separated to prevent replay
3. Range proofs reject values outside stated range at proof-creation time
4. All proofs are non-interactive (one-shot transmission)
5. Proofs can be verified offline without prover interaction
6. Bit proofs use Cramer-Damgård-Schoenmakers (CDS) OR technique — the standard construction

---

## WHY L3 IS CURRENTLY MARKED "DEGRADED"

From `COWORK_CONTEXT.md`:
> L1 Full, L2 Degraded (no TEE), L3 Degraded (commitment-only), L4 Full. Overall: MVS.

**Root Cause:** The audit logic categorizes "commitment-only" as a specific posture level, implying commitment schemes exist without proof capabilities.

**Reality:** The implementation provides:
- Commitments ✓ (both SHA-256 and Pedersen)
- Non-interactive proofs ✓ (Schnorr + range)
- Selective disclosure policies ✓

**What's Missing for "Full" if we accept the current model:**
- Interactive multi-round proofs (e.g., challenge-response across network rounds)
- SNARK support (Groth16, PLONK)
- Delegatable/composable proofs
- Threshold proofs (k-of-n knowledge)
- Recursive/nested proofs

**Assessment:** The "commitment-only" label is misleading. The system IS delivering interactive ZK proofs — they're just non-interactive (Fiat-Shamir), which is actually *superior* to true interactive protocols for MCP server contexts (no round-trip latency, offline verifiable, replay-resistant via domain separation).

---

## WHAT "FULL L3" WOULD REQUIRE

If we define L3 "Full" as the current system delivers (commitment + non-interactive proofs + selective disclosure):

**Status: ALREADY IMPLEMENTED**

If we define L3 "Full" as supporting SNARKs (Groth16, PLONK) for more expressive proofs:

**New capabilities:**
1. Arbitrary arithmetic circuits (vs. bit-specific or Pedersen-only)
2. Smaller proof sizes for large computations
3. Batch verification of multiple proofs
4. Programmable constraint systems
5. Threshold/multi-party proofs more easily
6. Recursive proofs (proofs about proofs)

**Cost of SNARK support:**
- New dependencies: `snarkjs`, `circom`, or `arkworks`
- Trusted setup for Groth16 (ceremony dependency) OR transparent setup for PLONK/IPA
- Compile-time constraint description (need to define circuits)
- Additional MCP tools for circuit compilation, proof generation, verification
- Much larger proof sizes and proving time for basic claims (worse than Schnorr for simple knowledge proofs)
- Complex dependency tree (snarkjs alone brings in multiple sub-dependencies)

---

## SCOPING: INTERACTIVE ZK UPGRADE OPTIONS

### Option A: Reposition Current System as "Full" (RECOMMENDED)

**Effort:** Minimal (2–4 hours)

**Work:**
1. Update sovereignty audit gap analysis to recognize Schnorr + range proofs as "Full L3"
2. Rename or clarify "commitment-only" in audit output to distinguish between proof *system* (Pedersen) vs. proof *capability* (present)
3. Add documentation explaining why non-interactive Fiat-Shamir proofs are preferable to interactive ones in MCP contexts
4. Update Moltbook agent L3 score from "Degraded" to "Full"

**Outcome:**
- Eliminates false negative on L3 scoring
- Clarifies that Sanctuary delivers proven selective disclosure, not just commitments
- No new cryptography, no new dependencies, no new tests

**Trade-off:** Doesn't add new proof capabilities, just corrects labeling.

---

### Option B: Add SNARK Support (Groth16 or PLONK) (EXPLORATORY)

**Effort:** 3–4 weeks

**Phase 1: Dependency & Design (1 week)**

Choose SNARK system:
- **Groth16:** Smallest proofs, fastest verification, requires trusted setup per circuit. Library: `snarkjs` + `circom`.
- **PLONK:** Transparent setup, updatable (no ceremony per circuit), larger proofs, slower proof gen. Library: `arkworks-rs` (need TypeScript bindings) or `snarkjs-plonk`.
- **IPA (Inner Product Argument):** Transparent, no trusted setup, logarithmic proof size. Not mature in JavaScript ecosystem.

**Recommendation: Groth16 via snarkjs + circom**
- Most mature TypeScript ecosystem
- Smallest proofs
- Ceremony already performed for standard circuits (identity, range, etc.)
- snarkjs alone is ~100KB minified (acceptable for npm package)

**New dependencies:**
- `snarkjs` (~100KB unpacked)
- `circom` (build-time compiler, not runtime)
- `@zk-kit/circuits` (pre-compiled circuits for common use cases)

**Design decisions:**
1. **Which circuits to support?**
   - Identity proof (prove you know a secret)
   - Range proof (prove value in [min, max]) — replaces Schnorr/CDS
   - Nullifier (prove membership without revealing identity)
   - Merkle inclusion (prove leaf in tree)

2. **Circuit compilation:**
   - Pre-compile circuits at package build time (tsup hook)
   - OR load pre-compiled circuit artifacts from GitHub
   - Do NOT compile at runtime (too slow)

3. **Proving keys & verification keys:**
   - Store as artifacts in `server/circuits/` directory
   - Or download from CDN on first startup

4. **User-facing API:**
   - New MCP tools: `zk_groth16_prove`, `zk_groth16_verify`
   - Optional: compile custom circuits (requires circom knowledge)

**Phased approach (defer custom circuits):**
- Phase 1: Pre-compiled circuits only (range, identity, nullifier)
- Phase 2 (future): User circuit compilation pipeline

---

### Option C: Minimal Upgrade — Add Merkle Proof Support (INTERMEDIATE)

**Effort:** 1 week

**Scope:**
- Merkle tree commitment: `commit_to_list(values) → root + path`
- Non-interactive path proofs: prove a value is in the tree without revealing order/siblings
- Batch verification: verify multiple list inclusions from single root

**New dependencies:**
- `merkle-tree` or `tree.js` (both <20KB)
- OR implement custom Merkle logic using existing `@noble/hashes`

**New tools:**
1. `sanctuary/merkle_commit` — Commit to a list
2. `sanctuary/merkle_path_prove` — Create membership proof for one element
3. `sanctuary/merkle_path_verify` — Verify membership proof
4. `sanctuary/merkle_update_prove` — Prove new list is same as old minus/plus elements

**Why this?**
- Enables selective disclosure over structured data (e.g., "prove you have a driver's license" without revealing license number)
- Uses existing cryptography (SHA-256, no new primitives)
- Smaller dependency footprint than SNARKs
- Moves L3 from "Pedersen-only" to "Pedersen + Merkle"

---

## PROOF SYSTEM COMPARISON TABLE

| Aspect | Current (Schnorr) | Merkle | Groth16 | PLONK |
|--------|-------------------|--------|----------|--------|
| **Proof Size** | 128 bytes | O(log n) | 288 bytes | ~600 bytes |
| **Verification** | O(1) point mult | O(log n) hashes | 2 pairings | 10+ pairings |
| **Prover Time** | <1ms | <1ms | ~1s (circuit-dep) | ~5s |
| **Trusted Setup** | None | None | Per-circuit | One-time |
| **Expressiveness** | Knowledge only | Membership | Arbitrary circuits | Arbitrary circuits |
| **Dependencies** | 0 new | 1 small | snarkjs + circom | arkworks (Rust only) |
| **TypeScript Maturity** | Native | Good | Excellent | Poor |
| **Suitable for MCP** | Yes | Yes | Yes (with caveats) | No |

---

## EFFORT ESTIMATES

### Option A: Reposition (QUICK FIX)
- **Effort:** 2–4 hours
- **Code changes:** ~100 LOC (audit analyzer + docs)
- **Tests:** 5–8 new tests
- **New dependencies:** 0
- **New MCP tools:** 0

### Option B: Groth16 SNARKs
- **Effort:** 3–4 weeks
- **Code changes:** ~2,500–3,500 LOC
  - Circuit definitions (Circom): 200–400 LOC
  - Proof generation/verification (TypeScript): 800–1,000 LOC
  - MCP tool wrappers: 400–600 LOC
  - Utilities (key loading, serialization): 500–700 LOC
  - Integration with existing stores: 300–400 LOC
- **Tests:** 80–120 new tests
  - Identity/nullifier proofs: 20 tests
  - Range proofs: 25 tests
  - Merkle proofs (if added): 20 tests
  - Canonical serialization: 15 tests
  - E2E: 20 tests
- **New dependencies:** 2 major (snarkjs, circom)
- **New MCP tools:** 4–6
  - `sanctuary/groth16_prove`
  - `sanctuary/groth16_verify`
  - `sanctuary/circuit_list` (enumerate available circuits)
  - `sanctuary/nullifier_hash` (compute nullifier for membership)
  - Optional: `sanctuary/custom_circuit_compile`

### Option C: Merkle Upgrade
- **Effort:** 1 week
- **Code changes:** ~800–1,200 LOC
- **Tests:** 35–50 tests
- **New dependencies:** 1 (merkle-tree, optional—can use @noble/hashes)
- **New MCP tools:** 3–4

---

## RISK ASSESSMENT

### Option A (Reposition)
- **Risk:** Minimal
- **Potential issue:** If "commitment-only" has semantic meaning to downstream users, this is a breaking change in semantics (not API)

### Option B (Groth16)
- **Risk:** Moderate-High
- **Issues:**
  1. **Trusted setup dependency:** Every circuit requires proving/verifying keys from a ceremony. If we use pre-compiled circuits, we depend on third-party ceremonies. No ceremony = no proofs.
  2. **Proof size growth:** Groth16 proofs are 288 bytes (vs. 128 for Schnorr), larger serialization cost
  3. **Proving time:** 0.5–2s per proof (vs. <1ms for Schnorr). Not suitable for real-time interactive scenarios.
  4. **Dependency complexity:** snarkjs brings transitive deps (elliptic, bn.js). Current noble-based stack has zero transitive deps.
  5. **Circuit correctness:** Writing correct Circom circuits is non-trivial. Off-by-one bugs = broken proofs.
  6. **Security review overhead:** Adding SNARK support requires cryptographic review of circuit design + parameter choices.

### Option C (Merkle)
- **Risk:** Low
- **Issues:** Merkle proofs are not composable with Pedersen in the same way SNARKs are. Merkle + Pedersen doesn't unlock new expressiveness compared to Schnorr alone.

---

## RECOMMENDATION

### For Moltbook Deployment (Short-term)

**Do Option A (Reposition):**
1. Recognize that current implementation already delivers "Full L3"
2. Update sovereignty audit to score L3 as "Full" for Pedersen + Schnorr + range proofs
3. Add documentation explaining proof system choices
4. **Est. 2–4 hours, zero risk, no new dependencies**

**Why:** The Moltbook agent will move from L3 "Degraded" to L3 "Full" immediately, improving overall sovereignty score. No delays, no new tests needed.

### For Future Roadmap (Medium-term)

**Consider Option C (Merkle) after Option A:**
- Adds structured data disclosure capability
- Low implementation risk
- Complements existing Pedersen/Schnorr without conflicts
- Natural next step: selective disclosure → selective disclosure over structured data
- **Est. 1 week, low risk, minimal deps**

**Defer Option B (Groth16):**
- Reserve for Phase 2 when use cases demand arbitrary circuit support
- Groth16 is more useful for proving *computations* (e.g., "I ran this algorithm and got this output") than for *claims* (e.g., "I have a credential")
- Current L3 already handles claims well
- SNARKs add complexity (trusted setups, proving time, circuit correctness) with diminishing returns for selective disclosure use cases

---

## DEPENDENCIES SUMMARY (OPTION B ONLY)

### New Runtime Dependencies
```json
{
  "snarkjs": "^0.7.0",
  "@zk-kit/circuits": "^1.0.0",
  "@zk-kit/snarks": "^0.7.0"
}
```

### Estimated Size Impact
- snarkjs: ~100KB unpacked
- zk-kit packages: ~50KB combined
- Proving/verification keys: ~1MB per circuit (stored on disk, not in npm package)
- **Total npm package size increase:** ~150KB (~30% growth from current ~600KB)

### Build-Time Dependency (Circom)
```json
{
  "circom": "^2.1.5",
  "circom_runtime": "^0.1.22"
}
```
(DevDependency only; used for circuit compilation at build time, not runtime)

---

## TESTING STRATEGY (OPTION B)

### New Test Files
1. `test/l3/groth16-identity.test.ts` — Identity proof (20 tests)
2. `test/l3/groth16-range.test.ts` — Range proof via Groth16 (25 tests)
3. `test/l3/groth16-nullifier.test.ts` — Nullifier proofs (15 tests)
4. `test/l3/groth16-batch.test.ts` — Batch verification (10 tests)
5. `test/l3/groth16-canonical.test.ts` — Canonical serialization (10 tests)
6. `test/l3/zk-migration.test.ts` — Schnorr → Groth16 interop (15 tests)

### New Test Count
- **80–120 new tests**
- **Existing tests:** 640 LOC (73 tests) — would remain unchanged
- **Total post-upgrade:** ~150–190 tests across 6 L3 test files

### Key Test Scenarios
1. Proof generation with known circuit keys
2. Verification of valid proofs
3. Rejection of invalid proofs (tampered proof, wrong commitment, etc.)
4. Batch verification efficiency
5. Canonical JSON serialization (deterministic digest)
6. Circuit parameter validation (range bounds, nullifier domain)
7. Interop with existing Pedersen commitment tools

---

## WHAT CANNOT BE DONE IN TYPESCRIPT ALONE (OPTION B)

The following would require stepping outside the TypeScript ecosystem:

1. **Writing custom Circom circuits** (requires Circom compiler setup)
   - Workaround: Provide pre-compiled circuits only, defer custom circuits to Python/Rust

2. **Generating new proving keys** (requires running circuit-specific ceremony)
   - Workaround: Use pre-generated keys from public ceremonies (e.g., Powers of Tau)

3. **Ark-based SNARKs** (PLONK, Marlin) have no mature TypeScript bindings
   - Recommendation: Stick with Groth16 via snarkjs

---

## TIMELINE FOR OPTION B (IF CHOSEN)

| Phase | Week | Deliverables |
|-------|------|--------------|
| 1: Design | Week 1 | Circuit specs, dependency audit, security review plan |
| 2: Circuits | Week 2 | Circom identity, range, nullifier circuits + pre-compiled artifacts |
| 3: Implementation | Weeks 3–4 | Proof generation, verification, MCP tools, integration |
| 4: Testing | Week 4 | 80–120 new tests, interop tests, performance benchmarks |
| 5: Review & Polish | Week 5 | Security audit, docs, blog post, GitHub release |

---

## CONCLUSION

**Current state:** L3 is NOT missing interactive ZK proofs. It HAS them (Schnorr + range proofs on Ristretto255). The "commitment-only" label is a categorization artifact.

**Best path forward:**
1. **Immediate (this week):** Option A — Reposition L3 as "Full" (2–4 hours)
2. **Near-term (next month):** Option C — Add Merkle proofs if use cases emerge (1 week)
3. **Future (Phase 2):** Option B — Groth16 SNARKs if arbitrary-circuit proofs are needed (3–4 weeks)

**For Moltbook:** Option A unblocks the agent immediately with zero risk and minimal effort.

---

## APPENDIX: CURRENT IMPLEMENTATION DETAILS

### Ristretto255 Group Operations (from @noble/curves)

The current system uses `RistrettoPoint` for all group operations:
- **BASE point (G):** Standard generator
- **Generator H:** Derived via hash-to-curve (nothing-up-my-sleeve)
- **Order:** 2^252 + 27742317777884353535851937790883648493 (prime group order, no cofactor)

### Canonical Serialization

To ensure Sanctuary and Concordia bridge commitments always produce identical hashes:
- Keys sorted alphabetically in JSON
- No whitespace
- Numbers as decimal strings
- Null/undefined explicitly handled

Current implementation in `bridge/bridge.ts:stableStringify()` — must be byte-identical with Concordia's Python version.

### Audit Trail

All L3 operations are logged to the encrypted audit log:
- `proof_commitment` → commitment_id, commitment_hash (truncated)
- `disclosure_set_policy` → policy_id, rules_count
- `zk_prove` → proof_type, commitment_hash (truncated)
- `zk_verify` → proof_type, validity result

---

*End of research document. Ready for implementation planning.*
