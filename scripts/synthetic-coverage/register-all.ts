/**
 * Single source of truth for the synthetic-coverage fixture registration set.
 *
 * Importing this module (for its side effects) registers EVERY fixture in the
 * suite via the registry. The runner (run.ts), the baseline generator
 * (gen-coverage-baseline.ts), AND the PR ratchet test (coverage-ratchet.test.ts)
 * all import THIS file, so they can never drift out of lockstep: a PR that adds
 * or removes a fixture changes the one list here and is reflected identically in
 * the workflow report, the regenerated baseline, and the in-process ratchet
 * report (codex H finding on the DoE H-3 build — three copied import lists were
 * a false-green vector: dropping a fixture from run.ts alone would have let the
 * coverage workflow regress while the ratchet test stayed green on its stale
 * copy).
 *
 * Keep this list exhaustive and alphabetized within each subtree.
 */

import "./fixtures/substrate-trust/attestation-envelope.js";
import "./fixtures/substrate-trust/audit-chain-checkpoint.js";
import "./fixtures/substrate-trust/certificate-to-key.js";
import "./fixtures/substrate-trust/custody-key-isolation.js";
import "./fixtures/substrate-trust/identity-signing.js";
import "./fixtures/castle-wall/boundary-admission.js";
import "./fixtures/castle-wall/custody-key-gate.js";
import "./fixtures/castle-wall/deny-by-default.js";
import "./fixtures/castle-wall/guest-jail-confinement.js";
import "./fixtures/castle-wall/identity-signing-tool-registry-guard.js";
import "./fixtures/castle-wall/sentinel-registration.js";
import "./fixtures/audit-and-envelope/audit-chain-verifier.js";
import "./fixtures/audit-and-envelope/state-envelope-migration.js";
import "./fixtures/audit-and-envelope/transparency-checkpoints.js";
import "./fixtures/outbound-trust/context-gate-source-of-truth.js";
import "./fixtures/outbound-trust/query-anonymity.js";
import "./fixtures/proxy/proxy-env-isolation.js";
import "./fixtures/proxy/proxy-sse-ssrf.js";
import "./fixtures/proxy/proxy-tool-discovery.js";
import "./fixtures/state-trust/config-profile-fail-closed.js";
import "./fixtures/state-trust/critical-audit-durability.js";
import "./fixtures/state-trust/exit-bundle.js";
