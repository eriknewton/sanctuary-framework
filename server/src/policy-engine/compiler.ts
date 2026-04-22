/**
 * Sanctuary Policy Engine — Authoring-time English compiler.
 *
 * Walkthrough Key 10 LOCKED: "English-first authoring, declarative artifact
 * under the hood, power-user DSL as escape hatch. Operator writes natural
 * language ... LLM compiles to structured policy rule. Operator sees both —
 * the English they wrote + the compiled rule — and approves."
 *
 * The LLM compile runs at AUTHORING TIME only. Gates never call this
 * module. Keeping them in separate subtrees makes the structural separation
 * legible at the import-graph level (see gate-import-hygiene.test.ts).
 *
 * The compile step is offline-able: the `CompilePass` function type accepts
 * any transport — local Ollama, Venice.ai, TEE-attested annex, or an
 * operator-pinned fixture for test harnesses. No vendor is hard-wired.
 */

import { sha256 } from "@noble/hashes/sha256";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { toBase64url } from "../core/encoding.js";
import { validateCompiledPolicyShape } from "./canonical-policy.js";
import { COMPILED_POLICY_SCHEMA_VERSION } from "./constants.js";
import { CompilerDeterminismError } from "./errors.js";
import type { CompiledPolicy } from "./types.js";

/** Authoring request: English + context the compile pass needs. */
export interface AuthoringRequest {
  agent_id: string;
  fortress_id: string;
  policy_version: number;
  parent_version?: number;
  /** The English the operator wrote. */
  source_english: string;
  /** Optional prior policy — compiler may merge rather than author from scratch. */
  prior_policy?: CompiledPolicy;
}

/**
 * The compile pass. Implementers: local LLM, remote LLM via gateway, or a
 * deterministic fixture. The return MUST be a valid CompiledPolicy shape.
 *
 * The returned policy is expected to have a fixed `compiled_at` — compilers
 * SHOULD stamp the current time, but tests that exercise determinism stamp
 * a fixed string. Either is acceptable as long as the same author input +
 * same compiler + same time stamp yield the same blob.
 */
export type CompilePass = (req: AuthoringRequest) => Promise<CompiledPolicy>;

/**
 * Run a compile pass and return both the compiled policy and an SHA-256
 * digest of its canonical bytes. Operators approve against the digest; any
 * later drift between English and artifact is caught by a digest mismatch.
 */
export async function compileAndDigest(
  req: AuthoringRequest,
  pass: CompilePass
): Promise<{ compiled: CompiledPolicy; digest: string }> {
  const compiled = await pass(req);
  validateCompiledPolicyShape(compiled);
  if (compiled.schema_version !== COMPILED_POLICY_SCHEMA_VERSION) {
    throw new CompilerDeterminismError(
      `compile pass produced schema_version ${compiled.schema_version}; engine handles ${COMPILED_POLICY_SCHEMA_VERSION} only`
    );
  }
  if (compiled.agent_id !== req.agent_id) {
    throw new CompilerDeterminismError(
      `compile pass produced agent_id ${compiled.agent_id}; authoring request was for ${req.agent_id}`
    );
  }
  if (compiled.fortress_id !== req.fortress_id) {
    throw new CompilerDeterminismError(
      `compile pass produced fortress_id ${compiled.fortress_id}; authoring request was for ${req.fortress_id}`
    );
  }
  if (compiled.policy_version !== req.policy_version) {
    throw new CompilerDeterminismError(
      `compile pass produced policy_version ${compiled.policy_version}; authoring request asked for ${req.policy_version}`
    );
  }
  const digest = toBase64url(sha256(canonicalizeToBytes(compiled)));
  return { compiled, digest };
}

/**
 * Run the same authoring request through the compile pass twice and assert
 * the digests match. Used by the operator-approval path so an unstable
 * compiler cannot ship (operator approves digest A; engine re-derives
 * digest B at pin-time).
 */
export async function verifyCompilerDeterminism(
  req: AuthoringRequest,
  pass: CompilePass
): Promise<{ compiled: CompiledPolicy; digest: string }> {
  const a = await compileAndDigest(req, pass);
  const b = await compileAndDigest(req, pass);
  if (a.digest !== b.digest) {
    throw new CompilerDeterminismError(
      `compile pass produced non-deterministic output for the same authoring request (digest ${a.digest} vs ${b.digest})`
    );
  }
  return a;
}
