/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Tool Definitions
 *
 * MCP tool wrappers for commitment schemes and disclosure policies.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import {
  createCommitment,
  verifyCommitment,
  CommitmentStore,
} from "./commitments.js";
import {
  evaluateDisclosure,
  PolicyStore,
  type DisclosureRule,
} from "./policies.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import {
  createPedersenCommitment,
  verifyPedersenCommitment,
  createProofOfKnowledge,
  verifyProofOfKnowledge,
  createRangeProof,
  verifyRangeProof,
} from "./zk-proofs.js";

export function createDisclosureTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[]; commitmentStore: CommitmentStore; policyStore: PolicyStore } {
  const commitmentStore = new CommitmentStore(storage, masterKey);
  const policyStore = new PolicyStore(storage, masterKey);

  const tools: ToolDefinition[] = [
    // ─── Commitment Schemes ───────────────────────────────────────────────

    {
      name: "proof_commitment",
      description:
        "Create a cryptographic commitment to a value. " +
        "The commitment hides the value until you choose to reveal it. " +
        "Returns the commitment hash and a blinding factor (store securely).",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "string",
            description: "The value to commit to",
          },
          blinding_factor: {
            type: "string",
            description:
              "Optional base64url blinding factor (auto-generated if omitted)",
          },
        },
        required: ["value"],
      },
      handler: async (args) => {
        const value = args.value as string;
        const blindingFactor = args.blinding_factor as string | undefined;

        const commitment = createCommitment(value, blindingFactor);

        // Store the commitment encrypted for reference
        const commitmentId = await commitmentStore.store(commitment, value);

        await auditLog.appendCritical({
          layer: "l3",
          operation: "proof_commitment",
          identity_id: "system",
          result: "success",
          details: {
            commitment_id: commitmentId,
            commitment_hash: commitment.commitment,
          },
        });

        return toolResult({
          commitment_id: commitmentId,
          commitment: commitment.commitment,
          blinding_factor: commitment.blinding_factor,
          committed_at: commitment.committed_at,
          note: "Store the blinding_factor securely. You will need it to reveal the committed value.",
        });
      },
    },

    {
      name: "proof_reveal",
      description:
        "Verify a previously committed value by revealing it with the blinding factor. " +
        "Returns whether the revealed value matches the commitment.",
      inputSchema: {
        type: "object",
        properties: {
          commitment: {
            type: "string",
            description: "The original commitment hash",
          },
          value: {
            type: "string",
            description: "The value being revealed",
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from the original commitment",
          },
        },
        required: ["commitment", "value", "blinding_factor"],
      },
      handler: async (args) => {
        const commitment = args.commitment as string;
        const value = args.value as string;
        const blindingFactor = args.blinding_factor as string;

        const valid = verifyCommitment(commitment, value, blindingFactor);

        void auditLog.append("l3", "proof_reveal", "system", {
          commitment_hash: commitment,
          valid,
        });

        return toolResult({
          valid,
          commitment,
          revealed_at: new Date().toISOString(),
        });
      },
    },

    // ─── Disclosure Policies ──────────────────────────────────────────────

    {
      name: "disclosure_set_policy",
      description:
        "Define a disclosure policy that controls what an agent will and will not " +
        "disclose in different interaction contexts. Rules specify which fields may " +
        "be disclosed, which must be withheld, and which require cryptographic proof.",
      inputSchema: {
        type: "object",
        properties: {
          policy_name: {
            type: "string",
            description: "Human-readable policy name",
          },
          rules: {
            type: "array",
            description: "Disclosure rules for different contexts",
            items: {
              type: "object",
              properties: {
                context: {
                  type: "string",
                  description:
                    'Interaction context: "negotiation", "commerce", "identity", "*" (wildcard)',
                },
                disclose: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields the agent MAY disclose",
                },
                withhold: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields the agent MUST NOT disclose",
                },
                proof_required: {
                  type: "array",
                  items: { type: "string" },
                  description:
                    "Fields that require proof rather than plain disclosure",
                },
              },
              required: ["context", "disclose", "withhold", "proof_required"],
            },
          },
          default_action: {
            type: "string",
            enum: ["withhold", "ask-principal"],
            description: "What to do when no rule matches a field",
          },
          identity_id: {
            type: "string",
            description: "Optional identity this policy is bound to",
          },
        },
        required: ["policy_name", "rules", "default_action"],
      },
      handler: async (args) => {
        const policyName = args.policy_name as string;
        const rules = args.rules as DisclosureRule[];
        const defaultAction = args.default_action as
          | "withhold"
          | "ask-principal";
        const identityId = args.identity_id as string | undefined;

        const policy = await policyStore.create(
          policyName,
          rules,
          defaultAction,
          identityId
        );

        await auditLog.appendCritical({
          layer: "l3",
          operation: "disclosure_set_policy",
          identity_id: identityId ?? "system",
          result: "success",
          details: {
            policy_id: policy.policy_id,
            policy_name: policyName,
            rules_count: rules.length,
          },
        });

        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          rules_count: policy.rules.length,
          created_at: policy.created_at,
        });
      },
    },

    {
      name: "disclosure_evaluate",
      description:
        "Evaluate a disclosure request against an active policy. " +
        "Returns per-field decisions: disclose, withhold, proof, or ask-principal.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "string",
            description: "The interaction context",
          },
          requested_fields: {
            type: "array",
            items: { type: "string" },
            description: "Fields the counterparty is requesting",
          },
          policy_id: {
            type: "string",
            description: "Specific policy to evaluate (uses first available if omitted)",
          },
        },
        required: ["context", "requested_fields"],
      },
      handler: async (args) => {
        const context = args.context as string;
        const requestedFields = args.requested_fields as string[];
        const policyId = args.policy_id as string | undefined;

        let policy;
        if (policyId) {
          policy = await policyStore.get(policyId);
        } else {
          const allPolicies = await policyStore.list();
          policy = allPolicies[0] ?? null;
        }

        if (!policy) {
          return toolResult({
            error: "No disclosure policy found. Create one with disclosure_set_policy first.",
          });
        }

        const decisions = evaluateDisclosure(policy, context, requestedFields);

        const withholding = decisions.filter(
          (d) => d.action === "withhold"
        ).length;
        const disclosing = decisions.filter(
          (d) => d.action === "disclose"
        ).length;
        const proofRequired = decisions.filter(
          (d) => d.action === "proof"
        ).length;
        const askPrincipal = decisions.filter(
          (d) => d.action === "ask-principal"
        ).length;

        void auditLog.append("l3", "disclosure_evaluate", "system", {
          policy_id: policy.policy_id,
          context,
          fields_requested: requestedFields.length,
          withholding,
          disclosing,
          proof_required: proofRequired,
        });

        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          context,
          decisions,
          summary: {
            total_fields: requestedFields.length,
            disclose: disclosing,
            withhold: withholding,
            proof: proofRequired,
            ask_principal: askPrincipal,
          },
          overall_recommendation:
            withholding > 0
              ? `Withholding ${withholding} of ${requestedFields.length} requested fields per policy "${policy.policy_name}"`
              : `All ${requestedFields.length} fields may be disclosed per policy "${policy.policy_name}"`,
        });
      },
    },

    // ─── ZK Proof Tools ───────────────────────────────────────────────────

    {
      name: "zk_commit",
      description:
        "Create a Pedersen commitment to a numeric value on Ristretto255. " +
        "Unlike SHA-256 commitments, Pedersen commitments support zero-knowledge proofs: " +
        "you can prove properties about the committed value without revealing it.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The integer value to commit to",
          },
        },
        required: ["value"],
      },
      handler: async (args) => {
        const value = args.value as number;

        if (!Number.isInteger(value)) {
          return toolResult({ error: "Value must be an integer." });
        }

        const commitment = createPedersenCommitment(value);

        await auditLog.appendCritical({
          layer: "l3",
          operation: "zk_commit",
          identity_id: "system",
          result: "success",
          details: {
            commitment_hash: commitment.commitment.slice(0, 16) + "...",
          },
        });

        return toolResult({
          commitment: commitment.commitment,
          blinding_factor: commitment.blinding_factor,
          committed_at: commitment.committed_at,
          proof_system: "pedersen-ristretto255",
          note: "Store the blinding_factor securely. Use zk_prove to create proofs about this commitment.",
        });
      },
    },

    {
      name: "zk_prove",
      description:
        "Create a zero-knowledge proof of knowledge for a Pedersen commitment. " +
        "Proves you know the value and blinding factor without revealing either. " +
        "Uses a Schnorr sigma protocol with Fiat-Shamir transform.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The committed value (integer)",
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from zk_commit (base64url)",
          },
          commitment: {
            type: "string",
            description: "The Pedersen commitment (base64url)",
          },
        },
        required: ["value", "blinding_factor", "commitment"],
      },
      handler: async (args) => {
        const value = args.value as number;
        const blindingFactor = args.blinding_factor as string;
        const commitment = args.commitment as string;

        // Verify the commitment first
        if (!verifyPedersenCommitment(commitment, value, blindingFactor)) {
          return toolResult({
            error: "The provided value and blinding factor do not match the commitment.",
          });
        }

        const proof = createProofOfKnowledge(value, blindingFactor, commitment);

        void auditLog.append("l3", "zk_prove", "system", {
          proof_type: proof.type,
          commitment: commitment.slice(0, 16) + "...",
        });

        return toolResult({
          proof,
          note: "This proof demonstrates knowledge of the commitment opening without revealing the value.",
        });
      },
    },

    {
      name: "zk_verify",
      description:
        "Verify a zero-knowledge proof of knowledge for a Pedersen commitment. " +
        "Checks that the prover knows the commitment's opening without learning anything.",
      inputSchema: {
        type: "object",
        properties: {
          proof: {
            type: "object",
            description: "The ZK proof object from zk_prove",
          },
        },
        required: ["proof"],
      },
      handler: async (args) => {
        const proof = args.proof as Parameters<typeof verifyProofOfKnowledge>[0];

        const valid = verifyProofOfKnowledge(proof);

        void auditLog.append("l3", "zk_verify", "system", {
          proof_type: proof.type,
          valid,
        });

        return toolResult({
          valid,
          proof_type: proof.type,
          commitment: proof.commitment,
          verified_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "zk_range_prove",
      description:
        "Create a zero-knowledge range proof: prove that a committed value is " +
        "within [min, max] without revealing the exact value. " +
        "Uses bit-decomposition with OR-proofs on Ristretto255.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The committed value (integer)",
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from zk_commit (base64url)",
          },
          commitment: {
            type: "string",
            description: "The Pedersen commitment (base64url)",
          },
          min: {
            type: "number",
            description: "Minimum of the range (inclusive)",
          },
          max: {
            type: "number",
            description: "Maximum of the range (inclusive)",
          },
        },
        required: ["value", "blinding_factor", "commitment", "min", "max"],
      },
      handler: async (args) => {
        const value = args.value as number;
        const blindingFactor = args.blinding_factor as string;
        const commitment = args.commitment as string;
        const min = args.min as number;
        const max = args.max as number;

        const proof = createRangeProof(value, blindingFactor, commitment, min, max);

        if ("error" in proof) {
          return toolResult({ error: proof.error });
        }

        void auditLog.append("l3", "zk_range_prove", "system", {
          proof_type: proof.type,
          range: `[${min}, ${max}]`,
          bits: proof.bit_commitments.length,
        });

        return toolResult({
          proof,
          note: `This proof demonstrates the committed value is in [${min}, ${max}] without revealing it.`,
        });
      },
    },

    {
      name: "zk_range_verify",
      description:
        "Verify a zero-knowledge range proof — confirms a committed value " +
        "is within the claimed range without learning the value.",
      inputSchema: {
        type: "object",
        properties: {
          proof: {
            type: "object",
            description: "The range proof object from zk_range_prove",
          },
        },
        required: ["proof"],
      },
      handler: async (args) => {
        const proof = args.proof as Parameters<typeof verifyRangeProof>[0];

        const valid = verifyRangeProof(proof);

        void auditLog.append("l3", "zk_range_verify", "system", {
          proof_type: proof.type,
          valid,
          range: `[${proof.min}, ${proof.max}]`,
        });

        return toolResult({
          valid,
          proof_type: proof.type,
          range: { min: proof.min, max: proof.max },
          commitment: proof.commitment,
          verified_at: new Date().toISOString(),
        });
      },
    },
  ];

  return { tools, commitmentStore, policyStore };
}

// ── Back-compat alias (L1-L4 rename PR-3) ───────────────────────────────
// The layer-numbered name stays exported so downstream imports keep working.
// The functional name above is canonical.
export const createL3Tools = createDisclosureTools;
