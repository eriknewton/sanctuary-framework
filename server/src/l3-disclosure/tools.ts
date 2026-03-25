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

export function createL3Tools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[]; commitmentStore: CommitmentStore; policyStore: PolicyStore } {
  const commitmentStore = new CommitmentStore(storage, masterKey);
  const policyStore = new PolicyStore(storage, masterKey);

  const tools: ToolDefinition[] = [
    // ─── Commitment Schemes ───────────────────────────────────────────────

    {
      name: "sanctuary/proof_commitment",
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

        auditLog.append("l3", "proof_commitment", "system", {
          commitment_id: commitmentId,
          commitment_hash: commitment.commitment,
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
      name: "sanctuary/proof_reveal",
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

        auditLog.append("l3", "proof_reveal", "system", {
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
      name: "sanctuary/disclosure_set_policy",
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

        auditLog.append("l3", "disclosure_set_policy", identityId ?? "system", {
          policy_id: policy.policy_id,
          policy_name: policyName,
          rules_count: rules.length,
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
      name: "sanctuary/disclosure_evaluate",
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

        auditLog.append("l3", "disclosure_evaluate", "system", {
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
  ];

  return { tools, commitmentStore, policyStore };
}
