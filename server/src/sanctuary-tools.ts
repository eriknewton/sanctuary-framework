/**
 * Sanctuary MCP Server — Bootstrap, Policy, Identity, and Human-Link Tools
 *
 * A collection of convenience tools that glue together existing Sanctuary
 * subsystems (identity, SHR, Verascore publishing, principal policy):
 *
 *   sanctuary/sanctuary_bootstrap              (Tier 1)
 *   sanctuary/sanctuary_policy_status          (Tier 3)
 *   sanctuary/sanctuary_export_identity_bundle (Tier 1)
 *   sanctuary/sanctuary_link_to_human          (Tier 2, auto-allowed + anomaly-gated)
 *   sanctuary/sanctuary_sign_challenge         (Tier 2, auto-allowed + anomaly-gated)
 */

import type { ToolDefinition } from "./router.js";
import { toolResult } from "./router.js";
import type { IdentityManager } from "./l1-cognitive/tools.js";
import type { AuditLog } from "./l2-operational/audit-log.js";
import type { PrincipalPolicy } from "./principal-policy/types.js";
import type { SanctuaryConfig } from "./config.js";
import { sign as identitySign } from "./core/identity.js";

const PASSPHRASE_BACKUP_WARNING =
  "\u26a0\ufe0f  IMPORTANT: Your Sanctuary passphrase is the only way to decrypt your agent's state. " +
  "If lost, all encrypted data is unrecoverable by design. Back up your passphrase now " +
  "to a password manager, encrypted USB, or other secure location separate from this machine.";
import { derivePurposeKey } from "./core/key-derivation.js";
import { toBase64url } from "./core/encoding.js";
import { createIdentity } from "./core/identity.js";
import { generateSHR, type L4Evidence } from "./shr/generator.js";
import { gatherL4Evidence } from "./shr/tools.js";
import type { ReputationStore } from "./l4-reputation/reputation-store.js";

export interface SanctuaryToolsOptions {
  config: SanctuaryConfig;
  identityManager: IdentityManager;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  policy: PrincipalPolicy;
  keyProtection: "passphrase" | "hardware-key" | "recovery-key";
  /**
   * Optional reputation store. When provided, identity-bundle exports
   * include an SHR with L4 degradation evidence reflecting the current
   * reputation state.
   */
  reputationStore?: ReputationStore;
}

/**
 * Validate a Verascore URL (HTTPS-only; must match configured host or a
 * known verascore.ai subdomain). Prevents SSRF.
 */
function validateVerascoreUrl(
  urlStr: string,
  configuredUrl: string
): { ok: true } | { ok: false; error: string } {
  const allowed = new Set([
    "verascore.ai",
    "www.verascore.ai",
    "api.verascore.ai",
  ]);
  try {
    allowed.add(new URL(configuredUrl).hostname);
  } catch {
    // ignore
  }
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:") {
      return { ok: false, error: `Verascore URL must use HTTPS. Got: ${parsed.protocol}` };
    }
    if (!allowed.has(parsed.hostname)) {
      return {
        ok: false,
        error: `Verascore URL must point to a known Verascore host (${[...allowed].join(", ")}). Got: ${parsed.hostname}`,
      };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: `Invalid Verascore URL: ${urlStr}` };
  }
}

export function createSanctuaryTools(
  opts: SanctuaryToolsOptions
): { tools: ToolDefinition[] } {
  const { config, identityManager, masterKey, auditLog, policy, keyProtection, reputationStore } = opts;
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  /**
   * Build L4 evidence for an existing identity. Returns undefined when
   * no reputation store is configured (generator then leaves L4 alone).
   */
  async function l4EvidenceForIdentity(
    identity: { identity_id: string; did: string }
  ): Promise<L4Evidence | undefined> {
    if (!reputationStore) return undefined;
    return gatherL4Evidence(reputationStore, auditLog, identity);
  }

  /**
   * Build empty L4 evidence for a brand-new identity (bootstrap path).
   * The identity was just created so `NO_REPUTATION_HISTORY` and
   * `NO_VERASCORE_LINK` will always fire — that's the truth of the state.
   */
  function emptyL4Evidence(): L4Evidence {
    return {
      attestation_count: 0,
      tier_distribution: {
        "verified-sovereign": 0,
        "verified-degraded": 0,
        "self-attested": 0,
        "unverified": 0,
      },
      most_recent_attestation_at: null,
      dispute_count: 0,
      context_breakdown: {},
      verascore_linked: false,
    };
  }

  const tools: ToolDefinition[] = [
    // ─── sanctuary_bootstrap ───────────────────────────────────────────
    {
      name: "sanctuary_bootstrap",
      description:
        "One-shot bootstrap for a new sovereign agent identity. " +
        "Generates an Ed25519 keypair, stores the encrypted identity, " +
        "constructs a Sovereignty Health Report (SHR), and publishes it to Verascore. " +
        "Returns { did, profileUrl, tier } for the newly-minted agent.",
      inputSchema: {
        type: "object",
        properties: {
          label: {
            type: "string",
            description: "Human-readable label for the new identity (default: 'sovereign-agent')",
          },
          verascore_url: {
            type: "string",
            description: "Verascore base URL. Defaults to server config / SANCTUARY_VERASCORE_URL.",
          },
          publish: {
            type: "boolean",
            description: "Whether to publish the SHR to Verascore. Defaults to true.",
          },
        },
      },
      handler: async (args) => {
        const label = (args.label as string) || "sovereign-agent";
        const publish = args.publish === undefined ? true : Boolean(args.publish);
        const verascoreUrl =
          (args.verascore_url as string) || config.verascore.url || "https://verascore.ai";

        // 1. Generate + persist new identity
        const { publicIdentity, storedIdentity } = createIdentity(
          label,
          identityEncKey,
          keyProtection
        );
        await identityManager.save(storedIdentity);

        await auditLog.append("l1", "sanctuary_bootstrap:identity_create", publicIdentity.identity_id, {
          label,
          did: publicIdentity.did,
        });

        // 2. Generate SHR for the new identity.
        // A brand-new identity has no reputation and no Verascore link,
        // so the emitter will produce NO_REPUTATION_HISTORY + NO_VERASCORE_LINK.
        const shr = generateSHR(publicIdentity.identity_id, {
          config,
          identityManager,
          masterKey,
          l4Evidence: emptyL4Evidence(),
        });
        if (typeof shr === "string") {
          return toolResult({
            error: `Identity created but SHR generation failed: ${shr}`,
            did: publicIdentity.did,
            identity_id: publicIdentity.identity_id,
          });
        }

        // 3. Optionally publish to Verascore
        const agentSlug = publicIdentity.did
          .replace(/[^a-zA-Z0-9-]/g, "-")
          .toLowerCase();
        const profileUrl = `${verascoreUrl.replace(/\/$/, "")}/agent/${publicIdentity.did}`;

        if (!publish || !config.verascore.auto_publish_to_verascore) {
          void auditLog.append("l4", "sanctuary_bootstrap", publicIdentity.identity_id, {
            did: publicIdentity.did,
            published: false,
          });
          return toolResult({
            did: publicIdentity.did,
            identity_id: publicIdentity.identity_id,
            profileUrl,
            tier: "self-attested",
            published: false,
            passphrase_warning: PASSPHRASE_BACKUP_WARNING,
          });
        }

        // Validate Verascore URL
        const urlCheck = validateVerascoreUrl(verascoreUrl, config.verascore.url);
        if (!urlCheck.ok) {
          return toolResult({
            error: urlCheck.error,
            did: publicIdentity.did,
            identity_id: publicIdentity.identity_id,
          });
        }

        // Build + sign payload
        const publishData = {
          sovereigntyLayers: shr.body.layers,
          capabilities: shr.body.capabilities,
          degradations: shr.body.degradations,
          did: publicIdentity.did,
          label,
        };
        const payloadBytes = new TextEncoder().encode(JSON.stringify(publishData));

        let signatureB64: string;
        try {
          const sigBytes = identitySign(
            payloadBytes,
            storedIdentity.encrypted_private_key,
            identityEncKey
          );
          signatureB64 = toBase64url(sigBytes);
        } catch (err) {
          return toolResult({
            error: "Failed to sign bootstrap payload",
            details: err instanceof Error ? err.message : String(err),
            did: publicIdentity.did,
          });
        }

        const body = {
          agentId: agentSlug,
          signature: signatureB64,
          publicKey: publicIdentity.public_key,
          type: "shr",
          data: publishData,
        };

        try {
          const response = await fetch(`${verascoreUrl.replace(/\/$/, "")}/api/publish`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
          const result = (await response.json().catch(() => ({}))) as Record<
            string,
            unknown
          >;

          void auditLog.append("l4", "sanctuary_bootstrap", publicIdentity.identity_id, {
            did: publicIdentity.did,
            verascore_url: verascoreUrl,
            status: response.status,
            published: response.ok,
          });

          return toolResult({
            did: publicIdentity.did,
            identity_id: publicIdentity.identity_id,
            profileUrl,
            tier: "self-attested",
            published: response.ok,
            verascore_status: response.status,
            verascore_response: result,
            passphrase_warning: PASSPHRASE_BACKUP_WARNING,
          });
        } catch (err) {
          void auditLog.append("l4", "sanctuary_bootstrap", publicIdentity.identity_id, {
            did: publicIdentity.did,
            error: err instanceof Error ? err.message : String(err),
          });
          return toolResult({
            did: publicIdentity.did,
            identity_id: publicIdentity.identity_id,
            profileUrl,
            tier: "self-attested",
            published: false,
            warning: `Identity created but Verascore publish failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
            passphrase_warning: PASSPHRASE_BACKUP_WARNING,
          });
        }
      },
    },

    // ─── sanctuary_policy_status ───────────────────────────────────────
    {
      name: "sanctuary_policy_status",
      description:
        "Return a summary of the active Principal Policy: which operations " +
        "require approval (Tier 1), which are subject to anomaly detection " +
        "(Tier 2), and which auto-allow with audit (Tier 3).",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const tier1 = [...policy.tier1_always_approve].sort();
        const tier3 = [...policy.tier3_always_allow].sort();
        // Tier 2 is anomaly-gated: any operation not in tier1/tier3 effectively
        // sits here, but the gate architecture keys Tier 2 off baseline
        // anomaly detection rather than a named list. We surface the current
        // anomaly configuration so callers can reason about it.
        const tier2Config = policy.tier2_anomaly;

        void auditLog.append("l2", "sanctuary_policy_status", "system", {
          tier1_count: tier1.length,
          tier3_count: tier3.length,
        });

        return toolResult({
          tier1,
          tier2: [] as string[],
          tier3,
          tier2_anomaly_config: tier2Config,
          counts: {
            tier1: tier1.length,
            tier2: 0,
            tier3: tier3.length,
          },
          note:
            "Tier 2 is not a named list in Sanctuary — it is behavioral anomaly " +
            "detection applied to all operations. See tier2_anomaly_config.",
        });
      },
    },

    // ─── sanctuary_export_identity_bundle ──────────────────────────────
    {
      name: "sanctuary_export_identity_bundle",
      description:
        "Export a signed, portable identity bundle: { publicKey, did, shr, attestations }. " +
        "The bundle is signed with the identity's Ed25519 key so a recipient can verify " +
        "authenticity against the public key. Private keys are never included.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description: "Identity to export (defaults to primary identity).",
          },
          attestations: {
            type: "array",
            items: { type: "object" },
            description: "Optional list of attestation objects to include in the bundle.",
          },
        },
      },
      handler: async (args) => {
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();
        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        const l4Evidence = await l4EvidenceForIdentity(identity);
        const shr = generateSHR(identity.identity_id, {
          config,
          identityManager,
          masterKey,
          l4Evidence,
        });

        const attestations = (args.attestations as unknown[] | undefined) ?? [];

        const body = {
          format: "SANCTUARY_IDENTITY_BUNDLE_V1" as const,
          publicKey: identity.public_key,
          did: identity.did,
          identity_id: identity.identity_id,
          label: identity.label,
          key_type: identity.key_type,
          shr: typeof shr === "string" ? null : shr,
          attestations,
          exported_at: new Date().toISOString(),
        };

        const bodyBytes = new TextEncoder().encode(JSON.stringify(body));
        let signatureB64: string;
        try {
          const sigBytes = identitySign(
            bodyBytes,
            identity.encrypted_private_key,
            identityEncKey
          );
          signatureB64 = toBase64url(sigBytes);
        } catch (err) {
          return toolResult({
            error: "Failed to sign identity bundle.",
            details: err instanceof Error ? err.message : String(err),
          });
        }

        await auditLog.appendCritical({
          layer: "l1",
          operation: "sanctuary_export_identity_bundle",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            did: identity.did,
            attestation_count: attestations.length,
          },
        });

        return toolResult({
          bundle: body,
          signature: signatureB64,
          signed_by: identity.did,
        });
      },
    },

    // ─── sanctuary_link_to_human ───────────────────────────────────────
    {
      name: "sanctuary_link_to_human",
      description:
        "Trigger a Verascore magic-link login flow so a human principal can " +
        "authenticate and subsequently claim this agent's DID. The email is " +
        "sent by Verascore to the supplied address. This tool only initiates " +
        "the flow — it does not directly bind the DID.",
      inputSchema: {
        type: "object",
        properties: {
          email: {
            type: "string",
            description: "Email address of the human to link this agent to.",
          },
          verascore_url: {
            type: "string",
            description: "Verascore base URL. Defaults to server config.",
          },
        },
        required: ["email"],
      },
      handler: async (args) => {
        const email = args.email as string;
        const verascoreUrl =
          (args.verascore_url as string) || config.verascore.url || "https://verascore.ai";

        const urlCheck = validateVerascoreUrl(verascoreUrl, config.verascore.url);
        if (!urlCheck.ok) {
          return toolResult({ ok: false, error: urlCheck.error });
        }

        // Basic email shape validation (defense-in-depth — Verascore validates too)
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
          return toolResult({ ok: false, error: "Invalid email format." });
        }

        try {
          const response = await fetch(`${verascoreUrl.replace(/\/$/, "")}/api/auth/request`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
          });

          await response.json().catch(() => ({}));

          void auditLog.append("l4", "sanctuary_link_to_human", "system", {
            verascore_url: verascoreUrl,
            status: response.status,
            // Do not log the email to the audit trail — keep it local.
            email_domain: email.split("@")[1] ?? null,
          });

          // DELTA-08: redact target email from tool response so a
          // compromised agent cannot read back the email it sent to.
          return toolResult({
            ok: response.ok,
            message:
              "Check your email for a login link. After logging in, visit " +
              "verascore.ai to claim this agent's DID.",
            email_redacted: `***@${email.split("@")[1] ?? "***"}`,
            verascore_status: response.status,
          });
        } catch (err) {
          return toolResult({
            ok: false,
            error: `Failed to reach Verascore at ${verascoreUrl}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          });
        }
      },
    },

    // ─── sanctuary_sign_challenge ──────────────────────────────────────
    {
      name: "sanctuary_sign_challenge",
      description:
        "Sign a domain-separated nonce with the agent's Ed25519 key. " +
        "Used in DID-ownership proof flows. The signed message is constructed as: " +
        "'sanctuary-sign-challenge-v1\\x00' + purpose + '\\x00' + nonce. " +
        "The verifier MUST reconstruct the same domain-prefixed message before " +
        "calling Ed25519 verify — a raw-nonce signature is NOT valid for this tool. " +
        "The `purpose` field binds the signature to a specific use case (e.g. " +
        "'verascore-claim') so a signature produced for one purpose cannot be " +
        "replayed against a different verifier.",
      inputSchema: {
        type: "object",
        properties: {
          nonce: {
            type: "string",
            description: "The nonce / challenge string to sign.",
          },
          purpose: {
            type: "string",
            description:
              "Domain-separation tag identifying what the signature will be used for " +
              "(e.g. 'verascore-claim'). Required. Max 128 chars, printable ASCII only.",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign with (defaults to primary).",
          },
        },
        required: ["nonce", "purpose"],
      },
      handler: async (args) => {
        const nonce = args.nonce as string;
        const purpose = args.purpose as string;
        if (!nonce || nonce.length === 0) {
          return toolResult({ error: "nonce must be a non-empty string." });
        }
        if (nonce.length > 4096) {
          return toolResult({ error: "nonce exceeds maximum length (4096)." });
        }
        if (typeof purpose !== "string" || purpose.length === 0) {
          return toolResult({
            error: "purpose is required (domain-separation tag, e.g. 'verascore-claim').",
          });
        }
        if (purpose.length > 128) {
          return toolResult({ error: "purpose exceeds maximum length (128)." });
        }
        // Printable ASCII only; no NUL bytes (NUL is our separator).
        if (!/^[\x20-\x7E]+$/.test(purpose)) {
          return toolResult({
            error: "purpose must be printable ASCII only (no NUL, no non-ASCII).",
          });
        }

        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();
        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        // Construct the domain-separated message:
        //   "sanctuary-sign-challenge-v1" || 0x00 || purpose || 0x00 || nonce
        const domainTag = "sanctuary-sign-challenge-v1";
        const enc = new TextEncoder();
        const tagBytes = enc.encode(domainTag);
        const purposeBytes = enc.encode(purpose);
        const nonceBytes = enc.encode(nonce);
        const sep = new Uint8Array([0x00]);
        const message = new Uint8Array(
          tagBytes.length + 1 + purposeBytes.length + 1 + nonceBytes.length
        );
        let offset = 0;
        message.set(tagBytes, offset); offset += tagBytes.length;
        message.set(sep, offset); offset += 1;
        message.set(purposeBytes, offset); offset += purposeBytes.length;
        message.set(sep, offset); offset += 1;
        message.set(nonceBytes, offset);

        let sigB64: string;
        try {
          const sig = identitySign(
            message,
            identity.encrypted_private_key,
            identityEncKey
          );
          sigB64 = toBase64url(sig);
        } catch (err) {
          return toolResult({
            error: "Failed to sign nonce.",
            details: err instanceof Error ? err.message : String(err),
          });
        }

        await auditLog.append("l1", "sanctuary_sign_challenge", identity.identity_id, {
          did: identity.did,
          nonce_len: nonce.length,
          purpose,
        });

        return toolResult({
          signature: sigB64,
          did: identity.did,
          public_key: identity.public_key,
          signed_by: identity.did,
          domain_tag: domainTag,
          purpose,
        });
      },
    },
  ];

  return { tools };
}
