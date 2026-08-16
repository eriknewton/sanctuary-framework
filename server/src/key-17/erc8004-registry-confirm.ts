/**
 * Key 17 -- ERC-8004 optional on-chain registry confirmation.
 *
 * Verascore-proven adapter lane: this module faithfully reuses the
 * ERC-8004 Identity Registry `ownerOf(uint256)` ABI shape from
 * `verascore/src/lib/erc8004/abi/identity.ts` and the viem public-client read
 * approach from `verascore/src/lib/erc8004/read.ts`.
 *
 * The read is optional and default-off. When enabled, only the public ERC-8004
 * identity id leaves the fortress in an `eth_call`; signer keys, private state,
 * and Sanctuary storage never enter the RPC payload.
 */

import {
  createPublicClient,
  defineChain,
  http,
  isAddress,
  type Abi,
  type Address,
} from "viem";

// Copied from Verascore PR #32's Identity Registry ABI, narrowed to the one
// read Sanctuary needs for confirmation. Do not hand-roll this selector.
export const erc8004IdentityRegistryOwnerOfAbi = [
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
] as const satisfies Abi;

export interface Erc8004RegistryConfirmationConfig {
  enabled: boolean;
  rpc_url: string;
  chain_id: number;
  timeout_ms: number;
}

export type Erc8004RegistryConfirmationStatus =
  | "disabled"
  | "confirmed"
  | "unconfirmed";

export interface Erc8004RegistryConfirmation {
  status: Erc8004RegistryConfirmationStatus;
  chain_id?: number;
  registry?: string;
  reason?: string;
  owner_address?: string;
}

export interface Erc8004RegistryEgressRequest {
  destination: string;
  method: "POST";
  rpc_url: string;
  chain_id: number;
  identity: string;
}

export interface Erc8004RegistryEgressDecision {
  decision: "allow" | "deny";
  reason_code?: string;
  explanation?: string;
}

export type Erc8004RegistryEgressGate = (
  req: Erc8004RegistryEgressRequest,
) => Erc8004RegistryEgressDecision | Promise<Erc8004RegistryEgressDecision>;

export type Erc8004RegistryFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface Erc8004RegistryConfirmationDeps {
  config: Erc8004RegistryConfirmationConfig;
  egressGate?: Erc8004RegistryEgressGate;
  fetchFn?: Erc8004RegistryFetch;
}

export interface Erc8004RegistryConfirmationInput {
  identity: string;
  registry: string;
  chain_id: number;
  signer_address: string;
}

class Erc8004EgressDeniedError extends Error {
  readonly reasonCode: string;

  constructor(reasonCode: string) {
    super(reasonCode);
    this.name = "Erc8004EgressDeniedError";
    this.reasonCode = reasonCode;
  }
}

function parseAgentId(identity: string): bigint | null {
  if (!/^\d+$/.test(identity)) return null;
  try {
    return BigInt(identity);
  } catch {
    return null;
  }
}

export function erc8004RpcDestination(rpcUrl: string): string | null {
  try {
    const parsed = new URL(rpcUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    return parsed.host;
  } catch {
    return null;
  }
}

function chainForId(chainId: number, rpcUrl: string) {
  return defineChain({
    id: chainId,
    name: chainId === 1 ? "Ethereum Mainnet" : `Chain ${chainId}`,
    nativeCurrency: {
      name: chainId === 1 ? "Ether" : "Native Ether",
      symbol: "ETH",
      decimals: 18,
    },
    rpcUrls: {
      default: { http: [rpcUrl] },
    },
  });
}

async function requireEgressAllowed(params: {
  gate: Erc8004RegistryEgressGate | undefined;
  destination: string;
  rpcUrl: string;
  chainId: number;
  identity: string;
}): Promise<void> {
  if (!params.gate) {
    // Registry confirmation is an external read; without an egress decision it
    // must remain unconfirmed rather than silently opening the network.
    throw new Erc8004EgressDeniedError("egress_gate_unavailable");
  }

  const decision = await params.gate({
    destination: params.destination,
    method: "POST",
    rpc_url: params.rpcUrl,
    chain_id: params.chainId,
    identity: params.identity,
  });

  if (decision.decision !== "allow") {
    // A denied RPC read cannot upgrade assurance; the caller maps this to an
    // unconfirmed result so offline validity never becomes registry proof.
    throw new Erc8004EgressDeniedError(
      decision.reason_code ?? "egress_denied",
    );
  }
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function makeGatedFetch(params: {
  gate: Erc8004RegistryEgressGate | undefined;
  fallbackFetch: Erc8004RegistryFetch | undefined;
  chainId: number;
  identity: string;
}): Erc8004RegistryFetch {
  return async (input, init) => {
    const url = requestUrl(input);
    const destination = erc8004RpcDestination(url);
    if (!destination) {
      throw new Erc8004EgressDeniedError("invalid_rpc_url");
    }
    // Every RPC request is re-checked at fetch time because viem owns request
    // construction and this wrapper is the last boundary before the network.
    await requireEgressAllowed({
      gate: params.gate,
      destination,
      rpcUrl: url,
      chainId: params.chainId,
      identity: params.identity,
    });

    const fetcher = params.fallbackFetch ?? globalThis.fetch;
    return fetcher(input, init);
  };
}

function unconfirmed(
  input: Erc8004RegistryConfirmationInput,
  reason: string,
  ownerAddress?: string,
): Erc8004RegistryConfirmation {
  return {
    status: "unconfirmed",
    chain_id: input.chain_id,
    registry: input.registry,
    reason,
    ...(ownerAddress ? { owner_address: ownerAddress } : {}),
  };
}

function isMissingRecordError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const msg = error.message.toLowerCase();
  return (
    msg.includes("not registered") ||
    msg.includes("invalid token") ||
    msg.includes("nonexistent token") ||
    msg.includes("owner query for nonexistent token")
  );
}

function extractEgressDeniedReason(error: unknown): string | null {
  let cursor: unknown = error;
  const seen = new Set<unknown>();
  while (cursor && !seen.has(cursor)) {
    seen.add(cursor);
    if (cursor instanceof Erc8004EgressDeniedError) {
      return cursor.reasonCode;
    }
    if (cursor instanceof Error) {
      const match = cursor.message.match(/\b(egress_[a-z0-9_]+|invalid_rpc_url)\b/);
      if (match) return match[1]!;
      cursor = (cursor as Error & { cause?: unknown }).cause;
      continue;
    }
    if (typeof cursor === "object" && "cause" in cursor) {
      cursor = (cursor as { cause?: unknown }).cause;
      continue;
    }
    break;
  }
  return null;
}

/**
 * Optionally confirm that the offline-verified signer is the on-chain owner.
 *
 * Fails closed to `unconfirmed` on every config, egress, RPC, or registry
 * error. It never upgrades an offline result unless ownerOf(identity) exactly
 * matches the recovered signer address.
 */
export async function confirmErc8004RegistryOwner(
  deps: Erc8004RegistryConfirmationDeps,
  input: Erc8004RegistryConfirmationInput,
): Promise<Erc8004RegistryConfirmation> {
  const { config } = deps;
  if (!config.enabled) {
    return { status: "disabled" };
  }

  if (!config.rpc_url) {
    return unconfirmed(input, "rpc_not_configured");
  }

  const destination = erc8004RpcDestination(config.rpc_url);
  if (!destination) {
    return unconfirmed(input, "invalid_rpc_url");
  }

  if (input.chain_id !== config.chain_id) {
    return unconfirmed(input, "chain_mismatch");
  }

  if (!isAddress(input.registry)) {
    return unconfirmed(input, "invalid_registry_address");
  }

  if (!isAddress(input.signer_address)) {
    return unconfirmed(input, "invalid_signer_address");
  }

  // Only numeric ERC-8004 identities can be passed to ownerOf(uint256); any
  // other identity remains offline-only rather than being coerced.
  const agentId = parseAgentId(input.identity);
  if (agentId === null) {
    return unconfirmed(input, "identity_not_numeric");
  }

  try {
    const client = createPublicClient({
      chain: chainForId(config.chain_id, config.rpc_url),
      transport: http(config.rpc_url, {
        fetchFn: makeGatedFetch({
          gate: deps.egressGate,
          fallbackFetch: deps.fetchFn,
          chainId: config.chain_id,
          identity: input.identity,
        }),
        retryCount: 0,
        timeout: config.timeout_ms,
      }),
    });

    const owner = await client.readContract({
      address: input.registry as Address,
      abi: erc8004IdentityRegistryOwnerOfAbi,
      functionName: "ownerOf",
      args: [agentId],
    });

    const ownerAddress = String(owner);
    // The on-chain owner must match the recovered offline signer exactly; any
    // mismatch preserves offline validity but refuses registry_confirmed.
    if (ownerAddress.toLowerCase() !== input.signer_address.toLowerCase()) {
      return unconfirmed(input, "owner_mismatch", ownerAddress);
    }

    return {
      status: "confirmed",
      chain_id: input.chain_id,
      registry: input.registry,
      owner_address: ownerAddress,
    };
  } catch (error) {
    const egressDeniedReason = extractEgressDeniedReason(error);
    if (egressDeniedReason) return unconfirmed(input, egressDeniedReason);
    if (isMissingRecordError(error)) {
      return unconfirmed(input, "identity_not_registered");
    }
    return unconfirmed(input, "rpc_error");
  }
}
