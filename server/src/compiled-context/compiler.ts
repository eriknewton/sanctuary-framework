import type {
  ClassifyRequest,
  RedactRequest,
  SummarizeRequest,
  Surface,
} from "../intelligence/types.js";
import { isFirstPartyContextClaim } from "../intelligence/types.js";
import type {
  CompiledContextContributor,
  CompiledContextScanRequest,
  CompiledContextTrustClass,
} from "./types.js";
import { COMPILED_CONTEXT_LIMITS } from "./types.js";

/**
 * Separator this compiler joins contributors with.
 *
 * MUST MATCH the `parts` reconstruction check in `./scanner.ts`, which proves
 * the per-contributor texts concatenate back to the exact artifact that was
 * hashed and cached. Every part below therefore carries its OWN leading
 * separator; concatenation, not a join, is what the scanner can verify.
 */
const PART_SEPARATOR = "\n";

/**
 * Surfaces on which a first-party context claim may be honored at all.
 *
 * `concierge` is the only surface whose context is compiled by this runtime's
 * own briefing builder (`concierge/prompt-builder.ts`, reached through
 * `ConciergeService.ask`). Every other surface's context is assembled from
 * text the operator, a calling agent, or a fetched result supplied.
 *
 * INVARIANT: this list is one of THREE conditions and never a substitute for
 * the others. The branded claim in `../intelligence/types.ts` is what an
 * out-of-process DTO cannot forge; the prefix re-verification below is what
 * stops a holder from naming more text than it authored; this list is what
 * keeps a future in-process importer of the mint function from widening the
 * exemption to another surface without editing a line that says so. Sharing
 * this list's surface name does not share the claim: `chat` and the v1.1
 * dashboard also invoke the `concierge` surface and hold no claim, so their
 * context is untrusted in full.
 */
const FIRST_PARTY_CONTEXT_SURFACES: readonly Surface[] = ["concierge"];

export function compileSubstrateContext(
  surface: Surface,
  request: SummarizeRequest | ClassifyRequest | RedactRequest,
): CompiledContextScanRequest {
  if (request.kind === "summarize") {
    const compiled = boundedCompile([request.context, request.query]);
    // The query is the operator's or the calling agent's own text, so it is
    // untrusted on every surface and always its own trailing contributor. It
    // carries the separator the artifact was joined with, so the parts
    // concatenate back to the artifact byte for byte.
    const queryPart = `${PART_SEPARATOR}${request.query}`;
    const contextParts = splitFirstPartyPrefix(surface, request);
    const parts = [...contextParts.map((part) => part.text), queryPart];
    const contributors: CompiledContextContributor[] = [
      ...contextParts.map((part) => ({
        kind: "request_context" as const,
        trust: part.trust,
      })),
      { kind: "request_query" as const, trust: "untrusted" as const },
    ];
    return {
      ...compiled,
      ...(compiled.preflightOverLimit === true ? {} : { parts }),
      metadata: {
        assemblerId: "substrate-selector",
        surface,
        contributors,
      },
    };
  }
  if (request.kind === "classify") {
    const count = request.items.length + request.categories.length;
    if (count > COMPILED_CONTEXT_LIMITS.maxContributors) {
      return overLimitRequest(surface, count);
    }
    const compiled = boundedCompile([...request.items, ...request.categories]);
    return {
      ...compiled,
      metadata: {
        assemblerId: "substrate-selector",
        surface,
        contributors: [
          ...request.items.map(() => ({ kind: "request_item" as const })),
          ...request.categories.map(() => ({ kind: "request_category" as const })),
        ],
      },
    };
  }
  const compiled = boundedCompile([request.text]);
  return {
    ...compiled,
    metadata: {
      assemblerId: "substrate-selector",
      surface,
      contributors: [{ kind: "redaction_text" }],
    },
  };
}

/**
 * Split `request.context` into the segment this runtime authored and the rest.
 *
 * Returns ONE untrusted contributor unless every condition holds: the surface
 * compiles its own context, the caller presented a branded claim, and the
 * claim's named prefix is really a non-empty proper prefix of the context it
 * was handed. Anything else is unprovable provenance, and unprovable
 * provenance is untrusted; a malformed or overreaching claim can only lose an
 * exemption, never widen one.
 */
function splitFirstPartyPrefix(
  surface: Surface,
  request: SummarizeRequest,
): ReadonlyArray<{ text: string; trust: CompiledContextTrustClass }> {
  const untrustedWhole = [
    { text: request.context, trust: "untrusted" as CompiledContextTrustClass },
  ];
  const claim = request.contextProvenance;
  if (!isFirstPartyContextClaim(claim)) return untrustedWhole;
  if (!FIRST_PARTY_CONTEXT_SURFACES.includes(surface)) return untrustedWhole;
  const prefix = claim.firstPartyPrefix;
  // An empty prefix claims nothing, and a prefix as long as the whole context
  // would leave no untrusted remainder to screen: both are rejected rather
  // than honored as a degenerate split.
  if (prefix.length === 0 || prefix.length >= request.context.length) {
    return untrustedWhole;
  }
  // The claim is CHECKED here, not trusted. A caller that names a prefix it did
  // not author fails this comparison and loses the exemption entirely.
  if (!request.context.startsWith(prefix)) return untrustedWhole;
  return [
    { text: prefix, trust: "first_party_runtime" },
    { text: request.context.slice(prefix.length), trust: "untrusted" },
  ];
}

function boundedCompile(parts: readonly string[]): Pick<
  CompiledContextScanRequest,
  "artifact" | "preflightOverLimit" | "observedByteLength"
> {
  let byteLength = 0;
  for (let index = 0; index < parts.length; index++) {
    byteLength += Buffer.byteLength(parts[index]!, "utf8");
    if (index > 0) byteLength += 1;
    if (byteLength > COMPILED_CONTEXT_LIMITS.maxBytes) {
      return {
        artifact: "",
        preflightOverLimit: true,
        observedByteLength: byteLength,
      };
    }
  }
  return { artifact: parts.join("\n"), observedByteLength: byteLength };
}

function overLimitRequest(
  surface: string,
  contributorCount: number,
): CompiledContextScanRequest {
  const boundedCount = Math.min(
    contributorCount,
    COMPILED_CONTEXT_LIMITS.maxContributors + 1,
  );
  return {
    artifact: "",
    preflightOverLimit: true,
    observedByteLength: 0,
    metadata: {
      assemblerId: "substrate-selector",
      surface,
      contributors: Array.from({ length: boundedCount }, () => ({
        kind: "request_item" as const,
      })),
    },
  };
}
