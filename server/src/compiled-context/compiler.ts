import type {
  ClassifyRequest,
  RedactRequest,
  SummarizeRequest,
  Surface,
} from "../intelligence/types.js";
import type { CompiledContextScanRequest } from "./types.js";
import { COMPILED_CONTEXT_LIMITS } from "./types.js";

export function compileSubstrateContext(
  surface: Surface,
  request: SummarizeRequest | ClassifyRequest | RedactRequest,
): CompiledContextScanRequest {
  if (request.kind === "summarize") {
    const compiled = boundedCompile([request.context, request.query]);
    return {
      ...compiled,
      metadata: {
        assemblerId: "substrate-selector",
        surface,
        contributors: [
          { kind: "request_context" },
          { kind: "request_query" },
        ],
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
