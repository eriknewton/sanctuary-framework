import type {
  ClassifyRequest,
  SubstrateResponse,
} from "../../../../server/src/intelligence/types.js";
import {
  createAnonymizedFetch,
  getRequiredHeaders,
  getStripList,
  stripHeaders,
} from "../../../../server/src/query-anonymity/header-strip.js";
import {
  PII_CATEGORIES,
  rewritePiiRegexOnly,
} from "../../../../server/src/query-anonymity/pii-rewrite.js";
import {
  QUERY_INTENT_CLASSIFIER_SURFACE,
  classifyQueryIntent,
} from "../../../../server/src/query-anonymity/intent-classifier.js";
import { registerFixture } from "../../registry.js";
import { outcome } from "../state-trust/helpers.js";

const CLAIM_ID = "13";
const CLAIM_LABEL = "Query anonymity (selective disclosure)";

// Entrypoints: stripHeaders/createAnonymizedFetch, rewritePiiRegexOnly, and classifyQueryIntent.
// Mirrored tests: server/test/query-anonymity/header-strip.test.ts, pii-rewrite.test.ts, smart-mode.test.ts.
// Matrix claim: Query anonymity (selective disclosure).

const SHIPPED_ADAPTERS = ["anthropic", "openai", "google"] as const;
const MATRIXED_ADAPTERS = ["anthropic", "openai", "google"] as const;
const CORPUS_VERSION = "query-anonymity-pii-corpus-v1";

class FakeClassifierSelector {
  calls: Array<{ surface: string; request: ClassifyRequest }> = [];

  async invokeClassify(
    surface: string,
    request: ClassifyRequest
  ): Promise<SubstrateResponse> {
    this.calls.push({ surface, request });
    return {
      servedBy: "local",
      failureClass: null,
      body: {
        kind: "classify",
        results: [{ category: "identity_grounded", confidence: 0.91 }],
      },
      completedAt: new Date().toISOString(),
      latencyMs: 1,
    };
  }
}

function adapterMatrixIsComplete(shipped: readonly string[], matrixed: readonly string[]): boolean {
  const known = new Set(matrixed);
  return shipped.every((adapter) => known.has(adapter));
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "query-anonymity: header-strip", async () => {
  const started = performance.now();
  let observedHeaders: Record<string, string> = {};
  const wrapped = createAnonymizedFetch(async (_input, init) => {
    observedHeaders = init?.headers as Record<string, string>;
    return new Response("{}", { status: 200 });
  });

  await wrapped("https://substrate.example.test/v1/messages", {
    method: "POST",
    headers: {
      "User-Agent": "node/22.5.0 operator-mbp",
      "Accept-Language": "en-US,en;q=0.9",
      "X-Forwarded-For": "192.168.1.42",
      Referer: "https://fortress.local/operator",
      Authorization: "Bearer required",
      "Content-Type": "application/json",
    },
  });

  const passed =
    observedHeaders["User-Agent"] === "" &&
    observedHeaders["Accept-Language"] === "" &&
    observedHeaders["X-Forwarded-For"] === undefined &&
    observedHeaders.Referer === undefined &&
    observedHeaders.Authorization === "Bearer required" &&
    observedHeaders["Content-Type"] === "application/json";
  return outcome(started, passed, "expected identity-bearing outbound headers scrubbed");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "query-anonymity: pii-rewrite", async () => {
  const started = performance.now();
  const result = rewritePiiRegexOnly(
    "Email Alex Johnson at alex@example.com, call 415-555-1234, visit 123 Main Street, SSN 123-45-6789."
  );
  const passed =
    result.rewritten.includes("[EMAIL_0]") &&
    result.rewritten.includes("[PHONE_0]") &&
    result.rewritten.includes("[STREET_ADDRESS_0]") &&
    result.rewritten.includes("[SSN_0]") &&
    !result.rewritten.includes("alex@example.com") &&
    !result.rewritten.includes("415-555-1234") &&
    !result.rewritten.includes("123 Main Street") &&
    !result.rewritten.includes("123-45-6789") &&
    Object.keys(result.placeholders).length >= 4;
  return outcome(started, passed, "expected PII shapes rewritten before outbound payload");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "query-anonymity: smart-mode classification", async () => {
  const started = performance.now();
  const selector = new FakeClassifierSelector();
  const intent = await classifyQueryIntent("who is Erik Newton", selector as never);
  const passed =
    selector.calls.length === 1 &&
    selector.calls[0]?.surface === QUERY_INTENT_CLASSIFIER_SURFACE &&
    intent.intent_category === "identity_grounded" &&
    intent.preserve_pii_classes.includes("name") &&
    intent.confidence >= 0.6;
  return outcome(started, passed, "expected smart-mode classifier to preserve identity classes");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "query-anonymity: adapter-matrix coverage gate", async () => {
  const started = performance.now();
  const stripList = getStripList();
  const requiredHeaders = getRequiredHeaders();
  const corpusComplete = PII_CATEGORIES.length === 7 && CORPUS_VERSION === "query-anonymity-pii-corpus-v1";
  const adapterComplete = adapterMatrixIsComplete(SHIPPED_ADAPTERS, MATRIXED_ADAPTERS);
  const syntheticFutureAdapterRejected = !adapterMatrixIsComplete(
    [...SHIPPED_ADAPTERS, "future-substrate"],
    MATRIXED_ADAPTERS
  );
  const stripResult = stripHeaders({
    "x-api-key": "provider-required",
    "anthropic-version": "2023-06-01",
    "User-Agent": "node",
  });
  const passed =
    corpusComplete &&
    adapterComplete &&
    syntheticFutureAdapterRejected &&
    stripList.length >= 20 &&
    requiredHeaders.includes("x-api-key") &&
    stripResult.stripped["x-api-key"] === "provider-required" &&
    stripResult.stripped["anthropic-version"] === "2023-06-01";
  return outcome(started, passed, "expected corpus and adapter matrix guards to reject unmapped adapters");
});
