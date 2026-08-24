/**
 * Sanctuary MCP Server — L2 Model Provenance
 *
 * Declares and attests to the model(s) powering this agent.
 *
 * Vitalik Buterin's "Secure LLM" post (April 2026) identified a critical gap:
 * open-weights-but-not-open-source models can have trained-in backdoors. Model
 * provenance declaration lets agents and their operators verify the integrity
 * of the inference backbone.
 *
 * Tracks: model name, version, weights hash, license, open-source status,
 * training data hash (if available). Included in SHR L2 section.
 *
 * This sits in L2 (Operational Isolation) because it's part of the runtime
 * attestation surface — the agent declares what model(s) it's actually running.
 */

/**
 * Metadata about a single model powering this agent.
 */
export interface ModelProvenance {
  /** Machine-readable model ID (e.g., "qwen3.5-35b", "claude-opus-4", "llama-3.3-70b-instruct") */
  model_id: string;

  /** Human-readable model name (e.g., "Qwen 3.5", "Claude Opus 4", "Llama 3.3 70B Instruct") */
  model_name: string;

  /** Semantic version (e.g., "3.5", "4.0", "3.3") */
  model_version: string;

  /** Provider/vendor (e.g., "Alibaba Cloud", "Anthropic", "Meta", "local") */
  provider: string;

  /** SHA-256 of model weights file, if available and verifiable */
  weights_hash?: string;

  /** SHA-256 of training data manifest or metadata, if available */
  training_data_hash?: string;

  /** License identifier (e.g., "Apache-2.0", "CC-BY-4.0", "proprietary", "unknown") */
  license: string;

  /** True if model weights are publicly available (even if training is proprietary) */
  open_weights: boolean;

  /** True if full training code, data, and methodology are publicly available */
  open_source: boolean;

  /** True if inference runs on the local agent's hardware (not delegated to cloud API) */
  local_inference: boolean;

  /** Closed intelligence surface names served by this verified local artifact. */
  serving_surfaces?: readonly string[];

  /** ISO 8601 timestamp when this provenance was declared */
  declared_at: string;
}

/**
 * In-memory and persistent store for model provenance declarations.
 * Declarations are encrypted under L1 sovereignty.
 */
export interface ModelProvenanceStore {
  /**
   * Declare a model's provenance and add it to the store.
   */
  declare(provenance: ModelProvenance): void;

  /**
   * Retrieve a model's provenance by ID.
   */
  get(model_id: string): ModelProvenance | undefined;

  /**
   * List all declared models.
   */
  list(): ModelProvenance[];

  /**
   * Get the primary/main model (the one the agent uses by default for inference).
   */
  primary(): ModelProvenance | undefined;

  /**
   * Set which model is the primary.
   */
  setPrimary(model_id: string): void;
}

/**
 * In-memory implementation of ModelProvenanceStore.
 * Suitable for most use cases. For encrypted persistence, integrate with L1 state store.
 */
export class InMemoryModelProvenanceStore implements ModelProvenanceStore {
  private models: Map<string, ModelProvenance> = new Map();
  private primaryModelId: string | null = null;

  declare(provenance: ModelProvenance): void {
    if (!provenance.model_id) {
      throw new Error("ModelProvenance requires a model_id");
    }
    if (!provenance.model_name) {
      throw new Error("ModelProvenance requires a model_name");
    }
    if (!provenance.provider) {
      throw new Error("ModelProvenance requires a provider");
    }

    this.models.set(provenance.model_id, provenance);

    // If this is the first model, make it primary
    if (this.primaryModelId === null) {
      this.primaryModelId = provenance.model_id;
    }
  }

  get(model_id: string): ModelProvenance | undefined {
    return this.models.get(model_id);
  }

  list(): ModelProvenance[] {
    return Array.from(this.models.values());
  }

  primary(): ModelProvenance | undefined {
    if (!this.primaryModelId) return undefined;
    return this.models.get(this.primaryModelId);
  }

  setPrimary(model_id: string): void {
    if (!this.models.has(model_id)) {
      throw new Error(`Model ${model_id} not found in store`);
    }
    this.primaryModelId = model_id;
  }
}

/**
 * Common model provenance presets for quick initialization.
 */
export const MODEL_PRESETS = {
  /**
   * Claude Opus 4 via Anthropic API (cloud inference, closed weights/source)
   */
  claudeOpus4: (): ModelProvenance => ({
    model_id: "claude-opus-4",
    model_name: "Claude Opus 4",
    model_version: "4.0",
    provider: "Anthropic",
    license: "proprietary",
    open_weights: false,
    open_source: false,
    local_inference: false,
    declared_at: new Date().toISOString(),
  }),

  /**
   * Qwen 3.5 via local inference (open weights, exact license unverified).
   *
   * This preset does not identify an upstream artifact precisely enough to
   * prove which size-specific Qwen terms apply. `unknown` is deliberately
   * narrower than the previous blanket Apache-2.0 assertion; a verified model
   * manifest supplies the exact upstream license for provisioned models.
   */
  qwen35Local: (): ModelProvenance => ({
    model_id: "qwen-3.5-35b",
    model_name: "Qwen 3.5 35B",
    model_version: "3.5",
    provider: "Alibaba Cloud",
    license: "unknown",
    open_weights: true,
    open_source: false,
    local_inference: true,
    declared_at: new Date().toISOString(),
  }),

  /**
   * Llama 3.3 70B via local inference (open weights, not OSI open-source).
   */
  llama33Local: (): ModelProvenance => ({
    model_id: "llama-3.3-70b-instruct",
    model_name: "Llama 3.3 70B Instruct",
    model_version: "3.3",
    provider: "Meta",
    license: "Llama Community License",
    open_weights: true,
    open_source: false,
    local_inference: true,
    declared_at: new Date().toISOString(),
  }),

  /**
   * Mistral 7B (open weights, open code, local inference)
   */
  mistral7bLocal: (): ModelProvenance => ({
    model_id: "mistral-7b-instruct",
    model_name: "Mistral 7B Instruct",
    model_version: "7",
    provider: "Mistral AI",
    license: "Apache-2.0",
    open_weights: true,
    open_source: true,
    local_inference: true,
    declared_at: new Date().toISOString(),
  }),
};
