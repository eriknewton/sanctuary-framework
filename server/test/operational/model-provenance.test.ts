/**
 * Sanctuary MCP Server — L2 Model Provenance Tests
 *
 * Tests for model provenance declaration, storage, and retrieval.
 * Validates that agents can accurately declare the inference models
 * powering them, enabling transparency around model provenance and
 * potential backdoor risks (as highlighted by Vitalik Buterin's
 * "Secure LLM" blog post).
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  InMemoryModelProvenanceStore,
  MODEL_PRESETS,
  type ModelProvenance,
} from "../../src/operational/model-provenance.js";

describe("ModelProvenanceStore", () => {
  let store: InMemoryModelProvenanceStore;

  beforeEach(() => {
    store = new InMemoryModelProvenanceStore();
  });

  describe("declare() — add a model to the store", () => {
    it("declares a model successfully", () => {
      const provenance: ModelProvenance = {
        model_id: "qwen-3.5-35b",
        model_name: "Qwen 3.5 35B",
        model_version: "3.5",
        provider: "Alibaba Cloud",
        license: "Apache-2.0",
        open_weights: true,
        open_source: false,
        local_inference: true,
        declared_at: new Date().toISOString(),
      };

      store.declare(provenance);
      expect(store.list().length).toBe(1);
      expect(store.get("qwen-3.5-35b")).toEqual(provenance);
    });

    it("declares multiple models", () => {
      const model1 = MODEL_PRESETS.qwen35Local();
      const model2 = MODEL_PRESETS.llama33Local();

      store.declare(model1);
      store.declare(model2);

      expect(store.list().length).toBe(2);
      expect(store.get("qwen-3.5-35b")).toBeDefined();
      expect(store.get("llama-3.3-70b-instruct")).toBeDefined();
    });

    it("overwrites a model with the same ID", () => {
      const v1: ModelProvenance = {
        model_id: "custom-model",
        model_name: "Custom Model v1",
        model_version: "1.0",
        provider: "LocalHost",
        license: "Apache-2.0",
        open_weights: true,
        open_source: true,
        local_inference: true,
        declared_at: new Date().toISOString(),
      };

      const v2: ModelProvenance = {
        ...v1,
        model_name: "Custom Model v2",
        model_version: "2.0",
      };

      store.declare(v1);
      expect(store.get("custom-model")?.model_version).toBe("1.0");

      store.declare(v2);
      expect(store.get("custom-model")?.model_version).toBe("2.0");
      expect(store.list().length).toBe(1);
    });

    it("throws when model_id is missing", () => {
      const invalid: Partial<ModelProvenance> = {
        model_name: "Test Model",
        provider: "Test",
        license: "Apache-2.0",
        open_weights: true,
        open_source: false,
        local_inference: false,
        declared_at: new Date().toISOString(),
      };

      expect(() => store.declare(invalid as ModelProvenance)).toThrow(
        /model_id/
      );
    });

    it("throws when model_name is missing", () => {
      const invalid: Partial<ModelProvenance> = {
        model_id: "test-model",
        provider: "Test",
        license: "Apache-2.0",
        open_weights: true,
        open_source: false,
        local_inference: false,
        declared_at: new Date().toISOString(),
      };

      expect(() => store.declare(invalid as ModelProvenance)).toThrow(
        /model_name/
      );
    });

    it("throws when provider is missing", () => {
      const invalid: Partial<ModelProvenance> = {
        model_id: "test-model",
        model_name: "Test Model",
        license: "Apache-2.0",
        open_weights: true,
        open_source: false,
        local_inference: false,
        declared_at: new Date().toISOString(),
      };

      expect(() => store.declare(invalid as ModelProvenance)).toThrow(
        /provider/
      );
    });
  });

  describe("get() — retrieve a model by ID", () => {
    it("returns undefined for non-existent model", () => {
      expect(store.get("nonexistent")).toBeUndefined();
    });

    it("returns the declared model", () => {
      const provenance = MODEL_PRESETS.claudeOpus4();
      store.declare(provenance);

      expect(store.get("claude-opus-4")).toEqual(provenance);
    });

    it("returns the exact provenance object with all fields", () => {
      const provenance: ModelProvenance = {
        model_id: "test-model",
        model_name: "Test Model",
        model_version: "1.2.3",
        provider: "TestCorp",
        license: "MIT",
        weights_hash: "sha256:abcd1234",
        training_data_hash: "sha256:efgh5678",
        open_weights: true,
        open_source: true,
        local_inference: true,
        declared_at: "2026-04-03T10:00:00Z",
      };

      store.declare(provenance);
      expect(store.get("test-model")).toEqual(provenance);
    });
  });

  describe("list() — list all declared models", () => {
    it("returns empty array when no models declared", () => {
      expect(store.list()).toEqual([]);
    });

    it("returns all declared models", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      const m2 = MODEL_PRESETS.mistral7bLocal();
      const m3 = MODEL_PRESETS.claudeOpus4();

      store.declare(m1);
      store.declare(m2);
      store.declare(m3);

      const all = store.list();
      expect(all).toHaveLength(3);
      expect(all).toContainEqual(m1);
      expect(all).toContainEqual(m2);
      expect(all).toContainEqual(m3);
    });
  });

  describe("primary() — get the primary/main model", () => {
    it("returns undefined when no models declared", () => {
      expect(store.primary()).toBeUndefined();
    });

    it("returns the first declared model as primary", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      store.declare(m1);

      expect(store.primary()).toEqual(m1);
    });

    it("keeps the original primary when new models are added", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      const m2 = MODEL_PRESETS.llama33Local();

      store.declare(m1);
      store.declare(m2);

      expect(store.primary()).toEqual(m1);
    });
  });

  describe("setPrimary() — change which model is primary", () => {
    it("sets a declared model as primary", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      const m2 = MODEL_PRESETS.llama33Local();

      store.declare(m1);
      store.declare(m2);

      expect(store.primary()?.model_id).toBe("qwen-3.5-35b");

      store.setPrimary("llama-3.3-70b-instruct");
      expect(store.primary()?.model_id).toBe("llama-3.3-70b-instruct");
    });

    it("throws when setting a non-existent model as primary", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      store.declare(m1);

      expect(() => store.setPrimary("nonexistent")).toThrow(
        /not found in store/
      );
    });

    it("allows switching back to a previous model", () => {
      const m1 = MODEL_PRESETS.qwen35Local();
      const m2 = MODEL_PRESETS.llama33Local();

      store.declare(m1);
      store.declare(m2);

      store.setPrimary("llama-3.3-70b-instruct");
      expect(store.primary()?.model_id).toBe("llama-3.3-70b-instruct");

      store.setPrimary("qwen-3.5-35b");
      expect(store.primary()?.model_id).toBe("qwen-3.5-35b");
    });
  });

  describe("MODEL_PRESETS — built-in model declarations", () => {
    it("claudeOpus4 has correct properties", () => {
      const preset = MODEL_PRESETS.claudeOpus4();

      expect(preset.model_id).toBe("claude-opus-4");
      expect(preset.model_name).toBe("Claude Opus 4");
      expect(preset.provider).toBe("Anthropic");
      expect(preset.open_weights).toBe(false);
      expect(preset.open_source).toBe(false);
      expect(preset.local_inference).toBe(false);
      expect(preset.license).toBe("proprietary");
    });

    it("qwen35Local has correct properties", () => {
      const preset = MODEL_PRESETS.qwen35Local();

      expect(preset.model_id).toBe("qwen-3.5-35b");
      expect(preset.open_weights).toBe(true);
      expect(preset.open_source).toBe(false);
      expect(preset.local_inference).toBe(true);
      expect(preset.provider).toBe("Alibaba Cloud");
    });

    it("llama33Local has correct properties", () => {
      const preset = MODEL_PRESETS.llama33Local();

      expect(preset.model_id).toBe("llama-3.3-70b-instruct");
      expect(preset.open_weights).toBe(true);
      expect(preset.open_source).toBe(true);
      expect(preset.local_inference).toBe(true);
      expect(preset.provider).toBe("Meta");
    });

    it("mistral7bLocal has correct properties", () => {
      const preset = MODEL_PRESETS.mistral7bLocal();

      expect(preset.model_id).toBe("mistral-7b-instruct");
      expect(preset.open_weights).toBe(true);
      expect(preset.open_source).toBe(true);
      expect(preset.local_inference).toBe(true);
    });

    it("all presets include declared_at timestamp", () => {
      const presets = [
        MODEL_PRESETS.claudeOpus4(),
        MODEL_PRESETS.qwen35Local(),
        MODEL_PRESETS.llama33Local(),
        MODEL_PRESETS.mistral7bLocal(),
      ];

      for (const preset of presets) {
        expect(preset.declared_at).toBeDefined();
        expect(() => new Date(preset.declared_at)).not.toThrow();
      }
    });

    it("presets are independent instances (not shared)", () => {
      const preset1 = MODEL_PRESETS.qwen35Local();
      const preset2 = MODEL_PRESETS.qwen35Local();

      preset1.license = "MIT";
      expect(preset2.license).toBe("Apache-2.0");
    });
  });

  describe("Integration — realistic agent setup", () => {
    it("agent declares multiple models (local + remote fallback)", () => {
      const local = MODEL_PRESETS.llama33Local();
      const fallback = MODEL_PRESETS.claudeOpus4();

      store.declare(local);
      store.declare(fallback);

      // Local is primary
      expect(store.primary()?.local_inference).toBe(true);

      // Can switch to remote fallback
      store.setPrimary("claude-opus-4");
      expect(store.primary()?.local_inference).toBe(false);

      // Full inventory available
      expect(store.list()).toHaveLength(2);
    });

    it("agent operator can verify model transparency", () => {
      // Open weights + open source = most transparent
      const transparent = MODEL_PRESETS.llama33Local();
      store.declare(transparent);

      const m = store.primary()!;
      expect(m.open_weights && m.open_source).toBe(true);

      // Proprietary = highest risk per Vitalik's post
      const proprietary = MODEL_PRESETS.claudeOpus4();
      store.declare(proprietary);
      store.setPrimary("claude-opus-4");

      const m2 = store.primary()!;
      expect(m2.open_weights || m2.open_source).toBe(false);
    });
  });
});
