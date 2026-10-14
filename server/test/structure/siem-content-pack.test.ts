/**
 * SIEM content pack structure guard.
 *
 * The pack is verified only as repo-local schema and fixture content. It does
 * not claim a live Elastic or Cortex tenant drill.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { load as loadYaml } from "js-yaml";
import {
  SIEM_ECS_FIELD_MAPPING,
  SIEM_XDM_FIELD_MAPPING,
} from "../../src/audit/siem-formatter.js";

const repoRoot = join(__dirname, "..", "..", "..");
const packRoot = join(repoRoot, "integrations", "siem");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readNdjson(path: string): unknown[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function collectReferencedFields(value: unknown): string[] {
  const fields = new Set<string>();

  function visit(node: unknown): void {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
        if (key === "sanctuary_field" && typeof child === "string") {
          fields.add(child);
        }
        if (key === "fields" && Array.isArray(child)) {
          child.filter((item): item is string => typeof item === "string").forEach((item) => {
            if (item.startsWith("sanctuary.") || item.startsWith("event.") || item.startsWith("xdm.") || item === "@timestamp" || item === "_time") {
              fields.add(item);
            }
          });
        }
        visit(child);
      }
    }
  }

  visit(value);
  return [...fields].sort();
}

describe("SIEM content pack", () => {
  it("ships the expected pack layout", () => {
    for (const path of [
      join(packRoot, "README.md"),
      join(packRoot, "elastic", "README.md"),
      join(packRoot, "elastic", "ecs-field-mapping.json"),
      join(packRoot, "elastic", "ingest-pipeline.json"),
      join(packRoot, "elastic", "dashboards.ndjson"),
      join(packRoot, "elastic", "detection-rules.ndjson"),
      join(packRoot, "cortex-xdm", "README.md"),
      join(packRoot, "cortex-xdm", "ModelingRules", "SanctuaryAudit_1_0", "SanctuaryAudit_1_0.xif"),
      join(packRoot, "cortex-xdm", "ModelingRules", "SanctuaryAudit_1_0", "SanctuaryAudit_1_0_schema.json"),
      join(packRoot, "cortex-xdm", "Dashboards", "sanctuary-audit-overview.json"),
      join(packRoot, "cortex-xdm", "Dashboards", "sanctuary-decision-trends.json"),
      join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-deny-burst.json"),
      join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-sensitive-operation-denied.json"),
    ]) {
      expect(existsSync(path), relative(repoRoot, path)).toBe(true);
    }
  });

  it("parses every JSON, NDJSON, and YAML file in the pack", () => {
    const files = [
      "elastic/ecs-field-mapping.json",
      "elastic/ingest-pipeline.json",
      "elastic/dashboards.ndjson",
      "elastic/detection-rules.ndjson",
      "cortex-xdm/ModelingRules/SanctuaryAudit_1_0/SanctuaryAudit_1_0_schema.json",
      "cortex-xdm/Dashboards/sanctuary-audit-overview.json",
      "cortex-xdm/Dashboards/sanctuary-decision-trends.json",
      "cortex-xdm/CorrelationRules/sanctuary-deny-burst.json",
      "cortex-xdm/CorrelationRules/sanctuary-sensitive-operation-denied.json",
    ];

    for (const file of files) {
      const path = join(packRoot, file);
      const ext = extname(path);
      if (path.endsWith(".ndjson")) {
        expect(readNdjson(path).length, file).toBeGreaterThan(0);
      } else if (ext === ".json") {
        expect(readJson(path), file).toBeDefined();
      } else if (ext === ".yaml" || ext === ".yml") {
        expect(loadYaml(readFileSync(path, "utf8")), file).toBeDefined();
      }
    }
  });

  it("references only fields present in the ECS or XDM formatter mapping tables", () => {
    const allowedFields: Set<string> = new Set([
      ...Object.values(SIEM_ECS_FIELD_MAPPING),
      ...Object.values(SIEM_XDM_FIELD_MAPPING),
    ]);
    const packDocuments = [
      readJson(join(packRoot, "elastic", "ecs-field-mapping.json")),
      readJson(join(packRoot, "elastic", "ingest-pipeline.json")),
      ...readNdjson(join(packRoot, "elastic", "dashboards.ndjson")),
      ...readNdjson(join(packRoot, "elastic", "detection-rules.ndjson")),
      readJson(join(packRoot, "cortex-xdm", "ModelingRules", "SanctuaryAudit_1_0", "SanctuaryAudit_1_0_schema.json")),
      readJson(join(packRoot, "cortex-xdm", "Dashboards", "sanctuary-audit-overview.json")),
      readJson(join(packRoot, "cortex-xdm", "Dashboards", "sanctuary-decision-trends.json")),
      readJson(join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-deny-burst.json")),
      readJson(join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-sensitive-operation-denied.json")),
    ];

    const referenced = packDocuments.flatMap(collectReferencedFields);
    expect(referenced.length).toBeGreaterThan(0);
    for (const field of referenced) {
      expect(allowedFields.has(field), field).toBe(true);
    }
  });
});
