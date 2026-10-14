/**
 * SIEM content pack structure guard.
 *
 * The pack is verified only as repo-local schema and fixture content. It does
 * not claim a live Elastic or Cortex tenant drill.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { load as loadYaml } from "js-yaml";
import {
  SIEM_ECS_FIELD_MAPPING,
  SIEM_XDM_FIELD_MAPPING,
} from "../../src/audit/siem-formatter.js";

const repoRoot = join(__dirname, "..", "..", "..");
const packRoot = join(repoRoot, "integrations", "siem");
const cortexDataset = "sanctuary_audit_raw";

const xdmModeledFields = [
  "_time",
  "xdm.event.type",
  "xdm.event.description",
  "xdm.event.operation",
  "xdm.event.operation_sub_type",
  "xdm.event.outcome",
  "xdm.event.is_completed",
  "xdm.observer.product",
  "xdm.observer.vendor",
  "xdm.source.user.username",
  "sanctuary.audit.decision",
  "sanctuary.audit.result",
] as const;

type ParsedPackFile = {
  relativePath: string;
  ext: string;
  text: string;
  documents: unknown[];
};

function walkFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? walkFiles(path) : [path];
  });
}

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

function parsePackFile(absolutePath: string): ParsedPackFile {
  const relativePath = relative(packRoot, absolutePath);
  const text = readFileSync(absolutePath, "utf8");
  const ext = absolutePath.endsWith(".ndjson") ? ".ndjson" : extname(absolutePath);
  if (ext === ".json") {
    return { relativePath, ext, text, documents: [JSON.parse(text)] };
  }
  if (ext === ".ndjson") {
    return { relativePath, ext, text, documents: readNdjson(absolutePath) };
  }
  if (ext === ".yml" || ext === ".yaml") {
    return { relativePath, ext, text, documents: [loadYaml(text)] };
  }
  if (ext === ".xif" || ext === ".md") {
    return { relativePath, ext, text, documents: [] };
  }
  throw new Error(`Unhandled SIEM pack extension for ${relativePath}`);
}

function addField(fields: Set<string>, value: unknown): void {
  if (typeof value === "string") fields.add(value);
  if (Array.isArray(value)) value.forEach((item) => addField(fields, item));
}

function extractKqlFields(query: string): string[] {
  return [...query.matchAll(/(?:^|[\s(])([@A-Za-z_][A-Za-z0-9_.@]*)\s*:/g)].map(
    (match) => match[1]!
  );
}

function extractXqlFields(query: string): string[] {
  const fields = new Set<string>();
  for (const match of query.matchAll(/\b(?:xdm|sanctuary|user|event|service)\.[A-Za-z0-9_.]+\b|_time/g)) {
    fields.add(match[0]);
  }
  return [...fields];
}

function extractCtxFields(condition: string): string[] {
  return [...condition.matchAll(/\bctx\.([A-Za-z0-9_?.]+)/g)].map((match) =>
    match[1]!.replaceAll("?", "")
  );
}

function collectObjectReferences(value: unknown, mode: "elastic" | "cortex"): string[] {
  const fields = new Set<string>();

  function visit(node: unknown): void {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      if (key === "fields" || key === "alert_fields") addField(fields, child);
      if (key === "sanctuary_field" || key === "field") addField(fields, child);
      if (key === "if" && typeof child === "string") {
        extractCtxFields(child).forEach((field) => fields.add(field));
      }
      if (key === "query" && typeof child === "string") {
        const extractor = mode === "elastic" ? extractKqlFields : extractXqlFields;
        extractor(child).forEach((field) => fields.add(field));
      }
      if (key === "xql_query" && typeof child === "string") {
        extractXqlFields(child).forEach((field) => fields.add(field));
      }
      visit(child);
    }
  }

  visit(value);
  return [...fields];
}

function collectMarkdownReferences(text: string): string[] {
  return [...text.matchAll(/`([^`]+)`/g)]
    .map((match) => match[1]!)
    .filter((token) =>
      /^(?:@timestamp|_time|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]+)+|sanctuary_[a-z0-9_]+)$/.test(
        token
      )
    );
}

function collectXifAssignments(text: string): Array<{ left: string; right: string }> {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.includes("=") && line.endsWith(";"))
    .map((line) => {
      const [left, ...rightParts] = line.slice(0, -1).split("=");
      return { left: left!.trim(), right: rightParts.join("=").trim() };
    });
}

function collectRawFieldsFromExpression(expression: string): string[] {
  return [...expression.matchAll(/\bsanctuary_[a-z0-9_]+\b/g)].map((match) => match[0]);
}

function expectFieldsAllowed(fields: Iterable<string>, allowed: ReadonlySet<string>, label: string): void {
  const unique = [...new Set(fields)].sort();
  expect(unique.length, `${label} should name at least one field`).toBeGreaterThan(0);
  for (const field of unique) {
    expect(allowed.has(field), `${label} references ${field}`).toBe(true);
  }
}

function elasticMappingFields(): string[] {
  const mapping = readJson(join(packRoot, "elastic", "ecs-field-mapping.json")) as {
    fields: string[];
    mapping: Array<{ sanctuary_field: string }>;
  };
  expect(mapping.fields.sort()).toEqual(Object.values(SIEM_ECS_FIELD_MAPPING).sort());
  expect(mapping.mapping.map((entry) => entry.sanctuary_field).sort()).toEqual(
    Object.values(SIEM_ECS_FIELD_MAPPING).sort()
  );
  return mapping.fields;
}

function cortexSchemaFields(): string[] {
  const schema = readJson(
    join(
      packRoot,
      "cortex-xdm",
      "ModelingRules",
      "SanctuaryAudit_1_0",
      "SanctuaryAudit_1_0_schema.json"
    )
  ) as Record<string, Record<string, { type: string; is_array: boolean }>>;
  const fields = Object.keys(schema[cortexDataset] ?? {});
  expect(fields.sort()).toEqual(Object.values(SIEM_XDM_FIELD_MAPPING).sort());
  for (const [field, spec] of Object.entries(schema[cortexDataset] ?? {})) {
    expect(["string", "int", "float", "datetime", "boolean"], field).toContain(spec.type);
    expect(spec.is_array, field).toBe(false);
  }
  return fields;
}

describe("SIEM content pack", () => {
  it("ships the expected pack layout", () => {
    for (const path of [
      join(packRoot, "README.md"),
      join(packRoot, "elastic", "README.md"),
      join(packRoot, "elastic", "ecs-field-mapping.json"),
      join(packRoot, "elastic", "ingest-pipeline.json"),
      join(packRoot, "elastic", "detection-rules.ndjson"),
      join(packRoot, "cortex-xdm", "README.md"),
      join(
        packRoot,
        "cortex-xdm",
        "ModelingRules",
        "SanctuaryAudit_1_0",
        "SanctuaryAudit_1_0.yml"
      ),
      join(
        packRoot,
        "cortex-xdm",
        "ModelingRules",
        "SanctuaryAudit_1_0",
        "SanctuaryAudit_1_0.xif"
      ),
      join(
        packRoot,
        "cortex-xdm",
        "ModelingRules",
        "SanctuaryAudit_1_0",
        "SanctuaryAudit_1_0_schema.json"
      ),
      join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-deny-burst.yml"),
      join(packRoot, "cortex-xdm", "CorrelationRules", "sanctuary-sensitive-operation-denied.yml"),
    ]) {
      expect(existsSync(path), relative(repoRoot, path)).toBe(true);
    }
  });

  it("parses every handled pack file and rejects unknown extensions", () => {
    const files = walkFiles(packRoot);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const parsed = parsePackFile(file);
      if ([".json", ".ndjson", ".yml", ".yaml"].includes(parsed.ext)) {
        expect(parsed.documents.length, parsed.relativePath).toBeGreaterThan(0);
      }
    }
  });

  it("checks mapping files by full-set equality against formatter constants", () => {
    elasticMappingFields();
    cortexSchemaFields();
    const rootReadme = readFileSync(join(packRoot, "README.md"), "utf8");
    for (const field of [
      ...Object.values(SIEM_ECS_FIELD_MAPPING),
      ...Object.values(SIEM_XDM_FIELD_MAPPING),
    ]) {
      expect(rootReadme, `README mapping table should name ${field}`).toContain(field);
    }
  });

  it("references only fields present in each vendor family's field table", () => {
    const ecsAllowed = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
    const xdmRawAllowed = new Set(Object.values(SIEM_XDM_FIELD_MAPPING));
    const xdmModeledAllowed = new Set<string>(xdmModeledFields);
    const files = walkFiles(packRoot).map(parsePackFile);

    for (const file of files) {
      if (file.relativePath === "README.md") {
        expectFieldsAllowed(
          collectMarkdownReferences(file.text),
          new Set([...ecsAllowed, ...xdmRawAllowed, ...xdmModeledAllowed]),
          file.relativePath
        );
      }

      if (file.relativePath.startsWith("elastic/")) {
        const refs = [
          ...file.documents.flatMap((doc) => collectObjectReferences(doc, "elastic")),
          ...collectMarkdownReferences(file.text),
        ];
        expectFieldsAllowed(refs, ecsAllowed, file.relativePath);
      }

      if (file.relativePath.includes("SanctuaryAudit_1_0_schema.json")) {
        expectFieldsAllowed(cortexSchemaFields(), xdmRawAllowed, file.relativePath);
      } else if (file.relativePath.endsWith(".xif")) {
        const assignments = collectXifAssignments(file.text);
        expect(assignments.length, file.relativePath).toBeGreaterThan(0);
        expectFieldsAllowed(
          assignments.map((assignment) => assignment.left),
          xdmModeledAllowed,
          file.relativePath
        );
        expectFieldsAllowed(
          assignments.flatMap((assignment) => collectRawFieldsFromExpression(assignment.right)),
          xdmRawAllowed,
          file.relativePath
        );
      } else if (file.relativePath.startsWith("cortex-xdm/CorrelationRules/")) {
        const refs = file.documents.flatMap((doc) => collectObjectReferences(doc, "cortex"));
        expectFieldsAllowed(refs, xdmModeledAllowed, file.relativePath);
      } else if (file.relativePath === "cortex-xdm/README.md") {
        expectFieldsAllowed(
          collectMarkdownReferences(file.text),
          new Set([...xdmRawAllowed, ...xdmModeledAllowed]),
          file.relativePath
        );
      }
    }
  });

  it("rejects planted bad field references in every handled pack file type", () => {
    const ecsAllowed = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
    const xdmRawAllowed = new Set(Object.values(SIEM_XDM_FIELD_MAPPING));
    const xdmModeledAllowed = new Set<string>(xdmModeledFields);

    expect(() => expectFieldsAllowed(["event.not_a_real_field"], ecsAllowed, "json")).toThrow();
    expect(() =>
      expectFieldsAllowed(
        collectObjectReferences({ query: "user.not_a_real_field: value" }, "elastic"),
        ecsAllowed,
        "ndjson"
      )
    ).toThrow();
    expect(() =>
      expectFieldsAllowed(
        collectObjectReferences(
          { xql_query: "datamodel dataset = xdm | filter user.not_a_real_field = \"x\"" },
          "cortex"
        ),
        xdmModeledAllowed,
        "yml"
      )
    ).toThrow();
    expect(() =>
      expectFieldsAllowed(
        collectRawFieldsFromExpression("sanctuary_not_a_real_field;"),
        xdmRawAllowed,
        "xif"
      )
    ).toThrow();
    expect(() =>
      expectFieldsAllowed(
        collectMarkdownReferences("chart `event.not_a_real_field`"),
        ecsAllowed,
        "md"
      )
    ).toThrow();
  });
});
