/**
 * SIEM field mapping structure guard.
 *
 * The integration files are verified only as repo-local mappings and README
 * field references. They do not claim a live Elastic or Cortex tenant drill.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import {
  SIEM_ECS_FIELD_MAPPING,
  SIEM_XDM_FIELD_MAPPING,
} from "../../src/audit/siem-formatter.js";

const repoRoot = join(__dirname, "..", "..", "..");
const packRoot = join(repoRoot, "integrations", "siem");

const expectedPackFiles = [
  "integrations/siem/README.md",
  "integrations/siem/cortex-xdm/README.md",
  "integrations/siem/cortex-xdm/xdm-field-mapping.json",
  "integrations/siem/elastic/README.md",
  "integrations/siem/elastic/ecs-field-mapping.json",
] as const;

const xdmFieldHomes = [
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
  document: unknown | undefined;
};

function gitPackFiles(): string[] {
  return execFileSync("git", ["ls-files", "integrations/siem"], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function parsePackFile(repoPath: string): ParsedPackFile {
  const absolutePath = join(repoRoot, repoPath);
  const relativePath = relative(packRoot, absolutePath);
  const text = readFileSync(absolutePath, "utf8");
  const ext = extname(absolutePath);
  if (ext === ".json") {
    return { relativePath, ext, text, document: JSON.parse(text) };
  }
  if (ext === ".md") {
    return { relativePath, ext, text, document: undefined };
  }
  throw new Error(`Unhandled SIEM mapping extension for ${relativePath}`);
}

function addField(fields: Set<string>, value: unknown): void {
  if (typeof value === "string") fields.add(value);
  if (Array.isArray(value)) value.forEach((item) => addField(fields, item));
}

function collectObjectReferences(value: unknown): string[] {
  const fields = new Set<string>();

  function visit(node: unknown): void {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      if (
        key === "fields" ||
        key === "raw_fields" ||
        key === "sanctuary_field" ||
        key === "raw_field" ||
        key === "xdm_field"
      ) {
        addField(fields, child);
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
  const expected = Object.values(SIEM_ECS_FIELD_MAPPING).sort();
  expect(mapping.fields.sort()).toEqual(expected);
  expect(mapping.mapping.map((entry) => entry.sanctuary_field).sort()).toEqual(expected);
  return mapping.fields;
}

function cortexMappingFields(): { rawFields: string[]; xdmFields: string[] } {
  const mapping = readJson(join(packRoot, "cortex-xdm", "xdm-field-mapping.json")) as {
    raw_fields: string[];
    mapping: Array<{ raw_field: string; xdm_field: string }>;
  };
  const expectedRawFields = Object.values(SIEM_XDM_FIELD_MAPPING).sort();
  expect(mapping.raw_fields.sort()).toEqual(expectedRawFields);
  expect(mapping.mapping.map((entry) => entry.raw_field).sort()).toEqual(expectedRawFields);
  expect(mapping.mapping.map((entry) => entry.xdm_field).sort()).toEqual([...xdmFieldHomes].sort());
  return {
    rawFields: mapping.raw_fields,
    xdmFields: mapping.mapping.map((entry) => entry.xdm_field),
  };
}

describe("SIEM field mappings", () => {
  it("ships only the expected mapping layout", () => {
    for (const path of expectedPackFiles) {
      expect(existsSync(join(repoRoot, path)), path).toBe(true);
    }
    expect(gitPackFiles()).toEqual([...expectedPackFiles].sort());
  });

  it("parses every handled mapping file and rejects unknown extensions", () => {
    const files = gitPackFiles();
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const parsed = parsePackFile(file);
      if (parsed.ext === ".json") {
        expect(parsed.document, parsed.relativePath).toBeDefined();
      } else if (parsed.ext === ".md") {
        expect(parsed.text.length, parsed.relativePath).toBeGreaterThan(0);
      } else {
        throw new Error(`Unhandled SIEM mapping file ${parsed.relativePath}`);
      }
    }
  });

  it("checks mapping files by full-set equality against formatter constants", () => {
    elasticMappingFields();
    const cortex = cortexMappingFields();
    const rootReadme = readFileSync(join(packRoot, "README.md"), "utf8");
    for (const field of [
      ...Object.values(SIEM_ECS_FIELD_MAPPING),
      ...Object.values(SIEM_XDM_FIELD_MAPPING),
      ...cortex.xdmFields,
    ]) {
      expect(rootReadme, `README mapping table should name ${field}`).toContain(field);
    }
  });

  it("references only fields present in each vendor family's field table", () => {
    const ecsAllowed = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
    const cortex = cortexMappingFields();
    const xdmAllowed = new Set([...cortex.rawFields, ...cortex.xdmFields]);
    const rootAllowed = new Set([...ecsAllowed, ...xdmAllowed]);
    const files = gitPackFiles().map(parsePackFile);

    for (const file of files) {
      if (file.relativePath === "README.md") {
        expectFieldsAllowed(collectMarkdownReferences(file.text), rootAllowed, file.relativePath);
      } else if (file.relativePath === "elastic/README.md") {
        expectFieldsAllowed(collectMarkdownReferences(file.text), ecsAllowed, file.relativePath);
      } else if (file.relativePath === "elastic/ecs-field-mapping.json") {
        expectFieldsAllowed(collectObjectReferences(file.document), ecsAllowed, file.relativePath);
      } else if (file.relativePath === "cortex-xdm/README.md") {
        expectFieldsAllowed(collectMarkdownReferences(file.text), xdmAllowed, file.relativePath);
      } else if (file.relativePath === "cortex-xdm/xdm-field-mapping.json") {
        expectFieldsAllowed(collectObjectReferences(file.document), xdmAllowed, file.relativePath);
      } else {
        throw new Error(`No SIEM mapping reference guard matched ${file.relativePath}`);
      }
    }
  });

  it("rejects planted bad field references in every remaining handled file type", () => {
    const ecsAllowed = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
    const xdmAllowed = new Set([
      ...Object.values(SIEM_XDM_FIELD_MAPPING),
      ...xdmFieldHomes,
    ]);

    expect(() => expectFieldsAllowed(["event.not_a_real_field"], ecsAllowed, "json")).toThrow();
    expect(() =>
      expectFieldsAllowed(
        collectObjectReferences({
          raw_fields: ["sanctuary_not_a_real_field"],
          mapping: [{ raw_field: "sanctuary_not_a_real_field", xdm_field: "_time" }],
        }),
        xdmAllowed,
        "json"
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
