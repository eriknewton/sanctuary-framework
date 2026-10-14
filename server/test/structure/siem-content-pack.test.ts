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
  SIEM_XDM_FIELD_HOMES,
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

// Null explicitly means no home; it never enters the allowed field-name set.
const xdmFieldHomes = Object.values(SIEM_XDM_FIELD_HOMES).filter(
  (field) => field !== null
);

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
  return parsePackText(relativePath, readFileSync(absolutePath, "utf8"));
}

function parsePackText(relativePath: string, text: string): ParsedPackFile {
  const ext = extname(relativePath);
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

type CortexMapping = {
  raw_fields: string[];
  mapping: Array<{ raw_field: string; xdm_field: string | null; note?: string }>;
};

function readCortexMapping(): CortexMapping {
  return readJson(join(packRoot, "cortex-xdm", "xdm-field-mapping.json")) as CortexMapping;
}

function cortexMappingFields(mapping = readCortexMapping()): { rawFields: string[]; xdmFields: string[] } {
  const expectedRawFields = Object.values(SIEM_XDM_FIELD_MAPPING).sort();
  expect(mapping.raw_fields.sort()).toEqual(expectedRawFields);
  expect(mapping.mapping.map((entry) => entry.raw_field).sort()).toEqual(expectedRawFields);
  // Key/home pairs must agree: independent sets would accept swapped meanings.
  expect(mapping.mapping.map(({ raw_field, xdm_field }) => [raw_field, xdm_field]).sort())
    .toEqual(Object.entries(SIEM_XDM_FIELD_HOMES).sort());
  for (const row of mapping.mapping) {
    if (row.xdm_field === null) {
      expect(row.note).toBe("no standard XDM home; keep as a raw dataset field");
    }
  }
  return {
    rawFields: mapping.raw_fields,
    xdmFields: mapping.mapping.map((entry) => entry.xdm_field).filter((field): field is string => field !== null),
  };
}

function expectReadmeFields(text: string, fields: readonly string[]): void {
  const tokens = new Set(collectMarkdownReferences(text));
  for (const field of fields) {
    expect(tokens.has(field), `README mapping table should name ${field}`).toBe(true);
  }
}

function checkPackFile(file: ParsedPackFile): void {
  const ecsAllowed = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
  const xdmAllowed = new Set([...Object.values(SIEM_XDM_FIELD_MAPPING), ...xdmFieldHomes]);
  const rootAllowed = new Set([...ecsAllowed, ...xdmAllowed]);
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
    const rootReadme = readFileSync(join(packRoot, "README.md"), "utf8")
      .split("\n").filter((line) => line.startsWith("|")).join("\n");
    expectReadmeFields(rootReadme, [
      ...Object.values(SIEM_ECS_FIELD_MAPPING),
      ...Object.values(SIEM_XDM_FIELD_MAPPING),
      ...cortex.xdmFields,
    ]);
  });

  it("references only fields present in each vendor family's field table", () => {
    const files = gitPackFiles().map(parsePackFile);

    for (const file of files) checkPackFile(file);
  });

  it("rejects planted bad field references through every file dispatch", () => {
    for (const path of expectedPackFiles) {
      const file = parsePackFile(path);
      if (file.ext === ".json") {
        const document = file.document as Record<string, unknown>;
        document.fields = ["event.not_a_real_field"];
        file.text = JSON.stringify(document);
      } else {
        file.text += "\nchart `event.not_a_real_field`";
      }
      // The planted name itself must be the refusal, not some other throw on the way.
      expect(() => checkPackFile(parsePackText(file.relativePath, file.text)), path)
        .toThrow(/references event\.not_a_real_field/);
    }
  });

  it("requires whole README field tokens", () => {
    expect(() => expectReadmeFields("`xdm.event.type`", ["event.type"])).toThrow();
    expect(() => expectReadmeFields("`event.type`", ["event.type"])).not.toThrow();
  });

  it("rejects swapped raw-to-home pairs", () => {
    const mapping = readCortexMapping();
    const operation = mapping.mapping.find((row) => row.raw_field === "sanctuary_event_operation")!;
    const outcome = mapping.mapping.find((row) => row.raw_field === "sanctuary_event_outcome")!;
    [operation.xdm_field, outcome.xdm_field] = [outcome.xdm_field, operation.xdm_field];
    expect(() => cortexMappingFields(mapping)).toThrow();
  });

  it("keeps unmapped custom values as raw fields with null homes", () => {
    const mapping = readCortexMapping();
    for (const field of ["sanctuary_audit_decision", "sanctuary_audit_result"]) {
      expect(mapping.mapping.find((row) => row.raw_field === field)).toEqual({
        raw_field: field,
        xdm_field: null,
        note: "no standard XDM home; keep as a raw dataset field",
      });
    }
    expect(collectObjectReferences({ xdm_field: null })).toEqual([]);
  });

  it("rejects an unknown extension through file dispatch", () => {
    expect(() => checkPackFile(parsePackText("elastic/planted.yaml", "fields: []")))
      .toThrow("Unhandled SIEM mapping extension for elastic/planted.yaml");
  });

  it("rejects unmatched files through file dispatch", () => {
    for (const path of ["elastic/planted.md", "cortex-xdm/planted.json"]) {
      expect(() => checkPackFile(parsePackText(path, path.endsWith(".json") ? "{}" : "`event.action`")))
        .toThrow(`No SIEM mapping reference guard matched ${path}`);
    }
  });
});
