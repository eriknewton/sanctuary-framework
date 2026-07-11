/**
 * Hermetic tests for the operator config-file loader (`readExportConfig`).
 *
 * Uses a throwaway temp fortress dir under the OS temp dir (never a real
 * ~/.sanctuary, never the network). Proves: missing file -> safe default;
 * present-but-invalid -> throws (fail closed) for bad JSON, a non-https
 * destination, a userinfo-credentialed destination, and a missing pin.
 */

import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_EXPORT_SINK,
  EnforcementExportConfigError,
  readExportConfig,
} from "../../../src/castle-wall/export/index.js";

let fortress: string;

beforeEach(async () => {
  fortress = await mkdtemp(join(tmpdir(), "cortex-export-cfg-"));
});

afterEach(async () => {
  await rm(fortress, { recursive: true, force: true });
});

async function writeConfig(contents: string): Promise<void> {
  const dir = join(fortress, "policy", "egress");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "cortex-export.json"), contents);
}

describe("readExportConfig", () => {
  it("returns the safe default (file sink, no network) when the file is absent", async () => {
    const config = await readExportConfig(fortress);
    expect(config).toEqual({ sink: DEFAULT_EXPORT_SINK, enabled: false });
  });

  it("throws (fail closed) on invalid JSON rather than degrading to a lane", async () => {
    await writeConfig("{ not valid json");
    await expect(readExportConfig(fortress)).rejects.toThrow(EnforcementExportConfigError);
    await expect(readExportConfig(fortress)).rejects.toThrow(/not valid JSON/);
  });

  it("loads and validates a well-formed https http-sink config", async () => {
    await writeConfig(
      JSON.stringify({ sink: "http", enabled: true, destination_url: "https://collector.example/xsiam" }),
    );
    const config = await readExportConfig(fortress);
    expect(config).toEqual({
      sink: "http",
      enabled: true,
      destination_url: "https://collector.example/xsiam",
    });
  });

  it("rejects a non-https (non-loopback) destination", async () => {
    await writeConfig(
      JSON.stringify({ sink: "http", enabled: true, destination_url: "http://collector.example/x" }),
    );
    await expect(readExportConfig(fortress)).rejects.toThrow(/https/);
  });

  it("rejects a userinfo-credentialed destination (no secret may hide in the pinned URL)", async () => {
    await writeConfig(
      JSON.stringify({
        sink: "http",
        enabled: true,
        destination_url: "https://ingest-key:SECRET@collector.example/x",
      }),
    );
    await expect(readExportConfig(fortress)).rejects.toThrow(/must not embed credentials/);
  });

  it("rejects an http sink with no pinned destination_url", async () => {
    await writeConfig(JSON.stringify({ sink: "http", enabled: true }));
    await expect(readExportConfig(fortress)).rejects.toThrow(/destination_url is required/);
  });

  it("rejects an unknown key (closed schema)", async () => {
    await writeConfig(JSON.stringify({ sink: "file", bogus: 1 }));
    await expect(readExportConfig(fortress)).rejects.toThrow(EnforcementExportConfigError);
  });
});
