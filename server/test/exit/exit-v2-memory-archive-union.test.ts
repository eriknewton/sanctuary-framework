import { describe, expect, it } from "vitest";
import { parseExitV2SdwMemoryLogicalPayloadUnion } from "../../src/exit/v2-memory-archive.js";

function v2File(overrides: Record<string, unknown> = {}) {
  return {
    path: "MEMORY.md", source_class: "codex_index", bytes_base64url: "YQ",
    size_bytes: 1, sha256: "0".repeat(64), source_passage_id: "source-passage",
    provenance: null, ...overrides,
  };
}

function v2Payload(file: Record<string, unknown>) {
  return {
    format: "SANCTUARY_EXIT_V2_SDW_MEMORY_LOGICAL_ARCHIVE_V2",
    transcode_version: "SANCTUARY_MEMORY_TRANSCODE_V1", state: "complete",
    source_harness: "codex", destination_harness: "claude-code",
    source_owner_ref: "owner", source_archive_lineage_ref: "0".repeat(64),
    source_file_count: 1, source_set_sha256: "0".repeat(64),
    projection_file_count: 1, projection_set_sha256: "0".repeat(64),
    files: [file], known_signers: { version: 1, signers: [], signature: "x" },
  };
}

describe("C4 explicit memory-archive version union", () => {
  it("never treats missing V2 provenance as a V1 file", () => {
    const { provenance: _missing, ...withoutProvenance } = v2File();
    expect(() => parseExitV2SdwMemoryLogicalPayloadUnion(v2Payload(withoutProvenance)))
      .toThrow(/logical file v2 is missing a required field/);
  });

  it("never treats malformed V2 provenance as a V1 file", () => {
    expect(() => parseExitV2SdwMemoryLogicalPayloadUnion(v2Payload(v2File())))
      .toThrow(/payload v2 provenance is invalid/);
  });
});
