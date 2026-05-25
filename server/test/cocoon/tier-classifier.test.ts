/**
 * Tier Classifier Tests
 *
 * Verifies the heuristic tool classification system that assigns
 * approval tiers to upstream tools based on name patterns.
 */

import { describe, it, expect } from "vitest";
import { classifyTool, classifyServerTools, tierDescription } from "../../src/wrap/tier-classifier.js";

describe("Tier Classifier", () => {
  // ── Tier 1: Destructive / sensitive operations ───────────────────

  describe("Tier 1 classification (requires approval)", () => {
    const tier1Tools = [
      "write_file",
      "delete_resource",
      "remove_entry",
      "exec_command",
      "execute_query",
      "run_script",
      "send_message",
      "post_data",
      "put_object",
      "create_user",
      "update_record",
      "upload_file",
      "deploy_service",
      "install_package",
      "drop_table",
      "modify_config",
      "push_changes",
      "publish_event",
      "kill_process",
      "shutdown_server",
      "grant_permission",
      "revoke_access",
    ];

    for (const tool of tier1Tools) {
      it(`classifies "${tool}" as Tier 1`, () => {
        expect(classifyTool(tool)).toBe(1);
      });
    }

    it("handles camelCase tool names", () => {
      expect(classifyTool("writeFile")).toBe(1);
      expect(classifyTool("deleteResource")).toBe(1);
      expect(classifyTool("executeCommand")).toBe(1);
    });

    it("handles dot-separated names", () => {
      expect(classifyTool("file.write")).toBe(1);
      expect(classifyTool("db.delete")).toBe(1);
    });

    it("handles slash-separated names", () => {
      expect(classifyTool("api/post")).toBe(1);
    });
  });

  // ── Tier 3: Read-only / safe operations ─────────────────────────

  describe("Tier 3 classification (auto-allowed)", () => {
    const tier3Tools = [
      "read_file",
      "get_status",
      "list_files",
      "search_index",
      "query_database",
      "find_records",
      "fetch_data",
      "retrieve_document",
      "lookup_user",
      "describe_table",
      "show_config",
      "info",
      "count_entries",
      "check_health",
      "exists_key",
      "peek_queue",
      "inspect_element",
      "view_log",
      "help",
      "version",
      "ping",
      "echo",
    ];

    for (const tool of tier3Tools) {
      it(`classifies "${tool}" as Tier 3`, () => {
        expect(classifyTool(tool)).toBe(3);
      });
    }

    it("handles camelCase read operations", () => {
      expect(classifyTool("readFile")).toBe(3);
      expect(classifyTool("getStatus")).toBe(3);
      expect(classifyTool("listItems")).toBe(3);
    });
  });

  // ── Tier 2: Unclassified / ambiguous ────────────────────────────

  describe("Tier 2 classification (anomaly-monitored default)", () => {
    const tier2Tools = [
      "process_data",
      "transform_record",
      "compute_score",
      "analyze_text",
      "parse_document",
      "validate_input",
      "compress_file",
      "encode_data",
    ];

    for (const tool of tier2Tools) {
      it(`classifies "${tool}" as Tier 2`, () => {
        expect(classifyTool(tool)).toBe(2);
      });
    }
  });

  // ── Word boundary matching ──────────────────────────────────────

  describe("word boundary matching", () => {
    it("does not match substrings (e.g., 'spreadsheet' should not match 'read')", () => {
      expect(classifyTool("spreadsheet")).toBe(2);
    });

    it("does not match substrings (e.g., 'posting' should not match 'post')", () => {
      // 'posting' as a standalone word doesn't match 'post' exactly
      expect(classifyTool("posting")).toBe(2);
    });

    it("does not match 'execute' in 'unexecuted'", () => {
      expect(classifyTool("unexecuted")).toBe(2);
    });
  });

  // ── classifyServerTools ─────────────────────────────────────────

  describe("classifyServerTools", () => {
    it("returns overrides only for non-Tier-2 tools", () => {
      const tools = ["read_file", "write_file", "process_data"];
      const overrides = classifyServerTools(tools);

      expect(overrides["read_file"]).toEqual({ tier: 3 });
      expect(overrides["write_file"]).toEqual({ tier: 1 });
      expect(overrides["process_data"]).toBeUndefined(); // Tier 2 is default
    });

    it("returns empty object when all tools are Tier 2", () => {
      const tools = ["process_data", "transform_record"];
      const overrides = classifyServerTools(tools);
      expect(Object.keys(overrides)).toHaveLength(0);
    });
  });

  // ── tierDescription ─────────────────────────────────────────────

  describe("tierDescription", () => {
    it("returns human-readable descriptions", () => {
      expect(tierDescription(1)).toBe("Requires your approval");
      expect(tierDescription(2)).toBe("Auto-monitored");
      expect(tierDescription(3)).toBe("Auto-allowed");
    });
  });
});
