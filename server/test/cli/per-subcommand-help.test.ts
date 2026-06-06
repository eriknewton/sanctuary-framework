import { describe, expect, it } from "vitest";
import { runCli, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

const cases: Array<{
  name: string;
  args: string[];
  summary: string;
  flag: string;
}> = [
  {
    name: "audit-chain verify",
    args: ["audit-chain", "verify", "--help"],
    summary: "sanctuary audit-chain verify.",
    flag: "--input",
  },
  {
    name: "anomaly subscribe",
    args: ["anomaly", "subscribe", "--help"],
    summary: "sanctuary anomaly subscribe.",
    flag: "--classifier",
  },
  {
    name: "exit export",
    args: ["exit", "export", "--help"],
    summary: "sanctuary exit export.",
    flag: "--out",
  },
  {
    name: "did-web issue",
    args: ["did-web", "issue", "--help"],
    summary: "sanctuary did-web issue.",
    flag: "--authority-host",
  },
  {
    name: "identity show",
    args: ["identity", "show", "--help"],
    summary: "sanctuary identity show.",
    flag: "--fortress",
  },
  {
    name: "agents list",
    args: ["agents", "list", "--help"],
    summary: "sanctuary agents list.",
    flag: "--json",
  },
  {
    name: "policy compile",
    args: ["policy", "compile", "--help"],
    summary: "sanctuary policy compile.",
    flag: "--help",
  },
  {
    name: "intelligence diagnose",
    args: ["intelligence", "diagnose", "--help"],
    summary: "sanctuary intelligence diagnose.",
    flag: "--fortress",
  },
];

describe("per-subcommand help routing (F-GA-3)", () => {
  it.each(cases)(
    "$name --help prints subcommand-specific help",
    async (testCase) => {
      const topLevel = await runCli("--help");
      const result = await runCli(...testCase.args);

      expect(result.code).toBe(0);
      expect(result.output.trim().length).toBeGreaterThan(0);
      expect(result.output).not.toBe(topLevel.output);
      expect(result.output).not.toContain("Sovereignty infrastructure for agents");
      expect(result.output).toContain(testCase.summary);
      expect(result.output).toContain(testCase.flag);
    },
    CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  );
});
