/**
 * Optional runtime adapter for a local OpenAI privacy-filter command.
 *
 * Sanctuary does not depend on privacy-filter being installed. When enabled,
 * this runner invokes a local command, expects JSON on stdout, and normalizes
 * the result through the existing placeholder vault.
 */

import { spawn } from "node:child_process";
import {
  applyOpenAIPrivacyFilterResult,
  applyPrivacyPlaceholders,
  type OpenAIPrivacyFilterResult,
  type PrivacyFilterResult,
  type PrivacyPlaceholderVault,
} from "./privacy-filter.js";

export interface PrivacyFilterRuntimeConfig {
  mode: "local" | "opf" | "off";
  fail_mode: "closed" | "fallback";
  command: string;
  timeout_ms: number;
}

export interface PrivacyFilterRuntimeResult<T = unknown> extends PrivacyFilterResult<T> {
  mode: PrivacyFilterRuntimeConfig["mode"];
  fallback_from?: "opf";
}

export class PrivacyFilterRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrivacyFilterRuntimeError";
  }
}

export async function applyConfiguredPrivacyFilter<T = unknown>(
  value: T,
  vault: PrivacyPlaceholderVault,
  scope: string,
  config: PrivacyFilterRuntimeConfig
): Promise<PrivacyFilterRuntimeResult<T>> {
  if (config.mode === "off") {
    return { value, findings: [], mode: "off" };
  }

  if (config.mode === "local") {
    const result = await applyPrivacyPlaceholders(value, vault, scope);
    return { ...result, mode: "local" };
  }

  try {
    const result = await applyOpenAIPrivacyFilter(value, vault, scope, config);
    return { ...result, mode: "opf" };
  } catch (err) {
    if (config.fail_mode === "fallback") {
      const result = await applyPrivacyPlaceholders(value, vault, scope);
      return { ...result, mode: "local", fallback_from: "opf" };
    }
    throw err;
  }
}

async function applyOpenAIPrivacyFilter<T>(
  value: T,
  vault: PrivacyPlaceholderVault,
  scope: string,
  config: PrivacyFilterRuntimeConfig
): Promise<PrivacyFilterResult<T>> {
  if (typeof value === "string") {
    const opf = await runOpenAIPrivacyFilter(value, config);
    const filtered = await applyOpenAIPrivacyFilterResult(opf, vault, scope);
    return filtered as PrivacyFilterResult<T>;
  }

  if (Array.isArray(value)) {
    const findings: PrivacyFilterResult["findings"] = [];
    const out: unknown[] = [];
    for (let index = 0; index < value.length; index++) {
      const filtered = await applyOpenAIPrivacyFilter(
        value[index],
        vault,
        scope,
        config
      );
      out.push(filtered.value);
      findings.push(...filtered.findings.map((f) => ({
        ...f,
        path: `$[${index}]${f.path === "$" ? "" : f.path.slice(1)}`,
      })));
    }
    return { value: out as T, findings };
  }

  if (value && typeof value === "object") {
    const findings: PrivacyFilterResult["findings"] = [];
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const filtered = await applyOpenAIPrivacyFilter(child, vault, scope, config);
      out[key] = filtered.value;
      findings.push(...filtered.findings.map((f) => ({
        ...f,
        path: `$.${key}${f.path === "$" ? "" : f.path.slice(1)}`,
      })));
    }
    return { value: out as T, findings };
  }

  return { value, findings: [] };
}

export async function runOpenAIPrivacyFilter(
  text: string,
  config: PrivacyFilterRuntimeConfig
): Promise<OpenAIPrivacyFilterResult> {
  const stdout = await runCommand(config.command, text, config.timeout_ms);
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new PrivacyFilterRuntimeError("OpenAI privacy-filter returned invalid JSON");
  }

  if (!isOpenAIPrivacyFilterResult(parsed)) {
    throw new PrivacyFilterRuntimeError(
      "OpenAI privacy-filter JSON did not match the expected span schema"
    );
  }
  return parsed;
}

function runCommand(
  command: string,
  input: string,
  timeoutMs: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [], {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new PrivacyFilterRuntimeError("OpenAI privacy-filter timed out"));
    }, timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new PrivacyFilterRuntimeError(`OpenAI privacy-filter failed to start: ${err.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new PrivacyFilterRuntimeError(
          `OpenAI privacy-filter exited with code ${code}: ${stderr.trim()}`
        ));
        return;
      }
      resolve(stdout);
    });

    child.stdin.end(input);
  });
}

function isOpenAIPrivacyFilterResult(value: unknown): value is OpenAIPrivacyFilterResult {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.text !== "string") return false;
  if (!Array.isArray(v.detected_spans)) return false;
  return v.detected_spans.every((span) => {
    if (!span || typeof span !== "object") return false;
    const s = span as Record<string, unknown>;
    return (
      typeof s.label === "string" &&
      typeof s.start === "number" &&
      typeof s.end === "number" &&
      typeof s.text === "string"
    );
  });
}
