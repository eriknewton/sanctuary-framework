/**
 * G4 guard: the ASCII label and base64url token regexes have the same
 * character set, but they are intentionally different semantic domains.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ASCII_LABEL_RE_SOURCE,
  ASCII_LABEL_RE,
  BASE64URL_TOKEN_RE_SOURCE,
  BASE64URL_TOKEN_RE,
  isAsciiLabel,
  isBase64urlToken,
} from "../../src/core/token-grammar.js";

const SRC_ROOT = join(__dirname, "..", "..", "src");
// Trip-wire, not a regex parser: catches the common inline label regex shapes
// this slice replaced without flagging broader allowlists such as stdio argv.
const INLINE_ASCII_LABEL_RE_LITERAL =
  /\/\^?(?:\[(?:a-zA-Z0-9_-|A-Za-z0-9_-|A-Z0-9a-z_-|0-9A-Za-z_-|a-z_A-Z0-9-)\]|\\w)(?:\+|\{1,64\})\$?\//;

function readSrc(relativePath: string): string {
  return readFileSync(join(SRC_ROOT, relativePath), "utf8");
}

describe("ASCII token grammar semantics", () => {
  it("keeps shared-alphabet label and base64url token grammars separately named", () => {
    const grammarSource = readSrc("core/token-grammar.ts");

    expect(grammarSource).toMatch(/export const ASCII_LABEL_RE_SOURCE =/);
    expect(grammarSource).toMatch(/export const BASE64URL_TOKEN_RE_SOURCE =/);
    expect(ASCII_LABEL_RE_SOURCE).toBe(BASE64URL_TOKEN_RE_SOURCE);
    expect(ASCII_LABEL_RE.source).toBe(BASE64URL_TOKEN_RE.source);
    expect(isAsciiLabel("agent_01-name")).toBe(true);
    expect(isBase64urlToken("QWdlbnRfMDEtbmFtZQ")).toBe(true);
    expect(isAsciiLabel("agent.name")).toBe(false);
    expect(isBase64urlToken("QWdlbnQ=")).toBe(false);
  });

  it("uses the label grammar at backend agent/server-name validation sites", () => {
    const sources = [
      "proxy/client-manager.ts",
      "sovereignty-profile.ts",
      "dashboard/api.ts",
      "principal-policy/dashboard.ts",
      "principal-policy/dashboard-html.ts",
      "recognition/did-web.ts",
    ].map(readSrc);

    for (const source of sources) {
      expect(source).toMatch(/\b(?:ASCII_LABEL_RE|ASCII_LABEL_RE_SOURCE|isAsciiLabel)\b/);
      expect(source).not.toMatch(INLINE_ASCII_LABEL_RE_LITERAL);
    }

    expect(readSrc("principal-policy/dashboard-html.ts")).toContain(
      String.raw`JSON.stringify(ASCII_LABEL_RE_SOURCE).replace(/</g, "\\u003c")`,
    );
  });

  it("uses the base64url token grammar in the agent contract schema", () => {
    const schema = readSrc("agent-contract/schema.ts");

    expect(schema).toMatch(/\bisBase64urlToken\b/);
    expect(schema).not.toMatch(/const\s+BASE64URL\s*=\s*\/\^\[A-Za-z0-9_-/);
  });
});
