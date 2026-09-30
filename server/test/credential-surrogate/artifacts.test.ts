/**
 * Capability: the three artifacts root arming writes have one render function
 * and one parse function each, and the reader re-validates every element rather
 * than trusting the writer's judgment.
 *
 * Each file has a writer at one privilege level and a reader at another, so a
 * writer and reader that disagreed about the format would either drop a binding
 * silently or read back a destination the writer refused. These tests drive the
 * render-then-parse round trip and then each refusal class.
 *
 * Host-free: pure functions over strings. Nothing is written and no socket
 * opens.
 *
 * Defect id: SURROGATE-ARTIFACT-PARITY.
 */

import { describe, expect, it } from "vitest";

import {
  SURROGATE_BINDINGS_FILE_KIND,
  SURROGATE_DESTINATIONS_FILE_KIND,
  SURROGATE_PLACEHOLDER_FILE_KIND,
  SURROGATE_PLACEHOLDER_LINE_RE,
  SurrogateArtifactError,
  parseSurrogateBindingsFile,
  parseSurrogateDestinationsFile,
  parseSurrogatePlaceholderFile,
  readSurrogateArtifactGeneration,
  renderSurrogateBindingsFile,
  renderSurrogateDestinationsFile,
  renderSurrogatePlaceholderFile,
} from "../../src/credential-surrogate/artifacts.js";
import type { MintedSurrogateBinding } from "../../src/credential-surrogate/binding.js";
import { MAX_SURROGATE_BINDINGS_PER_AGENT } from "../../src/credential-surrogate/constants.js";
import { mintSurrogatePlaceholder } from "../../src/credential-surrogate/placeholder.js";

const GENERATION = 12;

function binding(ordinal: number, over: Partial<MintedSurrogateBinding> = {}): MintedSurrogateBinding {
  return {
    ordinal,
    placeholder: mintSurrogatePlaceholder(),
    secret: `secret-${ordinal}`,
    agent: "hermes",
    env: `SECRET_${ordinal}`,
    header: "Authorization",
    destinations: [{ host: `api${ordinal}.example.com`, port: 443 }],
    ...over,
  };
}

describe("surrogate artifacts: the bindings table", () => {
  it("round trips every field, in ordinal order", () => {
    const bindings = [binding(1), binding(0), binding(2)];
    const text = renderSurrogateBindingsFile(GENERATION, bindings);
    const parsed = parseSurrogateBindingsFile(text);
    expect(parsed.generationId).toBe(GENERATION);
    expect(parsed.bindings.map((b) => b.ordinal)).toEqual([0, 1, 2]);
    // Element-level parity, not container-level (AGENTS.md rule 11): every field
    // the writer emitted comes back, or a binding is being silently narrowed.
    expect(parsed.bindings).toEqual([...bindings].sort((a, b) => a.ordinal - b.ordinal));
  });

  it("reads the generation from the header alone, which is what release commit does", () => {
    const text = renderSurrogateBindingsFile(GENERATION, [binding(0)]);
    expect(readSurrogateArtifactGeneration(text, SURROGATE_BINDINGS_FILE_KIND)).toBe(GENERATION);
  });

  it("refuses a file written for another artifact, so a misplaced file is not parsed", () => {
    const destinations = renderSurrogateDestinationsFile(GENERATION, [binding(0)]);
    expect(() => parseSurrogateBindingsFile(destinations)).toThrow(SurrogateArtifactError);
    const bindings = renderSurrogateBindingsFile(GENERATION, [binding(0)]);
    expect(() => parseSurrogateDestinationsFile(bindings)).toThrow(SurrogateArtifactError);
  });

  it("refuses an empty file, a bad header, and a wrong version", () => {
    for (const bad of [
      "",
      "garbage",
      `${SURROGATE_BINDINGS_FILE_KIND} v2 generation=1`,
      `${SURROGATE_BINDINGS_FILE_KIND} generation=1`,
      `${SURROGATE_BINDINGS_FILE_KIND} v1 generation=x`,
    ]) {
      expect(() => parseSurrogateBindingsFile(bad), bad).toThrow(SurrogateArtifactError);
    }
  });

  it("refuses an unknown key, a missing key, and a bad element on a binding line", () => {
    const header = `${SURROGATE_BINDINGS_FILE_KIND} v1 generation=1`;
    const base = {
      ordinal: 0,
      placeholder: mintSurrogatePlaceholder(),
      secret: "s",
      agent: "hermes",
      env: "S",
      header: "Authorization",
      destinations: [{ host: "api.example.com", port: 443 }],
    };
    const cases: Record<string, unknown>[] = [
      { ...base, extra: 1 },
      { ...base, placeholder: "not-a-placeholder" },
      { ...base, header: "Host" },
      { ...base, header: "Connection" },
      { ...base, env: "HTTP_PROXY" },
      { ...base, destinations: [] },
      { ...base, destinations: [{ host: "api.example.com", port: 80 }] },
      { ...base, destinations: [{ host: "*.example.com", port: 443 }] },
      { ...base, destinations: [{ host: "10.0.0.1", port: 443 }] },
      { ...base, destinations: [{ host: "api.example.com" }] },
      { ...base, ordinal: -1 },
    ];
    for (const record of cases) {
      const text = `${header}\n${JSON.stringify(record)}\n`;
      expect(() => parseSurrogateBindingsFile(text), JSON.stringify(record).slice(0, 60)).toThrow(
        SurrogateArtifactError,
      );
    }
    // A missing key is refused too, one key at a time.
    for (const key of Object.keys(base)) {
      const partial = { ...base } as Record<string, unknown>;
      delete partial[key];
      expect(() => parseSurrogateBindingsFile(`${header}\n${JSON.stringify(partial)}\n`), key).toThrow(
        SurrogateArtifactError,
      );
    }
  });

  it("refuses a duplicate placeholder, secret, env name or ordinal across lines", () => {
    const a = binding(0);
    for (const clash of [
      { ...binding(1), placeholder: a.placeholder },
      { ...binding(1), secret: a.secret },
      { ...binding(1), env: a.env },
      { ...binding(1), ordinal: a.ordinal },
    ]) {
      // Rendered by hand, because the render path sorts by ordinal and does not
      // itself police cross-line uniqueness; the READER is the enforcement site
      // that a stale or hand-edited file has to get past.
      const text = `${SURROGATE_BINDINGS_FILE_KIND} v1 generation=${GENERATION}\n${JSON.stringify(
        a,
      )}\n${JSON.stringify(clash)}\n`;
      expect(() => parseSurrogateBindingsFile(text)).toThrow(SurrogateArtifactError);
    }
  });

  it("refuses more than MAX_SURROGATE_BINDINGS_PER_AGENT on render and on parse", () => {
    const over = Array.from({ length: MAX_SURROGATE_BINDINGS_PER_AGENT + 1 }, (_, i) => binding(i));
    expect(() => renderSurrogateBindingsFile(GENERATION, over)).toThrow(SurrogateArtifactError);
    const text = `${SURROGATE_BINDINGS_FILE_KIND} v1 generation=${GENERATION}\n${over
      .map((b) => JSON.stringify(b))
      .join("\n")}\n`;
    expect(() => parseSurrogateBindingsFile(text)).toThrow(
      expect.objectContaining({ refusal: "too_many_bindings" }),
    );
    // Exactly at the cap is allowed, so the bound is the stated one and not one below it.
    const atCap = over.slice(0, MAX_SURROGATE_BINDINGS_PER_AGENT);
    expect(parseSurrogateBindingsFile(renderSurrogateBindingsFile(GENERATION, atCap)).bindings).toHaveLength(
      MAX_SURROGATE_BINDINGS_PER_AGENT,
    );
  });

  it("accepts a table with no bindings, which is what a removal writes", () => {
    const text = renderSurrogateBindingsFile(GENERATION, []);
    expect(parseSurrogateBindingsFile(text)).toEqual({ generationId: GENERATION, bindings: [] });
  });
});

describe("surrogate artifacts: the agent-readable placeholder file", () => {
  it("carries only ENV_NAME and placeholder, never a secret name or a destination", () => {
    const b = binding(0, { secret: "openai-api-key", env: "OPENAI_API_KEY" });
    const text = renderSurrogatePlaceholderFile(GENERATION, [b]);
    expect(text).not.toContain(b.secret);
    expect(text).not.toContain(b.destinations[0]!.host);
    expect(text).not.toContain(b.header);
    expect(parseSurrogatePlaceholderFile(text)).toEqual({
      generationId: GENERATION,
      entries: [{ env: "OPENAI_API_KEY", placeholder: b.placeholder }],
    });
  });

  it("emits body lines the release wrapper's own grammar accepts", () => {
    const text = renderSurrogatePlaceholderFile(GENERATION, [binding(0), binding(1)]);
    const body = text.split("\n").slice(1).filter((l) => l.length > 0);
    expect(body).toHaveLength(2);
    // This regex is the one the wrapper carries as a literal, so a render that
    // stopped matching it would refuse the harness start with exit 78 long after
    // the operator had left.
    for (const line of body) expect(SURROGATE_PLACEHOLDER_LINE_RE.test(line)).toBe(true);
  });

  it("refuses a body line that is not ENV_NAME=placeholder", () => {
    const header = `${SURROGATE_PLACEHOLDER_FILE_KIND} v1 generation=1`;
    for (const bad of [
      "lower_case=sanctuary_surrogate_00000000000000000000000000000000",
      "OK=sanctuary_surrogate_deadbeef",
      "OK=some-other-value",
      "OK",
      " OK=sanctuary_surrogate_00000000000000000000000000000000",
    ]) {
      expect(() => parseSurrogatePlaceholderFile(`${header}\n${bad}\n`), bad).toThrow(
        SurrogateArtifactError,
      );
    }
    // A blank line in the MIDDLE is refused, not skipped: a parser that skipped
    // blanks would also skip a line an editor truncated to nothing. A trailing
    // newline is a different thing and is tolerated, because every renderer here
    // emits one.
    const good = "OK=sanctuary_surrogate_00000000000000000000000000000000";
    expect(() => parseSurrogatePlaceholderFile(`${header}\n\n${good}\n`)).toThrow(
      SurrogateArtifactError,
    );
    expect(parseSurrogatePlaceholderFile(`${header}\n${good}\n`).entries).toHaveLength(1);
  });
});

describe("surrogate artifacts: the gate-readable destination set", () => {
  it("is the deduplicated sorted union of every binding's destinations, and nothing else", () => {
    const shared = { host: "api.shared.example.com", port: 443 } as const;
    const a = binding(0, { destinations: [shared, { host: "b.example.com", port: 443 }] });
    const c = binding(1, { destinations: [shared] });
    const text = renderSurrogateDestinationsFile(GENERATION, [a, c]);
    // The gate learns which authorities a placeholder may be spent toward. It
    // does NOT learn the secret name, the env name, or which binding owns which
    // destination.
    expect(text).not.toContain(a.secret);
    expect(text).not.toContain(a.env);
    expect(text).not.toContain(a.placeholder);
    expect(parseSurrogateDestinationsFile(text)).toEqual({
      generationId: GENERATION,
      destinations: [
        { host: "api.shared.example.com", port: 443 },
        { host: "b.example.com", port: 443 },
      ],
    });
  });

  it("re-validates each destination on read rather than trusting root wrote it", () => {
    const header = `${SURROGATE_DESTINATIONS_FILE_KIND} v1 generation=1`;
    for (const bad of [
      "api.example.com:80",
      "*.example.com:443",
      "10.0.0.1:443",
      "api.example.com",
      "api.example.com:443:443",
      "api.example.com:443 ",
    ]) {
      expect(() => parseSurrogateDestinationsFile(`${header}\n${bad}\n`), bad).toThrow(
        SurrogateArtifactError,
      );
    }
  });
});
