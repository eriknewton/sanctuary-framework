/**
 * Tests for the exclusive-routing MODE MARKER (Unified Protect Slice 5 S5-6):
 * the durable fortress-persisted declaration the signing daemon consults at
 * EVERY compose. The fail-closed contract under test: absent = coarse
 * (null), present + valid = parsed marker, present + malformed = THROWS
 * (never "guess a mode"), and the renderer round-trip validates.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ExclusiveRoutingMarkerError,
  exclusiveRoutingMarkerPath,
  loadExclusiveRoutingMarker,
  parseExclusiveRoutingMarker,
  renderExclusiveRoutingMarker,
} from "../../../src/castle-wall/allowlist/routing-marker.js";

const MARKER = {
  agent_uid: 502,
  gate_uid: 503,
  agent_id: "hermes",
  agent_template: "hermes",
};

describe("castle-wall/allowlist/routing-marker", () => {
  let fortress: string;

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "sanctuary-routing-marker-test-"));
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  it("render -> parse round-trips the canonical document", () => {
    const text = renderExclusiveRoutingMarker(MARKER);
    const parsed = parseExclusiveRoutingMarker(text, "(test)");
    expect(parsed).toEqual({ version: 1, mode: "exclusive", ...MARKER });
  });

  it("marker ABSENT loads as null (coarse mode, today's behavior byte-unchanged)", async () => {
    await expect(loadExclusiveRoutingMarker(fortress)).resolves.toBeNull();
  });

  it("marker PRESENT + valid loads the parsed marker", async () => {
    const path = exclusiveRoutingMarkerPath(fortress);
    await mkdir(join(fortress, "policy", "egress"), { recursive: true });
    await writeFile(path, renderExclusiveRoutingMarker(MARKER));
    await expect(loadExclusiveRoutingMarker(fortress)).resolves.toEqual({
      version: 1,
      mode: "exclusive",
      ...MARKER,
    });
  });

  it("marker PRESENT but malformed THROWS (the daemon must refuse to compose, never guess a mode)", async () => {
    const path = exclusiveRoutingMarkerPath(fortress);
    await mkdir(join(fortress, "policy", "egress"), { recursive: true });
    await writeFile(path, "{broken");
    await expect(loadExclusiveRoutingMarker(fortress)).rejects.toThrow(ExclusiveRoutingMarkerError);
  });

  it("strict parse refuses every malformed shape (fail-closed)", () => {
    const valid = { version: 1, mode: "exclusive", ...MARKER };
    const cases: Array<Record<string, unknown>> = [
      { ...valid, version: 2 },
      { ...valid, mode: "coarse" },
      { ...valid, agent_uid: 0 },
      { ...valid, gate_uid: -1 },
      { ...valid, gate_uid: valid.agent_uid },
      { ...valid, agent_id: "bad id!" },
      { ...valid, agent_template: "" },
    ];
    for (const c of cases) {
      expect(() => parseExclusiveRoutingMarker(JSON.stringify(c), "(test)")).toThrow(
        ExclusiveRoutingMarkerError,
      );
    }
    expect(() => parseExclusiveRoutingMarker("[1]", "(test)")).toThrow(/not a JSON object/);
  });

  it("the renderer itself refuses to render an invalid marker (colliding uids)", () => {
    expect(() =>
      renderExclusiveRoutingMarker({ ...MARKER, gate_uid: MARKER.agent_uid }),
    ).toThrow(ExclusiveRoutingMarkerError);
  });
});
