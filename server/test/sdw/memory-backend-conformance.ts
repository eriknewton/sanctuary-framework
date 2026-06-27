import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemorySearchResult,
} from "../../src/sdw/adapters/memory-backend.js";

export interface MemoryBackendConformanceSubject {
  readonly adapter: MemoryBackendAdapter;
  /**
   * Optional concrete-backend hook. Generic conformance checks retrievability
   * through the adapter; SDW also wires this to the real storage bytes so the
   * custody path proves ciphertext-only storage for secret probes.
   */
  readonly readStoredBytes?: () => Promise<readonly Uint8Array[]>;
  readonly cleanup?: () => Promise<void>;
}

export type MemoryBackendConformanceFactory = () =>
  | MemoryBackendAdapter
  | MemoryBackendConformanceSubject
  | Promise<MemoryBackendAdapter | MemoryBackendConformanceSubject>;

export interface MemoryBackendConformanceOptions {
  readonly suiteName?: string;
  readonly expectedRoundTripMinChunkCount?: number;
}

/**
 * Reusable executable contract for MemoryBackendAdapter implementations.
 *
 * Completeness note: the current interface has insert/get/search/delete/list
 * and count operations. It has no export operation, so export conformance is
 * intentionally outside this kit until the interface grows that method.
 */
export function conformanceKitForMemoryBackendAdapter(
  makeImpl: MemoryBackendConformanceFactory,
  options: MemoryBackendConformanceOptions = {},
): void {
  describe(options.suiteName ?? "MemoryBackendAdapter conformance", () => {
    it("roundtrips passage text, decorators, hashes, and chunk metadata", async () => {
      await withSubject(makeImpl, async ({ adapter }) => {
        const text = [
          "alpha sovereign memory contract line",
          "beta chunk boundary contract line",
          "gamma no corruption contract line",
        ].join("\n");

        const inserted = await adapter.insertPassage(
          {
            passage_id: "roundtrip-1",
            text,
            tags: ["contract", "roundtrip"],
            metadata: [{ key: "source", value: "conformance" }],
            created_at: "2026-06-22T00:00:00.000Z",
          },
          "user_content",
        );

        expect(inserted.passage_id).toBe("roundtrip-1");
        expect(inserted.text).toBe(text);
        expect(inserted.tags).toEqual(["contract", "roundtrip"]);
        expect(inserted.metadata).toEqual([{ key: "source", value: "conformance" }]);
        expect(inserted.chunk_count).toBeGreaterThanOrEqual(
          options.expectedRoundTripMinChunkCount ?? 1,
        );
        expect(inserted.content_hash).toMatch(/^[A-Za-z0-9_-]+$/);

        const fetched = await adapter.getPassage("roundtrip-1");
        expect(fetched).toEqual(inserted);

        const searched = await adapter.searchPassages({ text: "chunk boundary" });
        expect(searched.map((result) => result.passage)).toContainEqual(inserted);
      });
    });

    it("finds inserted passages by relevant query and excludes absent content", async () => {
      await withSubject(makeImpl, async ({ adapter }) => {
        await adapter.insertPassage(
          {
            passage_id: "search-hit",
            text: "Needle phrase: quartz-indexed operator memory.",
            tags: ["searchable"],
          },
          "user_content",
        );
        await adapter.insertPassage(
          {
            passage_id: "search-miss",
            text: "Unrelated local note with no target term.",
            tags: ["searchable"],
          },
          "user_content",
        );

        const hits = await adapter.searchPassages({ text: "quartz-indexed" });
        expect(hits.map((result) => result.passage.passage_id)).toEqual(["search-hit"]);

        const absent = await adapter.searchPassages({ text: "never-inserted-phrase" });
        expect(absent).toHaveLength(0);
      });
    });

    it("makes delete final across get, search, list, and count", async () => {
      await withSubject(makeImpl, async ({ adapter }) => {
        await adapter.insertPassage(
          {
            passage_id: "delete-target",
            text: "Delete finality sentinel: ember-custody-final.",
            tags: ["delete"],
          },
          "user_content",
        );
        expect(await adapter.countPassages()).toBe(1);

        await expect(adapter.deletePassage("delete-target")).resolves.toBe(true);
        await expect(adapter.deletePassage("delete-target")).resolves.toBe(false);
        await expect(adapter.getPassage("delete-target")).resolves.toBeNull();
        await expect(adapter.searchPassages({ text: "ember-custody-final" })).resolves.toHaveLength(0);
        await expect(adapter.listPassages()).resolves.toHaveLength(0);
        await expect(adapter.countPassages()).resolves.toBe(0);
      });
    });

    it("fails closed for raw and encoded secret probes without retrievable leakage", async () => {
      await withSubject(makeImpl, async (subject) => {
        const beforeForbiddenTaintCount = await subject.adapter.countPassages();
        await expect(
          subject.adapter.insertPassage(
            {
              passage_id: "secret-taint",
              text: "benign text carried with forbidden secret taint",
            },
            "secret" as never,
          ),
        ).rejects.toBeTruthy();
        await expect(subject.adapter.getPassage("secret-taint")).resolves.toBeNull();
        await expect(subject.adapter.countPassages()).resolves.toBe(beforeForbiddenTaintCount);

        const fixtures = secretFixtures();

        for (const fixture of fixtures) {
          const beforeCount = await subject.adapter.countPassages();
          let insertFailed = false;
          try {
            const inserted = await subject.adapter.insertPassage(
              {
                passage_id: fixture.passageId,
                text: fixture.text,
                tags: ["secret-probe"],
              },
              "user_content",
            );
            expectTextSetDoesNotExpose([inserted.text], fixture.forbiddenNeedles);
          } catch {
            insertFailed = true;
          }

          const fetched = await subject.adapter.getPassage(fixture.passageId);
          const listed = await subject.adapter.listPassages();
          const searchResults = await subject.adapter.searchPassages({ text: fixture.searchNeedle });
          const visibleTexts = collectVisibleTexts(fetched, listed, searchResults);
          expectTextSetDoesNotExpose(visibleTexts, fixture.forbiddenNeedles);

          if (insertFailed) {
            expect(fetched).toBeNull();
            expect(await subject.adapter.countPassages()).toBe(beforeCount);
          }
        }

        const storedBytes = await subject.readStoredBytes?.();
        if (storedBytes !== undefined) {
          const allForbiddenNeedles = fixtures.flatMap((fixture) => fixture.forbiddenNeedles);
          for (const raw of storedBytes) {
            expectTextSetDoesNotExpose([Buffer.from(raw).toString("utf8")], allForbiddenNeedles);
          }
        }
      });
    });

    it("keeps list and count accurate across inserts, pagination, and deletes", async () => {
      await withSubject(makeImpl, async ({ adapter }) => {
        for (const passageId of ["gamma", "alpha", "beta"]) {
          await adapter.insertPassage(
            { passage_id: passageId, text: `list integrity passage ${passageId}` },
            "agent_derived_clean",
          );
        }

        await expect(adapter.countPassages()).resolves.toBe(3);
        await expect(expectPassageIds(adapter.listPassages())).resolves.toEqual([
          "alpha",
          "beta",
          "gamma",
        ]);
        await expect(expectPassageIds(adapter.listPassages({ after: "alpha", limit: 1 }))).resolves.toEqual([
          "beta",
        ]);

        await expect(adapter.deletePassage("beta")).resolves.toBe(true);
        await expect(adapter.countPassages()).resolves.toBe(2);
        await expect(expectPassageIds(adapter.listPassages())).resolves.toEqual(["alpha", "gamma"]);
        await expect(expectPassageIds(adapter.listPassages({ after: "alpha", limit: 1 }))).resolves.toEqual([
          "gamma",
        ]);
      });
    });
  });
}

async function withSubject<T>(
  makeImpl: MemoryBackendConformanceFactory,
  fn: (subject: MemoryBackendConformanceSubject) => Promise<T>,
): Promise<T> {
  const subject = normalizeSubject(await makeImpl());
  try {
    return await fn(subject);
  } finally {
    await subject.cleanup?.();
  }
}

function normalizeSubject(
  value: MemoryBackendAdapter | MemoryBackendConformanceSubject,
): MemoryBackendConformanceSubject {
  if (typeof (value as { readonly insertPassage?: unknown }).insertPassage === "function") {
    return { adapter: value as MemoryBackendAdapter };
  }
  return value as MemoryBackendConformanceSubject;
}

function expectPassageIds(passages: Promise<readonly MemoryPassage[]>): Promise<readonly string[]> {
  return passages.then((items) => items.map((passage) => passage.passage_id));
}

function collectVisibleTexts(
  fetched: MemoryPassage | null,
  listed: readonly MemoryPassage[],
  searchResults: readonly MemorySearchResult[],
): string[] {
  return [
    ...(fetched === null ? [] : [fetched.text]),
    ...listed.map((passage) => passage.text),
    ...searchResults.map((result) => result.passage.text),
  ];
}

function expectTextSetDoesNotExpose(texts: readonly string[], forbiddenNeedles: readonly string[]): void {
  const visible = texts.join("\n");
  for (const needle of forbiddenNeedles) {
    expect(visible).not.toContain(needle);
  }
}

function secretFixtures(): readonly {
  readonly passageId: string;
  readonly text: string;
  readonly searchNeedle: string;
  readonly forbiddenNeedles: readonly string[];
}[] {
  const pem = "-----BEGIN ED25519 PRIVATE KEY-----\nredacted\n-----END ED25519 PRIVATE KEY-----";
  const encodedDer = encodedEd25519Pkcs8Fixture();
  return [
    secretFixture("secret-raw", `operator memory ${pem}`, "PRIVATE KEY", [pem]),
    secretFixture("secret-base64", `operator memory ${encodedDer.base64}`, "MC4CAQ", [
      encodedDer.base64,
    ]),
    secretFixture("secret-hex", `operator memory ${encodedDer.hex}`, "302e020", [encodedDer.hex]),
  ];
}

function secretFixture(
  passageId: string,
  text: string,
  searchNeedle: string,
  extraForbiddenNeedles: readonly string[],
): {
  readonly passageId: string;
  readonly text: string;
  readonly searchNeedle: string;
  readonly forbiddenNeedles: readonly string[];
} {
  return {
    passageId,
    text,
    searchNeedle,
    forbiddenNeedles: [
      text,
      Buffer.from(text, "utf8").toString("base64"),
      Buffer.from(text, "utf8").toString("base64url"),
      Buffer.from(text, "utf8").toString("hex"),
      ...extraForbiddenNeedles,
    ],
  };
}

function encodedEd25519Pkcs8Fixture(): { readonly hex: string; readonly base64: string } {
  const hex = "302e020100300506032b657004220420" + "11".repeat(32);
  return {
    hex,
    base64: Buffer.from(hex, "hex").toString("base64"),
  };
}
