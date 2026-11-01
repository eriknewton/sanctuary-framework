// Recall normalizes query terms and assembles a bounded canonical context.
import { expect, it } from "vitest";
import { HermesRecallBudget, recallTerms, recallPrefix, recallTimestamp, RECALL_MAX_QUERY_UNITS,
  RECALL_CONTEXT_MAX_UNITS, RECALL_PASSAGE_MAX_UNITS, RECALL_STOPWORDS } from "../../src/hermes-memory-bridge/recall.js";

it.each([
  ["when is the board meeting?", ["board", "meeting"]],
  [RECALL_STOPWORDS.join(" "), []],
  ["MEETING meeting café cafe\u0301", ["meeting", "café"]],
  ["a ab abc 12 123", ["abc", "123"]],
  ["one two three four five six seven", ["one", "two", "three", "four", "five", "six"]],
  ["𐐨".repeat(40), ["𐐨".repeat(32)]],
] as const)("extracts bounded terms from %s", (query, expected) => expect(recallTerms(query).terms).toEqual(expected));
it("backs off a surrogate at the query boundary", () => {
  const query = " ".repeat(RECALL_MAX_QUERY_UNITS - 1) + "𐐨board";
  expect(recallPrefix(query, RECALL_MAX_QUERY_UNITS)).toHaveLength(RECALL_MAX_QUERY_UNITS - 1);
  expect(recallTerms(query)).toEqual({ terms: [], truncated: true });
});
it("ranks distinct terms, occurrences, parsed instants and passage ids", () => {
  const budget = new HermesRecallBudget("board meeting", () => 0, new AbortController().signal);
  for (const [passage_id, text, created_at] of [
    ["single", "board board board", "2026-01-01T00:00:00.000Z"],
    ["old", "board meeting", "2025-01-01T00:00:00.000Z"],
    ["b", "board meeting", "2026-01-01T01:00:00+01:00"],
    ["a", "board meeting", "2026-01-01T00:00:00.000Z"],
    ["repeat", "board meeting board", "2024-01-01T00:00:00.000Z"],
  ]) budget.retain({ passage_id: passage_id!, text: text!, created_at: created_at! });
  expect(budget.result().passages.map(p => p.passage_id)).toEqual(["repeat", "a", "b"]);
  expect(budget.maximumRetained).toBe(3);
});
it.each(["x", "𐐨", "\u0001", '"'])("bounds assembly for %s", character => {
  const budget = new HermesRecallBudget("board", () => 0, new AbortController().signal);
  for (const passage_id of ["a", "b", "c"]) budget.retain({ passage_id,
    text: "board " + character.repeat(RECALL_PASSAGE_MAX_UNITS), created_at: "2026-01-01T01:00:00+01:00" });
  const result = budget.result();
  expect(result.context.length).toBeLessThanOrEqual(RECALL_CONTEXT_MAX_UNITS);
  expect(result.passages.every(p => p.created_at === "2026-01-01T00:00:00.000Z")).toBe(true);
  expect(result.context).not.toMatch(/[\uD800-\uDBFF]\n/u);
});
it("excludes nonfinite timestamps and extended ISO years", () => {
  expect(recallTimestamp("not a timestamp")).toBeNull();
  expect(recallTimestamp("+010000-01-01T00:00:00.000Z")).toBeNull();
});
