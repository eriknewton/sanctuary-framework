/**
 * Loaded into the job worker with --import by the wired-consumer test. Records
 * every globalThis.fetch call and every OllamaClient.prototype.generate call
 * in the worker, one line each, to a file named by the parent's pid. The
 * first line marks that the preload ran, so an empty record is a live result.
 */
import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OllamaClient } from "../../../src/intelligence/substrates/local.js";

// Must match spyFile in wired-consumer.test.ts.
const file = join(tmpdir(), `lr1b-worker-spy-${process.ppid}.log`);
appendFileSync(file, `loaded ${process.pid}\n`);
const realFetch = globalThis.fetch;
globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
  appendFileSync(file, "fetch\n");
  return realFetch(...args);
}) as typeof fetch;
const realGenerate = OllamaClient.prototype.generate;
OllamaClient.prototype.generate = function (this: OllamaClient, ...args: Parameters<typeof realGenerate>) {
  appendFileSync(file, "ollama_generate\n");
  return realGenerate.apply(this, args);
};
