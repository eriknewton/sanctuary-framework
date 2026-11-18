/**
 * Config for the child run that test/helpers/private-tmpdir-hook-failure.test.ts spawns. It is the
 * suite's own config with the include narrowed to the one fixture file and the recorder appended to
 * the setup files; nothing else differs, so the child runs hooks in the same order as the suite.
 */
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import base from "../../../../vitest.config.js";

const beside = (name: string) => fileURLToPath(new URL(name, import.meta.url));
const baseSetupFiles = base.test?.setupFiles;
if (!Array.isArray(baseSetupFiles)) throw new Error("server/vitest.config.ts no longer lists its setup files");

export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: [beside("./hook-failure.fixture.ts")],
    // Last in the list, so the recorder's hook registers after the suite's own setup files and still
    // before any hook the fixture file registers.
    setupFiles: [...baseSetupFiles, beside("./recorder.ts")],
    // One thread worker confines fixture execution to the child process that spawnSync reaps.
    pool: "threads",
    maxWorkers: 1,
  },
});
