/**
 * `saveConfig` is the WRITE chokepoint for the config file, and it must not
 * write into the operator's own fortress while the suite is running.
 *
 * Why this file exists
 * --------------------
 * The first version of the fortress-hermeticity work guarded the RESOLUTION
 * path (`paths.ts`) and left `defaultConfig()`'s raw `join(homedir(),
 * ".sanctuary")` deliberately unguarded, on the stated rationale that
 * constructing a default is not "where reaching the real fortress actually
 * costs something".
 *
 * Adversarial review measured that claim and it was false. `defaultConfig()`'s
 * value flowed into `createSanctuaryServer`'s step 20 (`await
 * saveConfig(config)`), so five test files that boot the server REWROTE the
 * operator's real `~/.sanctuary/sanctuary.json` on every suite run. The
 * attribution was not inferred: an idle control (180 s, no vitest) left the
 * mtime frozen, and two consecutive full-suite runs each moved it.
 *
 * The seam was exactly where the two mitigations met: the guard sat on
 * `resolveStoragePath`, and this path never goes through it.
 *
 * These tests pin the closure at the chokepoint, so the class stays shut for
 * code that has not been written yet -- a future test that boots the server
 * without isolating `HOME` gets a loud `NonHermeticStoragePathError` naming
 * `createTempFortress()`, instead of quietly editing the operator's config.
 *
 * The probe filename is deliberately NOT `sanctuary.json`: if the guard ever
 * regresses, these tests must not themselves rewrite the operator's real
 * config to find that out. The one case that does name `sanctuary.json` only
 * ever asserts that the file was left alone.
 */

import { describe, it, expect, afterEach } from "vitest";
import { statSync } from "node:fs";
import { rm } from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";

import { saveConfig, defaultConfig } from "../../src/config.js";
import { NonHermeticStoragePathError, DEFAULT_STORAGE_DIR } from "../../src/paths.js";

/**
 * The operator's real fortress, read from the account record rather than
 * `$HOME`, so this file answers the same question `assertHermeticStoragePath`
 * answers and cannot be fooled by a suite that has moved `HOME`.
 */
const OPERATOR_FORTRESS = join(userInfo().homedir, DEFAULT_STORAGE_DIR);

/** The one path these tests ever aim at inside the operator's fortress. */
const PROBE_PATH = join(OPERATOR_FORTRESS, "sanctuary.hermeticity-probe.json");

/** mtime in ms, or `null` when the file does not exist on this host. */
function mtimeOf(path: string): number | null {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return null;
  }
}

describe("saveConfig hermeticity", () => {
  afterEach(async () => {
    // Belt and braces. With the guard in place nothing is ever written here,
    // so this removes nothing. It exists for the one state in which these
    // tests CAN pollute: a future regression, or someone running the
    // revert-RED mutation proof. A test file whose whole subject is "do not
    // leave residue in the operator's fortress" must not be able to leave
    // residue in the operator's fortress, even while failing.
    await rm(PROBE_PATH, { force: true }).catch(() => {});
  });

  it("refuses to write into the operator's own fortress under Vitest", async () => {
    const config = { ...defaultConfig(), storage_path: OPERATOR_FORTRESS };
    await expect(saveConfig(config, PROBE_PATH)).rejects.toBeInstanceOf(
      NonHermeticStoragePathError,
    );
  });

  it("refuses the exact shape createSanctuaryServer step 20 used to take", async () => {
    // No explicit configPath: the target is derived from `config.storage_path`,
    // which is what `defaultConfig()` hands back on an un-isolated host. This
    // is byte-for-byte the call that was rewriting the real config file.
    const config = { ...defaultConfig(), storage_path: OPERATOR_FORTRESS };
    await expect(saveConfig(config)).rejects.toBeInstanceOf(
      NonHermeticStoragePathError,
    );
  });

  it("leaves the operator's real sanctuary.json untouched when it refuses", async () => {
    // The direct observation the review asked for: not "the guard threw", but
    // "the file on disk did not move". A guard that threw AFTER the rename
    // would pass the two tests above and still pollute.
    const realConfig = join(OPERATOR_FORTRESS, "sanctuary.json");
    const before = mtimeOf(realConfig);

    const config = { ...defaultConfig(), storage_path: OPERATOR_FORTRESS };
    await expect(saveConfig(config)).rejects.toThrow();

    expect(mtimeOf(realConfig)).toBe(before);
  });

  it("still writes normally to an isolated fortress", async () => {
    // The guard must be bounded: it fires on the operator's fortress and
    // nowhere else. Without this, "no writes anywhere" would pass the tests
    // above while breaking every legitimate save.
    const { createTempFortress } = await import("../helpers/temp-fortress.js");
    const fortress = await createTempFortress("sanctuary-saveconfig");
    try {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(fortress.storagePath, { recursive: true, mode: 0o700 });
      const config = { ...defaultConfig(), storage_path: fortress.storagePath };
      await saveConfig(config);
      expect(mtimeOf(join(fortress.storagePath, "sanctuary.json"))).not.toBeNull();
    } finally {
      await fortress.cleanup();
    }
  });
});
