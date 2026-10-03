/** Factory failure and shutdown preserve persistence and custody cleanup. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import * as custody from "../../src/core/master-custody.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { SovereigntyProfileStore } from "../../src/sovereignty-profile.js";
import { ResponseScreen } from "../../src/proxy/response-screen.js";
import { ResponseController, ResponseSession } from "../../src/proxy/response-runtime.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

afterEach(() => vi.restoreAllMocks());
describe("response cleanup composition", () => {
  it.each(["fenced", "rejecting"])("startup scrubs its key after %s scanner cleanup", async mode => {
    const home = await createTempHome("response-startup-cleanup");
    const storage = new MemoryStorage();
    const seed = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
    try {
      const profile = new SovereigntyProfileStore(storage, seed.masterKey); await profile.load();
      await profile.update({ upstream_servers: [{ name: "fixture", enabled: true, default_tier: 3,
        transport: { type: "stdio", command: process.execPath, args: [] } }] });
    } finally { await seed.cleanup(); }
    const establish = custody.establishMaster;
    let master: Uint8Array | undefined;
    const release = vi.fn(async () => {});
    vi.spyOn(custody, "establishMaster").mockImplementation(async options => {
      const result = await establish(options); master = result.masterKey;
      return { ...result, masterWriteBarrier: { ...result.masterWriteBarrier, release } } as typeof result;
    });
    vi.spyOn(ResponseScreen.prototype, "initialize").mockImplementation(async function (this: ResponseScreen) {
      if (mode === "fenced") {
        // Local controller keeps simulated unproven workers out of other tests' process quota.
        const session = new ResponseSession(new ResponseController());
        Object.defineProperty(this, "session", { value: session });
        const lease = session.reserve(); lease.fence(); lease.finish();
      }
      throw new Error("fixture startup failure");
    });
    if (mode === "rejecting") vi.spyOn(ResponseScreen.prototype, "close").mockRejectedValue(new Error("fixture cleanup failure"));
    try {
      const boot = createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
      // An assertion timeout witnesses a hung drain without leaving a timer or OS worker behind.
      let failure: unknown;
      void boot.catch(error => { failure = error; });
      await vi.waitFor(() => expect(failure).toBeInstanceOf(Error));
      await expect(boot).rejects.toThrow("fixture startup failure");
      expect(release).toHaveBeenCalledOnce();
      expect(master).toBeDefined(); expect(master!.every(byte => byte === 0)).toBe(true);
    } finally { await home.cleanup(); }
  });
});
