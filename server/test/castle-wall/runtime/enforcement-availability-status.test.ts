import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

import {
  buildEnforcementUnavailableStatusFile,
  enforcementAvailabilityStatusPath,
  readEnforcementAvailabilityStatus,
  writeEnforcementAvailabilityStatusBestEffort,
} from "../../../src/castle-wall/runtime/enforcement-availability-status.js";

describe("enforcement availability status file", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  async function tempFortress(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-enforcement-status-"));
    tempDirs.push(dir);
    return dir;
  }

  it("refuses to write a status object its reader would reject", async () => {
    const fortress = await tempFortress();
    const ok = await writeEnforcementAvailabilityStatusBestEffort(
      fortress,
      buildEnforcementUnavailableStatusFile("not-a-date"),
    );

    expect(ok).toBe(false);
    await expect(readFile(enforcementAvailabilityStatusPath(fortress), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("treats a present-but-corrupt status file as a fresh non-green read failure", async () => {
    const fortress = await tempFortress();
    await writeFile(enforcementAvailabilityStatusPath(fortress), "{nope\n");

    const status = await readEnforcementAvailabilityStatus(fortress);

    expect(status).toMatchObject({
      state: "enforcement_unavailable",
      reason: "status_present_unreadable",
      source: "local_status_file",
      manifest_received: null,
      arm_lease_received: null,
      read_error: {
        kind: "invalid_json",
        path: enforcementAvailabilityStatusPath(fortress),
      },
    });
    expect(Date.parse(status?.updated_at ?? "invalid")).not.toBeNaN();
  });

  it("chowns the safe-mode status file to the resolved fortress owner before restoring 0600 mode", async () => {
    const calls: string[] = [];
    const status = buildEnforcementUnavailableStatusFile(
      "2026-07-30T00:00:00.000Z",
    );

    const ok = await writeEnforcementAvailabilityStatusBestEffort(
      "/fortress",
      status,
      {
        ownerUid: 501,
        ownerGid: -1,
        forceChown: true,
        writeFileFn: async (path) => {
          calls.push(`write:${String(path)}`);
        },
        chownFn: async (path, uid, gid) => {
          calls.push(`chown:${path}:${uid}:${gid}`);
        },
        chmodFn: async (path, mode) => {
          calls.push(`chmod:${path}:${mode.toString(8)}`);
        },
      },
    );

    expect(ok).toBe(true);
    expect(calls).toEqual([
      "write:/fortress/castle-wall-enforcement-status.json",
      "chown:/fortress/castle-wall-enforcement-status.json:501:-1",
      "chmod:/fortress/castle-wall-enforcement-status.json:600",
    ]);
  });
});
