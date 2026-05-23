import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readHostTenantRegistry,
  registerHostTenant,
} from "../../../src/cli/agents/tenant-registry.js";

describe("cli/agents/tenant-registry", () => {
  let home: string;
  let root: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-tenant-registry-"));
    root = join(home, ".sanctuary");
    await mkdir(root, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("upserts tenant paths by absolute storage path", async () => {
    const storagePath = join(home, "fortress-a");

    await registerHostTenant(storagePath, {
      home,
      now: new Date("2026-05-22T00:00:00.000Z"),
    });
    await registerHostTenant(storagePath, {
      home,
      now: new Date("2026-05-22T00:01:00.000Z"),
    });

    const registry = await readHostTenantRegistry({ home });
    expect(registry.tenants).toHaveLength(1);
    expect(registry.tenants[0]).toMatchObject({
      name: "fortress-a",
      storage_path: storagePath,
      registered_at: "2026-05-22T00:00:00.000Z",
      updated_at: "2026-05-22T00:01:00.000Z",
    });
  });

  it("preserves all entries across concurrent registrations", async () => {
    const paths = Array.from({ length: 8 }, (_, i) => join(home, `fortress-${i}`));

    await Promise.all(paths.map((path) => registerHostTenant(path, { home })));

    const registry = await readHostTenantRegistry({ home });
    expect(registry.tenants.map((t) => t.storage_path).sort()).toEqual(paths.sort());
  });
});
