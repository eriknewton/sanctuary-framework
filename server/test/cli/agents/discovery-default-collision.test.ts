/**
 * Regression test for full-sweep #44: default tenant name collision.
 *
 * A subdirectory named "default" at ~/.sanctuary/default/ must not create
 * a second tenant with the same name as the root tenant.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverTenants } from "../../../src/cli/agents/discovery.js";

describe("default tenant collision (#44)", () => {
  let tempDir: string;
  let sanctuaryRoot: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-test-"));
    sanctuaryRoot = join(tempDir, ".sanctuary");
    await mkdir(sanctuaryRoot, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("skips a subdirectory named 'default' so it does not collide with root tenant", async () => {
    // Set up root tenant with state (so it qualifies as a tenant).
    await mkdir(join(sanctuaryRoot, "state", "_identities"), {
      recursive: true,
    });
    await writeFile(
      join(sanctuaryRoot, "cocoon-profile.json"),
      JSON.stringify({ version: 1 })
    );

    // Create a subdirectory named "default" that also looks like a tenant.
    const collisionDir = join(sanctuaryRoot, "default");
    await mkdir(join(collisionDir, "state", "_identities"), {
      recursive: true,
    });
    await writeFile(
      join(collisionDir, "cocoon-profile.json"),
      JSON.stringify({ version: 1 })
    );

    const tenants = await discoverTenants({
      home: tempDir,
      root: sanctuaryRoot,
    });

    // Only one tenant named "default" should appear (the root).
    const defaultTenants = tenants.filter((t) => t.name === "default");
    expect(defaultTenants).toHaveLength(1);
    expect(defaultTenants[0]!.storage_path).toBe(sanctuaryRoot);
  });

  it("still discovers other subdirectory tenants", async () => {
    // Root tenant
    await mkdir(join(sanctuaryRoot, "state", "_identities"), {
      recursive: true,
    });
    await writeFile(
      join(sanctuaryRoot, "cocoon-profile.json"),
      JSON.stringify({ version: 1 })
    );

    // A legitimate sub-tenant named "work"
    const workDir = join(sanctuaryRoot, "work");
    await mkdir(join(workDir, "state", "_identities"), { recursive: true });
    await writeFile(
      join(workDir, "cocoon-profile.json"),
      JSON.stringify({ version: 1 })
    );

    const tenants = await discoverTenants({
      home: tempDir,
      root: sanctuaryRoot,
    });

    expect(tenants.some((t) => t.name === "default")).toBe(true);
    expect(tenants.some((t) => t.name === "work")).toBe(true);
  });
});
