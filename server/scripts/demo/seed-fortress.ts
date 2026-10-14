#!/usr/bin/env tsx
import { rm } from "node:fs/promises";
import { basename, resolve } from "node:path";

import {
  DEMO_SEED_DEFAULT_PORT,
  seedDemoFortress,
} from "./seed-fortress-lib.js";

function usage(): string {
  return [
    "Usage:",
    "  SANCTUARY_PASSPHRASE=... npx tsx scripts/demo/seed-fortress.ts [--port 3517] [--no-open]",
    "  npx tsx scripts/demo/seed-fortress.ts --teardown /tmp/sanctuary-demo-fortress-...",
  ].join("\n");
}

function argValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

async function teardown(target: string): Promise<void> {
  const resolved = resolve(target);
  if (!basename(resolved).startsWith("sanctuary-demo-fortress-")) {
    throw new Error("refusing to teardown a path not created by the demo seeder");
  }
  await rm(resolved, { recursive: true, force: true });
  console.log(`Removed demo fortress home: ${resolved}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return;
  }
  const teardownTarget = argValue(args, "--teardown");
  if (teardownTarget) {
    await teardown(teardownTarget);
    return;
  }

  const portRaw = argValue(args, "--port");
  const port =
    portRaw === undefined ? DEMO_SEED_DEFAULT_PORT : Number.parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port <= 0 || port === 3501) {
    throw new Error("demo port must be a positive integer and must not be 3501");
  }
  const passphrase = process.env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    throw new Error("SANCTUARY_PASSPHRASE is required; it is never read from keychain.");
  }

  const seeded = await seedDemoFortress({
    passphrase,
    port,
    startDashboard: true,
    removeOnStop: false,
  });

  console.log(`Dashboard URL: ${seeded.dashboardUrl}`);
  console.log(`API base URL: ${seeded.apiBaseUrl}`);
  console.log(`Auth token: ${seeded.authToken}`);
  console.log(`Demo HOME: ${seeded.home}`);
  console.log(`Storage path: ${seeded.storagePath}`);
  console.log(
    `Teardown: npx tsx scripts/demo/seed-fortress.ts --teardown ${seeded.home}`,
  );
  const egress = seeded.seededItems.find((item) => item.item === "blocked egress event");
  if (egress?.status === "not_available") {
    console.log(`Blocked egress: not produced (${egress.note})`);
  }

  const stop = async () => {
    await seeded.stop();
  };
  process.once("SIGINT", () => {
    void stop().finally(() => process.exit(0));
  });
  process.once("SIGTERM", () => {
    void stop().finally(() => process.exit(0));
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  console.error(usage());
  process.exitCode = 1;
});
