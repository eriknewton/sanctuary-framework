#!/usr/bin/env tsx
import { readFile, realpath, rm } from "node:fs/promises";
import { basename, join, resolve, sep } from "node:path";

import {
  DEMO_PID_FILE_BASENAME,
  DEMO_SEED_DEFAULT_PORT,
  DEMO_TEMP_PREFIX,
  createDemoRoot,
  demoTempParent,
  parseDemoPort,
  seedDemoFortress,
  type SeedDemoFortressResult,
} from "./seed-fortress-lib.js";

// POSIX shells report interruption as 128 plus the signal number (SIGINT = 2, SIGTERM = 15).
const SIGINT_EXIT_CODE = 128 + 2;
const SIGTERM_EXIT_CODE = 128 + 15;

function usage(): string {
  return [
    "Usage:",
    `  SANCTUARY_PASSPHRASE=... npx tsx scripts/demo/seed-fortress.ts [--port ${DEMO_SEED_DEFAULT_PORT}] [--keep]`,
    `  npx tsx scripts/demo/seed-fortress.ts --teardown /tmp/${DEMO_TEMP_PREFIX}...`,
  ].join("\n");
}

function argValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

async function teardown(target: string): Promise<void> {
  const resolved = await realpath(resolve(target));
  const tmpRoot = await realpath(demoTempParent());
  if (
    !basename(resolved).startsWith(DEMO_TEMP_PREFIX) ||
    !resolved.startsWith(`${tmpRoot}${sep}`)
  ) {
    throw new Error("refusing to teardown a path not created by the demo seeder");
  }
  // Must match the DEMO_PID_FILE_BASENAME writer in seed-fortress-lib.ts.
  const pidText = await readFile(join(resolved, DEMO_PID_FILE_BASENAME), "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (pidText !== undefined) {
    const pid = Number(pidText.trim());
    if (!/^[1-9][0-9]*$/.test(pidText.trim()) || !Number.isSafeInteger(pid)) {
      throw new Error(`refusing to teardown demo root with invalid pid: ${resolved}`);
    }
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch (error) {
      // Only ESRCH proves absence; permission errors and reused pids safely refuse deletion.
      if ((error as NodeJS.ErrnoException).code === "ESRCH") alive = false;
    }
    if (alive) throw new Error(`refusing to teardown live demo pid ${pid}: ${resolved}`);
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

  const port = parseDemoPort(argValue(args, "--port"));
  const passphrase = process.env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    throw new Error("SANCTUARY_PASSPHRASE is required; it is never read from keychain.");
  }

  const keep = args.includes("--keep");
  const controller = new AbortController();
  let phase: "seeding" | "ready" | "stopping" = "seeding";
  let interruption: "SIGINT" | "SIGTERM" | undefined;
  let seeded: SeedDemoFortressResult | undefined;
  let requestStop!: () => void;
  const stopRequested = new Promise<void>((resolveStop) => { requestStop = resolveStop; });
  const onSignal = (signal: "SIGINT" | "SIGTERM") => {
    if (phase === "stopping") return;
    if (phase === "seeding") {
      interruption = signal;
      // Let in-flight writes finish before the library releases resources and the CLI removes the root.
      controller.abort();
    }
    phase = "stopping";
    requestStop();
  };
  const onSigint = () => onSignal("SIGINT");
  const onSigterm = () => onSignal("SIGTERM");
  const onNormalStop = () => { phase = "stopping"; requestStop(); };

  // Synchronous creation and handler installation leave no event-loop gap before root ownership is armed.
  const home = createDemoRoot();
  process.on("SIGINT", onSigint);
  process.on("SIGTERM", onSigterm);
  process.once("beforeExit", onNormalStop);
  try {
    console.log(`Demo HOME: ${home}`);
    seeded = await seedDemoFortress(home, {
      passphrase,
      port,
      startDashboard: true,
      removeOnStop: !keep,
      signal: controller.signal,
    });
    phase = "ready";
    console.log(`Dashboard URL: ${seeded.dashboardUrl}`);
    console.log(`API base URL: ${seeded.apiBaseUrl}`);
    console.log(`Operator token file: ${seeded.authTokenPath}`);
    console.log("Paste the token from that file into the console when it asks for operator authorization.");
    console.log(`Storage path: ${seeded.storagePath}`);
    console.log(`Teardown: npx tsx scripts/demo/seed-fortress.ts --teardown ${home}`);
    const egress = seeded.seededItems.find((item) => item.item === "blocked egress event");
    if (egress?.status === "not_available") {
      console.log(`Blocked egress: not produced (${egress.note})`);
    }
    await stopRequested;
    console.error("Demo stopped after ready.");
  } catch (error) {
    if (!interruption) throw error;
    console.error(`Demo seeding was interrupted by ${interruption}.`);
    process.exitCode = interruption === "SIGINT" ? SIGINT_EXIT_CODE : SIGTERM_EXIT_CODE;
  } finally {
    phase = "stopping";
    try {
      await seeded?.stop();
    } finally {
      try {
        // force makes library error cleanup and CLI ownership idempotent without ignoring removal failures.
        if (!keep) await rm(home, { recursive: true, force: true });
      } finally {
        process.off("SIGINT", onSigint);
        process.off("SIGTERM", onSigterm);
        process.off("beforeExit", onNormalStop);
      }
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
