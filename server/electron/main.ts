/**
 * Sanctuary Operator Console v1.0 — Electron desktop shell.
 *
 * Thin BrowserWindow wrapper that loads the console URL served by
 * `server/src/console/server.ts`. The render tree is the same server-
 * rendered HTML the browser sees — "single render tree, two shells" is
 * satisfied by the server being the tree's single source of truth.
 *
 * Packaging / code-signing / auto-update are v1.0.1 concerns. This file
 * builds only with `electron` as a dev dependency; the published npm
 * package does NOT ship the Electron bundle to keep the runtime npm
 * install small. Operators who want the desktop shell build it from
 * source with a separate `npm run electron:build` script (not shipped
 * at v1.0 — see handoff for follow-up scope).
 *
 * CAUTION: at v1.0 this file is not compiled by the default `tsup`
 * build (it imports `electron`, which is not a server dep). It lives
 * here as the reference implementation for the v1.0.1 packaging pass.
 * `server/tsconfig.build.json` excludes `electron/` explicitly.
 */

// @ts-expect-error — electron is intentionally not a runtime dep
import { app, BrowserWindow, session } from "electron";

interface ShellConfig {
  url: string;
  auth_token?: string;
  width?: number;
  height?: number;
}

function readShellConfig(): ShellConfig {
  const url = process.env.SANCTUARY_CONSOLE_URL;
  if (!url) {
    throw new Error(
      "SANCTUARY_CONSOLE_URL not set. Start the console server first (e.g. sanctuary dashboard) and export the URL it prints."
    );
  }
  const config: ShellConfig = {
    url,
    width: process.env.SANCTUARY_SHELL_WIDTH
      ? Number(process.env.SANCTUARY_SHELL_WIDTH)
      : 1280,
    height: process.env.SANCTUARY_SHELL_HEIGHT
      ? Number(process.env.SANCTUARY_SHELL_HEIGHT)
      : 800,
  };
  if (process.env.SANCTUARY_CONSOLE_TOKEN) {
    config.auth_token = process.env.SANCTUARY_CONSOLE_TOKEN;
  }
  return config;
}

async function createWindow(): Promise<void> {
  const cfg = readShellConfig();

  // Inject the bearer token as an Authorization header so we never embed
  // it in a URL (matches the dashboard's cookie/session model).
  if (cfg.auth_token) {
    session.defaultSession.webRequest.onBeforeSendHeaders(
      (details: { requestHeaders: Record<string, string> }, cb: (args: { requestHeaders: Record<string, string> }) => void) => {
        details.requestHeaders["Authorization"] = `Bearer ${cfg.auth_token}`;
        cb({ requestHeaders: details.requestHeaders });
      }
    );
  }

  const win = new BrowserWindow({
    width: cfg.width,
    height: cfg.height,
    title: "Sanctuary Operator Console",
    backgroundColor: "#f6f7f9",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Restrict new-window / navigation to the same origin so a compromised
  // server-side XSS cannot pivot to file:// or remote hosts.
  const origin = new URL(cfg.url).origin;
  win.webContents.setWindowOpenHandler(
    ({ url }: { url: string }) => {
      if (new URL(url).origin === origin) return { action: "allow" };
      return { action: "deny" };
    }
  );
  win.webContents.on(
    "will-navigate",
    (e: { preventDefault: () => void }, navUrl: string) => {
      if (new URL(navUrl).origin !== origin) e.preventDefault();
    }
  );

  await win.loadURL(cfg.url);
}

app.whenReady().then(() => {
  createWindow().catch((err: Error) => {
    console.error("Failed to launch Sanctuary console shell:", err);
    app.exit(1);
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow().catch((err: Error) => {
        console.error("Failed to reopen shell window:", err);
      });
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
