# Sanctuary Operator Console — Electron desktop shell

Thin Electron wrapper that loads the console HTML served by
`server/src/console/server.ts`. "Single render tree, two shells" is
satisfied by the server being the render tree's source of truth — the
browser and this desktop shell both load the same `/console` URL.

## Status at v1.0

- `main.ts` is the reference implementation. It is **not** compiled by
  the default `tsup` build (see `tsconfig.build.json` exclude).
- Packaging, code-signing, and auto-update are v1.0.1 scope. Operators
  who want the desktop shell at v1.0 run the console server and launch
  Electron against it via `SANCTUARY_CONSOLE_URL=...`.

## Development

```bash
# 1. Start a console server (standalone or alongside the dashboard)
SANCTUARY_CONSOLE_URL=http://127.0.0.1:3501/console \
SANCTUARY_CONSOLE_TOKEN=<bearer-token-if-any> \
  npx electron server/electron/main.ts
```

## Why the shell is a separate artifact

- The server-rendered HTML is the same whether the client is a browser
  or Electron. There's no bundler to maintain, no divergence between
  surfaces.
- The Electron shell is pinned to the same origin so a compromised or
  unreachable server doesn't let the UI pivot to `file://` or remote
  URLs.
- Auth token is injected via `Authorization: Bearer ...` header, never
  embedded in the URL (matches the existing dashboard's pattern).

## v1.0.1 follow-ups

- `electron-builder` config for macOS / Windows / Linux installers.
- Code signing pathway (macOS notarization, Windows EV cert, Linux AppImage).
- Auto-update channel keyed to the console server's version.
- Menu bar entries for the six primary surfaces.
