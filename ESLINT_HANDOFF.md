# ESLint Wiring Handoff

## Context

- Starting HEAD confirmed: `40954a4a2140ce44b4b42dc767d06de77b262636`
- Installed versions used from `server/node_modules`:
  - `eslint`: `10.4.1`
  - `typescript-eslint`: `8.61.0`
  - `@eslint/js`: `10.0.1`
- No installs were run by this worker.
- `server/node_modules` and `sidecars/concordia/.venv` are prepared symlinks and were not added to the commit.

## What Changed

- Added `server/eslint.config.js` using ESLint flat config.
- Kept the existing `server/package.json` lint script as `eslint src/`.
- Included the coordinator-provided dependency updates in `server/package.json` and `server/package-lock.json`.

## Lint Result

`npm run lint` now exits 0 in `server/`.

Current warning profile:

| Rule | Warnings |
| --- | ---: |
| `@typescript-eslint/no-floating-promises` | 207 |
| `no-useless-escape` | 23 |
| `no-useless-assignment` | 20 |
| `@typescript-eslint/no-explicit-any` | 10 |
| `preserve-caught-error` | 8 |
| `@typescript-eslint/no-unused-vars` | 7 |
| `prefer-const` | 2 |
| `@typescript-eslint/no-empty-object-type` | 1 |
| `no-misleading-character-class` | 1 |

Total: 279 warnings across 100 files.

## Follow-Ups

- Burn down `@typescript-eslint/no-floating-promises` intentionally. Most findings need behavior-aware decisions (`await`, `.catch`, or explicit `void`) and should not be swept mechanically.
- Review regex warnings from `no-useless-escape` and `no-misleading-character-class`; some are likely trivial, but they span enough files to exceed this wiring task.
- Fix `no-useless-assignment`, `prefer-const`, and `@typescript-eslint/no-unused-vars` in small module-scoped batches.
- Tighten `@typescript-eslint/no-explicit-any` after choosing local replacement types.
- Revisit `preserve-caught-error` and add `cause` where error chains should be preserved.
- Castle-wall warnings were left untouched per prompt; do not fix those in this branch while the related PR is in flight.
