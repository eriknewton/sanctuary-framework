## Summary

- Wire ESLint flat config for the server package.
- Add the installed ESLint dependencies to `server/package.json` and `server/package-lock.json`.
- Configure current repo-wide violations as warnings so `npm run lint` exits 0 today while still surfacing useful findings.

## Verification

- `npm run lint`
- `npm run typecheck`
- `npm test`

## Notes

`npm run lint` currently reports 279 warnings across 100 files. The largest bucket is `@typescript-eslint/no-floating-promises` with 207 warnings; the rest are documented in `ESLINT_HANDOFF.md` for follow-up cleanup.
