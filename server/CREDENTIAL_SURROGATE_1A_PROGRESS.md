# Credential surrogacy slice 1a: progress ledger

Branch `feat/credential-surrogate-1a-2026-09-30`, base `origin/main` at `94bc9d41`.
Design: `Review/Sanctuary/Credential_Surrogacy_Design_v2.1_2026-09-30.md` (coordinator repo).
This ledger is the resume point for the next job in the chain. Read the "next" line first.

## Job 1 (2026-09-30)

### done
- Step 0 worktree setup (npm install plus hash-pinned Concordia sidecar venv, both succeeded on this host).
- Read design v2.1 sections 1 to 5 and `ROUND2_DISPOSITIONS.md` in full.

### in progress
- Scope item 8: new pure module `server/src/credential-surrogate/`.

### next
- Finish scope item 8 (module plus tests), then scope item 1 (`parseSurrogatePolicyDocument`
  and the conflict check in `disclosure/broker/policy.ts`), then item 2 (`surrogate-store.ts`),
  then item 3 (broker refusal through the required `surrogateBoundSecrets` set).
- Items 4 to 7 and 9 to 10 are untouched and belong to later jobs in the chain.

### open questions
- None yet. The design and the tree agree at every seam read so far.

### test results so far
- None yet.

### environmental notes for this host (Mini2)
- No `timeout(1)` binary is installed; waits use the tool call timeout instead.
- `gh` is unauthenticated: never query or open a PR from here.
