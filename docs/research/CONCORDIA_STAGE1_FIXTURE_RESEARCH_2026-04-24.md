# Concordia Stage 1 Fixture Research

Status: complete
Date: 2026-04-24
Branch: `codex/concordia-stage1-fixture-research`

## Scope

Stage 1 inspected the installed `concordia-protocol==0.4.0` sidecar fixture
surface already used by Sanctuary composition tests. The goal was to identify
the smallest real-sidecar proof needed before later tool-handler integration.

## Findings

1. The local Concordia sidecar venv exists under `sidecars/concordia/.venv` and
   imports `concordia.__version__ == "0.4.0"`.
2. Existing composition tests spawn the real Python sidecar and prove receipt
   packing, version reporting, mandate parsing, graceful degradation, and
   references propagation.
3. The missing fixture proof was round-trip receipt verification. A receipt
   packed by `pack_receipt` did not verify through `verify_receipt` in the same
   sidecar process.
4. Root cause: `pack_receipt` signed `source_event_type`, but `verify_receipt`
   rebuilt the signable receipt without `source_event_type`. The TypeScript
   adapter also did not forward that field during verification.

## Stage 1 Change

The branch adds a real-sidecar regression test:

```text
packed receipt verifies through the same real Concordia sidecar
```

The fix keeps the existing receipt schema intact and only aligns the verifier
with the packer:

- `sidecars/concordia/sidecar.py`: include `source_event_type` in the
  verification signable payload.
- `server/src/composition/concordia-adapter.ts`: forward
  `receipt.source_event_type` to `verify_receipt`.

## Remaining Follow-Ups

1. Cross-process receipt verification still depends on sidecar key continuity.
   The sidecar returns `public_key` from `pack_receipt`, but
   `ConcordiaReceipt` does not currently persist it. Same-process verification
   is fixed; restart-stable verification needs a separate design.
2. The Sanctuary composition reference shape uses `ref_type` and `ref_id`.
   Concordia's session-attestation helper uses `type` and `id`. This is not
   changed in Stage 1 because Sanctuary's composition v1.0 type has existing
   tests and downstream assumptions. A future interop pass should decide
   whether to normalize at the sidecar boundary or keep the Sanctuary wrapper
   shape explicit.
3. The production pipeline still synthesizes a `ConcordiaReceipt` from the
   signed proposal rather than calling `CompositionService.packReceipt()`.
   Tool-handler integration should decide whether the real sidecar pack path is
   required before Verascore signal emission.

## Verification

```bash
cd server
npm test -- --run test/composition/composition-v1.test.ts
npm run typecheck
```

Expected result after this branch:

```text
test/composition/composition-v1.test.ts: 54 passed
typecheck: clean
```
