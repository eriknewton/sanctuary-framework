# Concordia Python Sidecar

The Concordia sidecar is an optional Python process launched by the Sanctuary
composition layer (WP-MVP-10) when `composition_enabled: true` is set in the
fortress config. It speaks JSON-RPC 2.0 over stdio with the Sanctuary Node.js
process and wraps `concordia-protocol==0.6.0` for receipt packing, receipt
verification, and mandate verification.

Composition is OFF by default. The structural moat invariant ("framework alone
is fully operational") means a stock Sanctuary install never spawns this
sidecar, never loads its dependencies, and never speaks JSON-RPC over stdio to
a Python process.

## Files in this directory

| File               | Purpose                                                                      |
| ------------------ | ---------------------------------------------------------------------------- |
| `sidecar.py`       | Long-running JSON-RPC server. Spawned by `SidecarManager`.                   |
| `requirements.in`  | Source-of-truth list of direct dependencies (one line, human-edited).        |
| `requirements.txt` | Generated + hash-pinned install manifest. Installed with `--require-hashes`. |
| `README.md`        | This file.                                                                   |

## Supply-chain posture

Every dependency in `requirements.txt` is pinned with a SHA256 hash. CI invokes
`pip install --require-hashes -r requirements.txt`, which rejects a tarball
whose hash does not match the recorded value. A compromised PyPI release that
replaces an existing version's tarball is rejected at install time.

The two CI workflows that exercise this path:

- `.github/workflows/ci.yml` (test matrix, Node 22 and 24).
- `.github/workflows/test-baseline-guard.yml` (baseline guard on every PR).

Both workflows install using `--require-hashes`. Adding another pip-install
site WITHOUT `--require-hashes` is a supply-chain regression.

## Regenerating `requirements.txt` on a Concordia version bump

`requirements.txt` is generated from `requirements.in` with `pip-tools`. The
`requirements.in` file is short (one direct dependency today) and maintained by
hand. The `requirements.txt` file carries pinned versions plus hashes for every
transitive dependency and is installed from as the CI manifest.

Run this from the repo root against a Python 3.12 venv with `pip-tools`
installed:

```bash
# 1. Ensure pip-tools is installed in the venv you use for regeneration.
sidecars/concordia/.venv/bin/pip install pip-tools

# 2. Bump the version in requirements.in. Example for concordia-protocol 0.5.0:
#    concordia-protocol==0.5.0

# 3. Regenerate the pinned + hashed requirements.txt:
cd sidecars/concordia
../../sidecars/concordia/.venv/bin/pip-compile \
  --generate-hashes \
  --output-file requirements.txt \
  requirements.in

# 4. Smoke-test the new pin:
cd ../..
rm -rf sidecars/concordia/.venv
python3.12 -m venv sidecars/concordia/.venv
sidecars/concordia/.venv/bin/pip install --upgrade pip
sidecars/concordia/.venv/bin/pip install --require-hashes -r sidecars/concordia/requirements.txt
```

Commit both `requirements.in` and `requirements.txt` in the same change.

## v1.x roadmap (non-blocking)

- **Sidecar JSON-RPC protocol versioning.** v1.0 uses plain JSON-RPC 2.0 over
  stdio. v1.x may introduce a protocol version handshake plus Sanctuary-specific
  extensions (audit-correlation IDs, replay-queue ordering hints).
- **TS port of the sidecar.** The sidecar exists in Python because the
  reference Concordia SDK is Python. A Node.js port would collapse the
  cross-process boundary but is scheduled for v1.x.
- **CPU / memory / FD cgroup limits on the sidecar process.** v1.0 enforces
  only a per-message 10 MiB size cap in `sidecar-rpc.ts`. v1.x adds full
  cgroup-level resource limits for the sidecar child process.
