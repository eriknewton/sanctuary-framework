# Internal Ubuntu package refusal guard

This directory builds an **internal, unprovisioned-only** Ubuntu 24.04 amd64
`.deb` for `castle-wall-daemon`. It remains `install_ready=false` and does not
establish a Linux enforcement claim.

`build-deb.sh` takes an explicit positive package revision, builds the locked
default-feature daemon, copies the current source unit byte for byte, and
writes a `.deb`, checksum, manifest and root-custodied build identity. It puts
the hook's early `systemd`, `nftables` and `python3` probes in `Pre-Depends`;
finished-ELF libraries remain in ordinary `Depends`. Source inputs must be
clean, including untracked files, before the build stamps a commit identity.
`assert-source-constants.py` pins the reviewed **entire** `src/nftables.rs`
source by SHA-256 and also checks the relevant literal constants. This is a
deliberately narrow source pin, not a general Rust parser: any nft source edit,
including a new table-construction helper or an inline command, must receive
source review and an explicit pin update before package assertion can pass.

The control archive contains only `control`, `preinst` and `prerm`. These
self-contained scripts read bounded dpkg/filesystem/systemd/nft state and
refuse a fresh install unless the package and Castle Wall footprint are
positively absent. Upgrade and removal require an exact old package identity,
inert disabled unit and absent runtime state. No hook provisions, starts,
stops, reloads or disarms. A refused old `prerm upgrade` is backed by the new
`prerm failed-upgrade` veto. After a guarded removal, the operator purges an
ordinary `config-files` residue if present, then runs `systemctl daemon-reload`
and rechecks full absence before reinstall. Hooks never do those actions.

The first slice assumes a quiescent operator-controlled host with no direct
daemon or concurrent root provisioning actor; hooks cannot prove that process
or transaction exclusion. Provisioned package upgrades/removal, trusted CLI
delivery and target-host Linux acceptance remain separate work.

The public repository's CI retains the inert internal `.deb` and lifecycle
evidence as downloadable Actions artifacts for seven days. This is review
visibility, not confidential storage, a package publication, or a release.

Example build command (builds only; it does not install):

```bash
bash castle-wall-daemon/packaging/ubuntu/build-deb.sh --revision 1 --output /tmp/sanctuary-linux-package
bash castle-wall-daemon/packaging/ubuntu/assert-structure.sh --artifact-dir /tmp/sanctuary-linux-package
```
