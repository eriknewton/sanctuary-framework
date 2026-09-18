# Internal Ubuntu package scaffold

This directory builds one **internal structural** Ubuntu 24.04 amd64 `.deb` for
`castle-wall-daemon`. It does not make the daemon install-ready and does not
establish a Linux enforcement claim.

`build-deb.sh` builds the locked, default-feature daemon binary, copies the
current source systemd unit verbatim at build time, derives Ubuntu runtime
dependencies from the finished ELF and required executables through
`dpkg-query`, and writes a `.deb`, checksum, manifest, and in-package build
identity to an empty output directory.

The scaffold intentionally contains no Debian maintainer scripts. It creates
no environment file, policy/key/state material, system user/group, or nftables
state, and it cannot enable, start, stop, disarm, or remove a service. Those
lifecycle decisions remain blocked on the finalized A119 safe-disarm contract
and on install-grade evidence in a disposable Ubuntu environment.

Example build command (builds only; it does not install):

```bash
bash castle-wall-daemon/packaging/ubuntu/build-deb.sh --output /tmp/sanctuary-linux-package
bash castle-wall-daemon/packaging/ubuntu/assert-structure.sh --artifact-dir /tmp/sanctuary-linux-package
```
