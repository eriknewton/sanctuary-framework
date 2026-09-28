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
`assert-source-constants.py` pins the exact `src/nftables.rs` bytes from
repository baseline `17d251f50514a885d0cd9666e363d19dbc963574` by SHA-256
and checks the relevant literal constants. This byte-identity pin is not a
general Rust parser or a claim of whole-file review: any nft source edit,
including a new table-construction helper or an inline command, requires
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

## Agent template unit

The package also ships `/etc/systemd/system/sanctuary-agent@.service`, a
template whose instance name is the agent's numeric uid. It has no `[Install]`
section, so nothing enables or starts it. In every systemd unit root the guard
refuses any entry whose name starts with `sanctuary-agent@` other than the
packaged template itself (the template drop-in directory
`sanctuary-agent@.service.d/`, an instance drop-in directory such as
`sanctuary-agent@<uid>.service.d/`, an alternate fragment, an instance
enablement symlink) and any symlink whose target names `sanctuary-agent@`. It
also refuses any package operation while an agent instance is active or
transitioning. Two drop-in directories that systemd also applies to every agent
instance are outside the guard's scope: the prefix drop-in
`sanctuary-.service.d/` and the top-level `service.d/` (distributions ship files
there, so it cannot be refused wholesale). Host acceptance checks them instead:
the agent unit's `DropInPaths` must be empty. The
package does not ship the agent executable
(`/usr/local/libexec/sanctuary/protected-agent-v1`); an instance whose
executable is absent fails with 203/EXEC and no agent process runs.

Provision one agent uid `U` (root, once per host, before publishing a manifest
that admits `U`). Classify first and stop on anything unexpected:

```bash
getent passwd U ; getent group U
groupadd --system --gid U sanctuary-agent-U
useradd --system --uid U --gid U --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sanctuary-agent-U
```

Run both commands only when both lookups are empty; run only `useradd` when the
group `sanctuary-agent-U:x:U:` exists and the user does not (an interrupted
earlier run); do nothing when the user already has uid `U`, gid `U` and shell
`/usr/sbin/nologin`. Anything else (uid or gid `U` held by another name, a
different gid, a login shell, the user in a supplementary group) is a stop:
choose another `U` or repair by hand. Failure mode: `useradd: UID U is not
unique` looks like a broken tool and is this stop case.

Identity change from `U` to `V`, in this order: `systemctl stop
sanctuary-agent@U`, `systemctl stop sanctuary-castle-wall`, stop any process of
uid `U` started outside the unit and confirm `ps -u U` prints nothing, then
`castle-wall-daemon --disarm`, provision `V`, publish the manifest admitting
`V`, start the wall, start `sanctuary-agent@V`. Failure mode: skipping the
disarm makes the wall's start refuse through the drift path and the agent start
fail as a dependency; that is the designed refusal, not a broken unit. Failure
mode that looks like success: `--disarm` refuses only while the daemon runs, so
a surviving uid-`U` process is not detected by it; the explicit agent stop and
the `ps -u U` check come first for that reason.

The agent's state directory `/var/lib/sanctuary-agent-U` survives stop,
disarm, package removal and purge. Nothing bounds its size or content. After
the agent stop, decide whether to archive or delete that exact path; never use
a glob.

Starting `sanctuary-agent@U` while the wall is stopped or failed starts the
wall too (`BindsTo=` pulls it). After a wall exit 78 that is an explicit wall
start, not an automatic restart, so repair the host first. If the wall has hit
its start limit, the agent start fails with "start request repeated too
quickly" as a dependency; run `systemctl reset-failed sanctuary-castle-wall`,
not an edit of the agent unit.

A package built before the agent unit shipped cannot be upgraded in place: the
new preinst refuses with "required package file absent" for the agent unit and
nothing is unpacked. Use the guarded remove, purge, `systemctl daemon-reload`
and a fresh install.

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
