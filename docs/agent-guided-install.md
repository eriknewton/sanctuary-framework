# Agent-guided installation

Sanctuary's supported installation experience assumes that an operator delegates
the mechanical work to a local shell-capable agent. The operator is not expected
to translate a long runbook into commands.

The agent drives installation by repeatedly running:

```bash
sanctuary install --profile <memory|full> --harness <name> --json
```

Each invocation observes the machine again and returns one of four states:

- `agent_action`: the response contains one argument vector the agent may run.
- `human_action`: progress is waiting on Apple consent, exact-command privilege
  authorization, or private recovery custody.
- `complete`: the requested mechanical installation has been observed.
- `blocked`: the requested profile is unsupported or a trusted artifact is absent.

The response is advisory, not a mutable progress file. A caller must execute no
command other than the returned argument vector, then rerun the planner. This
makes interruption and handoff safe: a fresh agent resumes from observed state,
not from a transcript or a claimed prior step.

## Secret boundary

The planner never returns a passphrase, recovery key, dashboard bearer token, or
command that prints one. `protect --agent-guided` keeps the passphrase in the
platform credential store and stages the newly minted recovery key in a mode
`0600` file outside the fortress without printing its contents. Once installation
is complete, the response gives that path to the operator. The operator moves it
into a password manager in a private local session and deletes the staging file.
The installing agent must not read the file, run `export-passphrase`, capture
secret output, or ask the operator to paste recovery material into chat.

## Profiles

`memory` installs the sovereign encrypted memory/cooperative policy surface for
any harness supported by `sanctuary protect`.

`full` additionally requires macOS, Hermes, the signed Castle Wall app at
`/Applications/Sanctuary-CastleWall.app`, an enabled system extension, a root
boot service, and observed live enforcement. The signed app is deliberately not
downloaded by the planner: artifact provenance must come from the signed release
channel or an explicitly supplied drill candidate. The agent may copy a verified
artifact into place, launch it, and guide the operator to the named macOS pane.
Only the operator can grant Apple consent and authorize the exact privileged
command. The installer never asks the operator to run `sudo -v`: a retained
timestamp would give the agent reusable, general sudo authority rather than
bounded authorization. The returned privileged argument vector is therefore a
human action to run in a private local Terminal. The agent resumes by observing
the resulting state.

### Root boot-runtime custody

The Castle Wall boot service runs as root, so none of its executable inputs may
remain replaceable by the operator account after installation. `install-boot`
therefore first copies the app bundle into temporary root-owned custody, verifies
that copied bundle's deep signature, Gatekeeper status, Sanctuary identity,
headless contract, and build identity, and only then snapshots three inputs into
a root-owned, non-writable directory under `/Library/Application Support/Sanctuary`:

- the standalone Node executable embedded in the signed Castle Wall app;
- the self-contained safe-mode daemon embedded in that app; and
- the signed Castle Wall signer client.

Each installed filename is bound to the SHA-256 digest of its bytes. The launchd
property list names only those installed paths. Installation refuses a Node or
signer-client executable with non-system dynamic-library dependencies, and it
refuses a signer client that does not satisfy Sanctuary's Developer ID team and
designated-identifier requirement. Existing snapshots are revalidated before
reuse. `uninstall-boot` removes the boot service before removing the root-owned
runtime. If replacement fails after the plist changes, installation restores
the previous same-fortress plist and reloads its prior unit; a rollback failure
is reported as critical rather than claiming boot survival.

The ordinary npm CLI and the operator's Homebrew Node installation are never
retained as root execution inputs. This snapshot is not a software-update trust
decision. The operator's one-time privilege authorization approves the exact
signed app already selected by the agent. The snapshot prevents those approved bytes from becoming a
persistent root execution path that an unprivileged process can replace later.

## Cold-install acceptance

A release candidate passes the install experience only when a fresh agent on a
fresh Mac can reach `complete` from this contract, with the operator performing
only Apple consent, privilege authorization, and private recovery custody. A
manual expert run proves technical installability, but does not satisfy this
product acceptance criterion.
