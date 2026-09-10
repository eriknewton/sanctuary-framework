# Agent-guided installation

Sanctuary's supported installation experience assumes that an operator delegates
the mechanical work to a local shell-capable agent. The operator is not expected
to translate a long runbook into commands.

The agent drives installation by repeatedly running:

```bash
sanctuary install --profile <memory|full> --harness <name> --json
```

On a factory Mac, Node and npm are not preinstalled. After the verified signed
Castle Wall app is placed at `/Applications/Sanctuary-CastleWall.app`, start the
full-profile planner from the CLI runtime sealed inside that app:

```bash
/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary install --profile full --harness hermes --json
```

The planner and the Hermes MCP configuration both continue to use that absolute
signed launcher. It clears Node preload/search overrides before entering the
app-sealed runtime and does not require a separate Node/npm installation. The
sealed runtime is staged to carry the complete built CLI: every compiled entry
point (including the storage worker that fortress creation starts), the agent
templates, the first-party reference plugins, the catalog schemas, and the
production dependency closure. The build's contents gate verifies that set
before the app is signed, and `sanctuary install` verifies it again against the
app's runtime manifest before planning; an app whose runtime is incomplete
reads as a mismatch with the remedy of replacing the app. Fortress creation
from the signed app on a Mac with no Node of its own is confirmed per release
on the exact released artifact. For
profiles without a verified signed app, an absent package manager is reported
as `blocked`; the agent must not invent a download or installer outside the
returned action contract.

Each invocation observes the machine again and returns one of four states:

- `agent_action`: the response contains one argument vector the agent may run.
- `human_action`: progress is waiting on Apple consent, exact-command privilege
  authorization, or private recovery custody.
- `complete`: the requested mechanical installation has been observed.
- `blocked`: the requested profile is unsupported or a trusted artifact is absent.

An `agent_action` is single-shot. Execute its `argv` once. If it exits zero,
rerun the planner and trust the newly observed machine state. If it exits
nonzero, do not retry it and do not rerun the planner autonomously: follow the
action's declared `on_nonzero` human transition instead. After the human action
completes, rerun the planner. This rule prevents an observed-state loop from
turning a session-scoped custody refusal into unlimited autonomous retries.

The response is advisory, not a mutable progress file. A caller must execute no
command other than the returned argument vector, then follow its exit contract:
rerun the planner only after exit zero, or transition to `on_nonzero` after a
failure. This makes interruption and handoff safe: a fresh agent resumes from
observed state, not from a transcript or a claimed prior step.

## Secret boundary

The planner never returns a passphrase, recovery key, dashboard bearer token, or
command that prints one. `protect --agent-guided` keeps the passphrase in the
platform credential store and stages the newly minted recovery key in a mode
`0600` file outside the fortress without printing its contents.

Once installation is complete, the custody step the planner emits depends on
what it actually observed at that staged path, and it never names a file that
is not there. A run that mints a recovery key stages one; a run against a
fortress this host already holds a credential for does not, and the two need
different instructions.

- **Staged file present.** The response gives the operator that exact path. In a
  private local session the operator moves the file into a password manager and
  then deletes it.
- **Staged file absent.** Nothing was staged, so there is nothing to move. The
  response says which credential this host already holds and tells the operator
  to run `sanctuary export-passphrase` in a private local session to record it.
- **Path present but not a regular file.** The observation failed (a symlink, a
  directory, an account that cannot stat it), so the response says so and asks
  the operator to look at the path first rather than asserting either branch.

The installing agent must not read the file, run `export-passphrase`, capture
secret output, or ask the operator to paste recovery material into chat.

On macOS, true first custody is deliberately a human action. The planner returns
the exact `protect` argument vector with `--operator-custody`; the operator runs
it once in a private local desktop Terminal and unlocks the login Keychain if
macOS asks. The agent must not add that operator-only flag, run the command on
the operator's behalf, request the login password, or capture command output.
Passwordless SSH does not prove access to the login Keychain, and an absent-item
lookup does not prove that a later Keychain write will succeed. Sanctuary
therefore resolves and persists the passphrase before bootstrapping Hermes or
writing fortress/recovery state. Any custody failure leaves those unrelated
surfaces untouched.

Wrapping a second harness is not a new first-custody ceremony. When the fortress
already has custody material (including a user-supplied encrypted fallback), the
planner may return the ordinary single-shot agent action. Its `on_nonzero`
transition still names the exact private-local-Terminal action; a failed agent
attempt is never retried automatically.

## Rung 1 memory onboarding

For the fresh-host and second-machine walkthrough (first-use proof with the MCP
tools, restart persistence, portability, archive transfer, the exact-fortress
unwrap, recovery-key rekey, and `restore-attest`), see
[Rung 1: fresh-host sovereign-memory onboarding](rung1-fresh-host.md).
On a copied host or after a lost passphrase, guide the operator first to the
private recovery-key rekey in that document. Never recommend nuke while a
human-held recovery key (or configured share/guardian recovery) can preserve
the fortress.

The planner reports three ambient-env-blind daily-UX observations for the memory
surface. Credential/envelope inspection is read-only; the separate lock-capability
check uses a short-lived private runtime socket and refuses known shared/network
filesystems. `custody_access`
(`usable`, `absent`, `locked`, `mismatch`, `missing`, `unavailable`, or `unknown`)
reports whether this host opens the fortress from its exact-fortress stored
credential with no secret typed; `custody_mutation` (`available`, `unavailable`,
or `unknown`) independently reports whether the reviewed process-owned mutation
lock is usable; `recovery_factor` (`present`, `absent`, or `unknown`) reports a
MAC-authenticated, operator-verified human-held recovery-key wrap.

The planner also reports `staged_recovery_file` (`present`, `absent`, or
`unknown`), the observation that selects the `private_recovery_custody` operator
action. It is reported alongside the chosen action text so a `--json` consumer
can see why that branch was taken: `present` names a staged file to move into a
password manager, `absent` means this install staged none, and `unknown` means
the path could not be observed as a regular file. `unknown` is never folded into
`absent`.

The planner reports `complete` only when access is `usable` and mutation is `available`.
It then adds a
`restart_and_verify_rung1` human action: restart the host and confirm memory
survives via `memory_insert`, `memory_search`, and `memory_get` (which proves
exact content: it decrypts and re-verifies the stored content hash, not signer
data) with no ambient credential env. Verified provenance and signer fields come
from `sdw_memory_provenance`, not `memory_get`.

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

Apple consent on the full profile is more than the system-extension toggle. The
first time the content filter arms, macOS raises a one-time "would like to filter
network content" approval; the planner returns an `approve_content_filter` human
action that names this dialog and the System Settings pane, because the arm
otherwise appears to hang until the operator approves it. Separately, the boot service cannot come up cleanly
until the root-owned enforcement anchor holds the signer helper's key. That is
true of a machine where the anchor holds some other key, of a machine that has
no anchor yet, and of a vault that has never been put on the wall, and the
planner returns the same `repin_trust_anchor` human action for all three, naming
the exact `castle-wall re-pin` command rather than leaving the operator with an
unexplained boot loop. Creating a vault never installs that anchor, so a machine
that has never been through this step is the ordinary starting state, not a
fault. The command asks the operator to confirm and refuses when it has no
terminal, so the agent cannot run it: it is a human action by construction as
well as by policy. The trust-anchor verdict is read from `castle-wall status`;
when the anchor is not readable from the planner's context, the observation is
reported as unknown and no remedy is invented.

The vault's own state is reported separately from the machine's. Init records
only that a vault has not yet been put on this machine's Castle Wall
(`not_yet_walled`); nothing is ever recorded to say a vault IS on the wall.
Whether a vault is on the wall is derived, never stored: it holds only when
this Mac's trust-anchor verdict is consistent with the signer helper's key
AND that vault's own arm evidence says armed. Re-pin supplies the anchor half
of that pair; arming, a separate step, supplies the other. The planner,
`doctor`, `castle-wall status`, `sanctuary status`, and the health surfaces
each report what they can observe of that pair, so a machine can carry a
running wall from an earlier install while the vault in front of the operator
is on no wall at all; machine-wide observations are never read as protection
for a particular vault.

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
