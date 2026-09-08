/**
 * `sanctuary export-passphrase` — print the credential THIS HOST holds for the
 * fortress, so the operator can back it up.
 *
 * Its own module (rather than a closure inside `cli.ts`) because `cli.ts` runs
 * `main()` on import and is therefore untestable; every other subcommand
 * already lives under `cli/` and is lazy-imported the same way.
 *
 * A73: the credential comes from the ONE shared resolver
 * (`wrap/custody-credential.ts`), restricted to the host-local sources. This
 * verb previously read only the `sanctuary-passphrase[-<id>]` keyring family,
 * so on a fortress created by `sanctuary init` — which enrolls an OS-keyring
 * CUSTODY factor and no passphrase — it reported "No stored passphrase found"
 * about a fortress whose custody was perfectly fine.
 *
 * It consults that resolver TWICE rather than once, because a backup verb wants
 * a different ranking than the unlocking verbs do: the portable passphrase
 * spelling before the machine-resident custody factor. See the comment at the
 * two calls.
 */

export async function runExportPassphrase(args: string[]): Promise<void> {
  let assumeYes = false;
  for (const a of args) {
    if (a === "--yes" || a === "-y") assumeYes = true;
    else if (a === "--help" || a === "-h") {
      printExportPassphraseHelp();
      process.exit(0);
    }
  }

  // Resolve the fortress HERE, at the CLI entry point, and pass it down.
  // Ambient resolution is correct at this layer -- for `sanctuary
  // export-passphrase` the operator's own environment IS the input -- but it
  // is stated rather than left implicit, so no leaf module has to reach for
  // process state on its own.
  const { resolveStoragePath } = await import("../paths.js");
  const storagePath = resolveStoragePath();

  // Same resolver `protect` uses, restricted to the HOST-LOCAL sources: this
  // verb backs up the credential THIS MACHINE holds for this fortress, so
  // echoing back a value the operator just put in the environment would be a
  // loop, not a backup. Before A73 this read only the
  // `sanctuary-passphrase[-<id>]` family and therefore reported "No stored
  // passphrase found" on a fortress whose custody was fine, because `init`
  // enrolls an OS-keyring CUSTODY factor and no passphrase.
  const {
    resolveFortressCustodyCredential,
    custodyCredentialSourceLabel,
    HOST_LOCAL_CUSTODY_SOURCES,
  } = await import("../wrap/custody-credential.js");

  // PASSPHRASE FIRST, and deliberately NOT the resolver's own order. The
  // resolver ranks the enrolled custody factor above the stored passphrase
  // because `protect` and the server boot want whichever factor OPENS the
  // fortress, and on the documented `init` path only the custody factor exists.
  // This verb has a different job: what it prints has to be a credential the
  // operator can put back. A passphrase is the portable spelling every
  // `SANCTUARY_PASSPHRASE` consumer accepts; the custody factor is 32 raw bytes
  // that no consumer takes, so inheriting the resolver's order printed a
  // base64url key on exactly the fortresses where a usable passphrase also
  // existed, while the help promised the passphrase. The honest resolution is
  // to make the CODE match that help, so the two calls below are ordered:
  // ask for a stored passphrase that unlocks THIS fortress, and only when
  // there is none fall back to the enrolled factor with its machine-resident
  // bound. Must match the ordering sentence in `printExportPassphraseHelp`.
  const resolveHostLocal = async (
    allow: Parameters<typeof resolveFortressCustodyCredential>[0]["allow"],
  ) =>
    resolveFortressCustodyCredential({
      storagePath,
      allow,
      // A read-only backup verb never creates custody.
      allowMint: false,
    });
  const stored = await resolveHostLocal(["stored-passphrase"]);
  // The fallback run allows BOTH sources, so its report still accounts for the
  // stored passphrase: a refusal that named only the custody factor would hide
  // a stale or locked passphrase item the operator needs to hear about.
  const resolution =
    stored.status === "resolved"
      ? stored
      : await resolveHostLocal(HOST_LOCAL_CUSTODY_SOURCES);

  if (resolution.status !== "resolved") {
    // SAFETY: stderr is the operator-facing CLI channel; names credential
    // SOURCES and non-secret reasons only, never a value.
    for (const source of resolution.report.indeterminate) {
      const detail = resolution.report.details[source];
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand; this text names credential SOURCES and reasons only, never a value.
      console.error(
        `  ${custodyCredentialSourceLabel(source)} is present but unusable right now` +
          `${detail ? ` (${detail})` : ""}.`,
      );
    }
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; this text names credential SOURCES and reasons only, never a value.
    console.error(
      resolution.report.found.length === 0
        ? "No stored fortress credential found on this host. Run `sanctuary init` or `sanctuary protect` first."
        : "No stored fortress credential on this host currently opens this fortress.",
    );
    process.exit(1);
  }

  const credential = resolution.credential;
  const { toBase64url } = await import("../core/encoding.js");
  // The custody factor is 32 raw bytes; base64url is the same encoding the
  // keyring item itself holds, so what is printed round-trips exactly.
  const value =
    credential.kind === "keychain-key"
      ? toBase64url(credential.keychainKey)
      : credential.kind === "passphrase"
        ? credential.passphrase
        : credential.recoveryKey;
  const description = custodyCredentialSourceLabel(credential.source);

  if (!assumeYes) {
    const readline = await import("node:readline/promises");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    const answer = await rl.question(
      `\n  This will print ${description} (from ${credential.location}) to stdout.\n  Continue? [y/N] `
    );
    rl.close();
    if (!/^y(es)?$/i.test(answer.trim())) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("Aborted.");
      process.exit(1);
    }
  }

  if (credential.kind === "keychain-key") {
    // HONEST BOUND, not a caveat: this factor is machine-resident by design
    // and no env var consumes it, so a copy of it is a backup of THIS host's
    // unlock, not a portable credential. The recovery key is the portable one.
    // Saying so here is the difference between a backup and a false sense of
    // one. Printed AFTER the confirmation so it sits with the value.
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; this text names credential SOURCES and reasons only, never a value.
    console.error(
      "\n  This is the OS-keyring custody factor for this fortress on this host.\n" +
        "  It unlocks the fortress only where Sanctuary can read it back from the\n" +
        "  keyring; the portable credential is the recovery key captured at creation.\n",
    );
  }
  process.stdout.write(value + "\n");
}

export function printExportPassphraseHelp(): void {
  // The ordering sentence below is a contract with `runExportPassphrase`: the
  // two resolver calls there ask for the stored passphrase first and fall back
  // to the enrolled custody factor. Changing one without the other is how this
  // verb came to print a base64url key while promising a passphrase.
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
  sanctuary export-passphrase. Print the credential this host holds for the
  fortress to stdout.

  Usage:
    sanctuary export-passphrase [--yes]

  Options:
    --yes, -y    Skip confirmation prompt (for scripts)
    --help, -h   Show this help

  Prints the stored fortress passphrase when one unlocks this fortress,
  otherwise the OS-keyring custody factor this fortress was created with.
  Either one opens the fortress and therefore decrypts your state; store the
  output in a password manager and clear your terminal history afterwards. The
  custody factor is machine-resident: the portable credential is the recovery
  key captured when the fortress was created.
`);
}
