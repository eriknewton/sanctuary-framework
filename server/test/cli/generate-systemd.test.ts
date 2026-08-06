import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import {
  renderSystemdUnit,
  resolveCliScriptPath,
  resolveSystemdStateDir,
  runGenerateCommand,
} from "../../src/cli/generate.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("sanctuary generate systemd", () => {
  it("renders deterministic unit content", () => {
    const unit = renderSystemdUnit({
      user: "svc-sanctuary",
      stateDir: "/var/lib/sanctuary",
      binary: "/usr/local/bin/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain("sudo systemctl enable --now sanctuary.service");
    expect(unit).toContain("User=svc-sanctuary");
    expect(unit).toContain("Environment=SANCTUARY_STORAGE_PATH=/var/lib/sanctuary");
    expect(unit).toContain("ExecStart=/usr/local/bin/sanctuary dashboard --no-confirm");
  });

  it("notes macOS context but still emits Linux unit", () => {
    const unit = renderSystemdUnit({
      user: "erik",
      stateDir: "/Users/erik/.sanctuary",
      binary: "/usr/local/bin/sanctuary",
      platform: "darwin",
    });
    expect(unit).toContain("this host is macOS");
    expect(unit).toContain("[Unit]");
  });

  it("supports CLI flags", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({
      argv: [
        "systemd",
        "--user",
        "svc",
        "--state-dir",
        "/srv/sanctuary",
        "--binary",
        "/opt/bin/sanctuary",
      ],
      out,
      platform: "linux",
      currentUser: "ignored",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("User=svc");
    expect(out.text()).toContain("SANCTUARY_STORAGE_PATH=/srv/sanctuary");
    expect(out.text()).toContain("ExecStart=/opt/bin/sanctuary dashboard --no-confirm");
  });

  it("rejects unknown generate subcommands", async () => {
    const err = new Capture();
    const code = await runGenerateCommand({ argv: ["launchd"], err });
    expect(code).toBe(2);
    expect(err.text()).toContain("Unknown generate command: launchd");
  });

  it("prints systemd help without templating", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({ argv: ["systemd", "--help"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary generate systemd");
    expect(out.text()).not.toContain("[Service]");
  });
});

/**
 * Defect B1 (register 2026-08-05): on any installed package the generated unit
 * carried `ExecStart=/usr/local/bin/node dashboard --no-confirm`, i.e. the node
 * binary with no script. systemd starts that and node exits immediately.
 */
describe("generate systemd emits a startable ExecStart", () => {
  const EXEC_START = /^ExecStart=(\S+) (\S+) dashboard --no-confirm$/m;

  it("names an interpreter AND a CLI script, never the interpreter alone", () => {
    // The pre-fix output was `ExecStart=<node> dashboard --no-confirm`: the
    // node binary with no script. Asserted through renderSystemdUnit with a
    // built-package script path, because that is the layout the default
    // ExecStart is composed for.
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: "/home/svc/.sanctuary",
      binary: "/usr/local/bin/node",
      scriptPath: "/usr/local/lib/node_modules/pkg/dist/cli.js",
      platform: "linux",
    });
    const match = EXEC_START.exec(unit);
    expect(match, `no two-token ExecStart in:\n${unit}`).not.toBeNull();
    const [, interpreter, script] = match!;
    expect(interpreter).toMatch(/^\//);
    expect(script).toMatch(/[/\\]cli\.(js|cjs|mjs)$/);
  });

  it("refuses the default ExecStart when run from a source checkout", async () => {
    // This module is a .ts under vitest, so `sanctuary generate systemd` with
    // no --binary takes the refusal branch here every run. The previous round
    // asserted the unrunnable `ExecStart=<node> .../src/cli.ts` as expected.
    const out = new Capture();
    const err = new Capture();
    const code = await runGenerateCommand({
      argv: ["systemd"],
      out,
      err,
      platform: "linux",
      currentUser: "svc",
      homeDir: "/home/svc",
    });
    expect(code).toBe(2);
    expect(out.text(), "a refused generate must emit no unit at all").toBe("");
    expect(err.text()).toContain("plain node cannot execute");
    expect(err.text()).toContain("--binary");
  });

  it("resolves the CLI entry for every JavaScript layout the CLI ships in", () => {
    // Bundled install: generate.ts is inlined into dist/cli.js, so this module
    // IS the entry. This is the layout the pre-fix probe missed entirely.
    expect(resolveCliScriptPath("/usr/local/lib/node_modules/pkg/dist/cli.js")).toEqual({
      scriptPath: "/usr/local/lib/node_modules/pkg/dist/cli.js",
    });
    // Unbundled dist, the only layout the pre-fix probe handled.
    expect(resolveCliScriptPath("/opt/pkg/dist/cli/generate.js")).toEqual({
      scriptPath: "/opt/pkg/dist/cli.js",
    });
    // Library entry a consumer may call through.
    expect(resolveCliScriptPath("/opt/pkg/dist/index.js")).toEqual({
      scriptPath: "/opt/pkg/dist/cli.js",
    });
  });

  it("refuses the source-tree-under-tsx layout instead of emitting a dead unit", () => {
    // Gate finding P1b: this used to resolve to /repo/server/src/cli.ts and be
    // rendered as `ExecStart=<node> /repo/server/src/cli.ts`, which plain node
    // cannot execute, so the unit failed at every start. The refusal has to
    // name the reason; a bare "unsupported" would leave the operator guessing.
    const resolution = resolveCliScriptPath("/repo/server/src/cli/generate.ts");
    expect("error" in resolution, "a .ts entry must not be handed to systemd").toBe(true);
    expect(resolution).toEqual({
      error: expect.stringContaining("plain node cannot execute"),
    });
    expect(resolution).toEqual({ error: expect.stringContaining("--binary") });
  });

  it("refuses to render a unit whose script node cannot execute", () => {
    // Last gate before operator-installed text: renderSystemdUnit is exported,
    // so it cannot trust its caller to have run resolveCliScriptPath.
    expect(() =>
      renderSystemdUnit({
        user: "svc",
        stateDir: "/var/lib/sanctuary",
        binary: "/usr/bin/node",
        scriptPath: "/repo/server/src/cli.ts",
        platform: "linux",
      }),
    ).toThrow(/plain node can execute/);
  });

  it("takes an operator-supplied --binary verbatim", async () => {
    const out = new Capture();
    await runGenerateCommand({
      argv: ["systemd", "--binary", "/opt/bin/sanctuary", "--state-dir", "/srv/s"],
      out,
      platform: "linux",
      currentUser: "svc",
    });
    expect(out.text()).toContain("ExecStart=/opt/bin/sanctuary dashboard --no-confirm");
  });
});

/**
 * Defect B2 (register 2026-08-05): the generator emitted
 * `Environment=SANCTUARY_STORAGE_PATH=~/.sanctuary`. systemd does not expand
 * `~`, so the unit pointed at a literal `~` directory.
 */
describe("generate systemd never emits a tilde", () => {
  it("expands the default state dir to an absolute path", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({
      // --binary because this test runs from the source tree, where the
      // default ExecStart is refused (see the source-checkout test above).
      argv: ["systemd", "--binary", "/usr/local/bin/sanctuary"],
      out,
      platform: "linux",
      currentUser: "svc",
      homeDir: "/home/svc",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      "Environment=SANCTUARY_STORAGE_PATH=/home/svc/.sanctuary",
    );
    expect(out.text(), "no tilde may survive into the unit").not.toContain("~");
  });

  it("refuses a tilde state dir for a service user it cannot resolve", async () => {
    const out = new Capture();
    const err = new Capture();
    const code = await runGenerateCommand({
      argv: ["systemd", "--user", "svc-sanctuary", "--binary", "/usr/local/bin/sanctuary"],
      out,
      err,
      platform: "linux",
      currentUser: "erik",
      homeDir: "/home/erik",
    });
    expect(code).toBe(2);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("systemd does not expand ~");
    expect(err.text()).toContain("--state-dir /home/svc-sanctuary/.sanctuary");
  });

  it("refuses an explicit relative or tilde-user state dir", () => {
    const shared = { user: "svc", currentUser: "svc", home: "/home/svc" };
    expect(resolveSystemdStateDir({ ...shared, raw: "state" })).toEqual({
      error: expect.stringContaining("must be an absolute path"),
    });
    expect(resolveSystemdStateDir({ ...shared, raw: "~other/.sanctuary" })).toEqual({
      error: expect.stringContaining("must be an absolute path"),
    });
    expect(resolveSystemdStateDir({ ...shared, raw: "~/.sanctuary" })).toEqual({
      stateDir: "/home/svc/.sanctuary",
    });
    expect(resolveSystemdStateDir({ ...shared, raw: "/var/lib/sanctuary" })).toEqual({
      stateDir: "/var/lib/sanctuary",
    });
  });

  it("refuses to render a unit with a non-absolute state dir", () => {
    expect(() =>
      renderSystemdUnit({
        user: "svc",
        stateDir: "~/.sanctuary",
        binary: "/usr/local/bin/sanctuary",
        platform: "linux",
      }),
    ).toThrow(/must be absolute/);
  });
});

/**
 * Gate finding P2b: `resolveSystemdStateDir` accepts any absolute path,
 * including one with a space, but the unit interpolated it raw. systemd splits
 * `Environment=` on whitespace, so `/var/lib/Sanctuary Test` set the variable
 * to `/var/lib/Sanctuary` and the service ran against a fortress the operator
 * never named -- the same silently-wrong-directory shape as the tilde defect.
 */
describe("generate systemd quotes operator values for systemd, not for a shell", () => {
  const SPACED = "/var/lib/Sanctuary Test";

  it("accepts a space-containing state dir and quotes the whole assignment", () => {
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: SPACED,
      binary: "/usr/local/bin/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain(`Environment="SANCTUARY_STORAGE_PATH=${SPACED}"`);
    // The raw, unquoted form is the defect. Assert it is gone, not merely
    // that the quoted form is present: a line carrying both would pass the
    // check above and still truncate.
    expect(unit).not.toContain(`Environment=SANCTUARY_STORAGE_PATH=${SPACED}`);
  });

  it("survives the CLI path, not just the renderer", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({
      argv: ["systemd", "--state-dir", SPACED, "--binary", "/usr/local/bin/sanctuary"],
      out,
      platform: "linux",
      currentUser: "svc",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(`Environment="SANCTUARY_STORAGE_PATH=${SPACED}"`);
  });

  it("escapes a percent, which systemd reads as a specifier anywhere in the file", () => {
    const unit = renderSystemdUnit({
      user: "svc",
      // %i is systemd's instance-name specifier; left raw it is substituted
      // before exec and the service reads a different directory.
      stateDir: "/var/lib/%i-sanctuary",
      binary: "/opt/bin/%i-launcher",
      platform: "linux",
    });
    expect(unit).toContain('Environment="SANCTUARY_STORAGE_PATH=/var/lib/%%i-sanctuary"');
    expect(unit).toContain('ExecStart="/opt/bin/%%i-launcher" dashboard --no-confirm');
  });

  it("escapes a dollar on the command line, which systemd expands before exec", () => {
    // systemd.service(5) "Command Lines": `${FOO}` and `$FOO` are substituted
    // in ExecStart, quoted or not, and `$$` is the only literal dollar. Left
    // raw, `/opt/${SANCTUARY_BIN}/sanctuary` becomes `/opt//sanctuary` at
    // start time because the variable is unset, and the unit dies with a bare
    // status=203/EXEC that names no path.
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: "/var/lib/sanctuary",
      binary: "/opt/${SANCTUARY_BIN}/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain(
      'ExecStart="/opt/$${SANCTUARY_BIN}/sanctuary" dashboard --no-confirm',
    );
    // The unescaped form is the defect; a line carrying both would satisfy the
    // assertion above and still be substituted away.
    expect(unit).not.toContain("ExecStart=/opt/${SANCTUARY_BIN}/sanctuary");
  });

  it("escapes a dollar in the interpreter AND the script path", () => {
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: "/var/lib/sanctuary",
      binary: "/opt/$NODE_HOME/bin/node",
      scriptPath: "/opt/$APP_HOME/dist/cli.js",
      platform: "linux",
    });
    expect(unit).toContain(
      'ExecStart="/opt/$$NODE_HOME/bin/node" "/opt/$$APP_HOME/dist/cli.js" dashboard --no-confirm',
    );
  });

  it("survives the CLI path with a dollar in --binary", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({
      argv: [
        "systemd",
        "--state-dir",
        "/var/lib/sanctuary",
        "--binary",
        "/opt/$SANCTUARY_BIN/sanctuary",
      ],
      out,
      platform: "linux",
      currentUser: "svc",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      'ExecStart="/opt/$$SANCTUARY_BIN/sanctuary" dashboard --no-confirm',
    );
  });

  it("leaves a dollar in Environment= alone, where systemd does not expand it", () => {
    // systemd.exec(5) Environment=: "The $ character has no special meaning."
    // Doubling it here would put a second literal `$` into the value the
    // service reads, which is the mirror-image defect of the ExecStart case
    // above and equally invisible in the emitted text.
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: "/var/lib/$sanctuary",
      binary: "/usr/local/bin/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain("Environment=SANCTUARY_STORAGE_PATH=/var/lib/$sanctuary");
    expect(unit).not.toContain("$$sanctuary");
  });

  it("escapes quotes and backslashes with systemd's rules, not the shell's", () => {
    const unit = renderSystemdUnit({
      user: "svc",
      stateDir: '/var/lib/od"d\\path',
      binary: "/usr/local/bin/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain(
      'Environment="SANCTUARY_STORAGE_PATH=/var/lib/od\\"d\\\\path"',
    );
    // The shell idiom for embedding a quote has no meaning to systemd.
    expect(unit).not.toContain("'\\''");
  });

  it("refuses a newline rather than pretending quoting can hold one", () => {
    for (const [label, opts] of [
      ["stateDir", { stateDir: "/var/lib/s\nExecStart=/bin/sh -c evil" }],
      ["user", { user: "svc\nExecStart=/bin/sh -c evil" }],
      ["binary", { binary: "/usr/local/bin/s\nExecStart=/bin/sh" }],
    ] as Array<[string, Partial<Parameters<typeof renderSystemdUnit>[0]>]>) {
      expect(
        () =>
          renderSystemdUnit({
            user: "svc",
            stateDir: "/var/lib/sanctuary",
            binary: "/usr/local/bin/sanctuary",
            platform: "linux",
            ...opts,
          }),
        `${label} must not be able to add a directive`,
      ).toThrow(/control character or newline/);
    }
  });

  it("refuses a user name with whitespace, which systemd's User= rejects", () => {
    expect(() =>
      renderSystemdUnit({
        user: "svc sanctuary",
        stateDir: "/var/lib/sanctuary",
        binary: "/usr/local/bin/sanctuary",
        platform: "linux",
      }),
    ).toThrow(/single account name/);
  });
});
