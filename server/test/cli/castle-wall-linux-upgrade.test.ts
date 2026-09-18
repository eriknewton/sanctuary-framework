import { describe, expect, it, vi } from "vitest";
import {
  parseFixedUnitEnvironment,
  parseFixedUnitShow,
  parseLinuxUpgradeArgv,
  runCastleWallLinuxUpgrade,
} from "../../src/cli/castle-wall-linux-upgrade.js";

const FORTRESS = "a1b2c3d4e5f60718";
const UID = "1001";
const EXEC = "/usr/local/libexec/sanctuary/castle-wall-daemon";
const FIRST_PRE = "/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/\${SANCTUARY_FORTRESS_ID}";
const SECOND_PRE = "/usr/bin/install -d -o root -g sanctuary -m 0700 /run/sanctuary/locks";
const metadata = "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=exited ; status=0/SUCCESS";
const validShow = [
  "LoadState=loaded",
  "FragmentPath=/etc/systemd/system/sanctuary-castle-wall.service",
  "DropInPaths=",
  "NeedDaemonReload=no",
  "EnvironmentFiles=/etc/sanctuary/castle-wall.env (ignore_errors=no)",
  "Environment=",
  `ExecStart={ path=${EXEC} ; argv[]=${EXEC} --fortress-id \${SANCTUARY_FORTRESS_ID} --trusted-service-uid \${SANCTUARY_TRUSTED_SERVICE_UID} ; ignore_errors=no ; ${metadata} }`,
  `ExecStartPre={ path=/usr/bin/install ; argv[]=${FIRST_PRE} ; ignore_errors=no ; ${metadata} } { path=/usr/bin/install ; argv[]=${SECOND_PRE} ; ignore_errors=no ; ${metadata} }`,
  `ExecStartPreEx={ path=/usr/bin/install ; argv[]=${FIRST_PRE} ; flags= ; ${metadata} } { path=/usr/bin/install ; argv[]=${SECOND_PRE} ; flags=privileged ; ${metadata} }`,
  "ExecCondition=", "ExecConditionEx=", "ExecStartPost=", "ExecStartPostEx=",
  "ExecStop=", "ExecStopEx=", "ExecStopPost=", "ExecStopPostEx=",
].join("\n") + "\n";

describe("fixed privileged Linux upgrade boundary", () => {
  it("accepts only the two plain root-unit identity assignments", () => {
    expect(parseFixedUnitEnvironment(`SANCTUARY_FORTRESS_ID=${FORTRESS}\nSANCTUARY_TRUSTED_SERVICE_UID=${UID}\n`))
      .toEqual({ fortressId: FORTRESS, trustedServiceUid: UID });
    for (const bad of [
      `SANCTUARY_FORTRESS_ID="${FORTRESS}"\nSANCTUARY_TRUSTED_SERVICE_UID=${UID}\n`,
      `SANCTUARY_FORTRESS_ID=${FORTRESS}\nSANCTUARY_FORTRESS_ID=${FORTRESS}\n`,
      `SANCTUARY_FORTRESS_ID=${FORTRESS}\nSANCTUARY_TRUSTED_SERVICE_UID=0\n`,
      `SANCTUARY_FORTRESS_ID=${FORTRESS}\nSANCTUARY_TRUSTED_SERVICE_UID=${UID}\nEXTRA=1\n`,
    ]) expect(() => parseFixedUnitEnvironment(bad)).toThrow(/refused/);
  });

  it("binds the loaded effective unit to the fixed fragment, env and ExecStart", () => {
    expect(() => parseFixedUnitShow(validShow, FORTRESS, UID)).not.toThrow();
    expect(() => parseFixedUnitShow(validShow.replace("DropInPaths=", "DropInPaths=/etc/systemd/system/x.conf"), FORTRESS, UID)).toThrow(/fixed supported unit/);
    expect(() => parseFixedUnitShow(validShow.replace("NeedDaemonReload=no", "NeedDaemonReload=yes"), FORTRESS, UID)).toThrow(/fixed supported unit/);
    expect(() => parseFixedUnitShow(validShow.replace("Environment=", "Environment=SANCTUARY_FORTRESS_ID=evil"), FORTRESS, UID)).toThrow(/fixed supported unit/);
    expect(() => parseFixedUnitShow(validShow.replace(`path=${EXEC}`, "path=/tmp/evil"), FORTRESS, UID)).toThrow(/ExecStart/);
    expect(() => parseFixedUnitShow(validShow.replace(SECOND_PRE, "/tmp/evil"), FORTRESS, UID)).toThrow(/ExecStartPre/);
    expect(() => parseFixedUnitShow(validShow.replace("flags=privileged", "flags="), FORTRESS, UID)).toThrow(/ExecStartPreEx/);
    for (const hook of ["ExecCondition", "ExecConditionEx", "ExecStartPost", "ExecStartPostEx",
      "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx"]) {
      expect(() => parseFixedUnitShow(validShow.replace(`${hook}=\n`, `${hook}={ path=/tmp/evil }\n`), FORTRESS, UID))
        .toThrow(new RegExp(hook));
    }
    expect(() => parseFixedUnitShow(`${validShow}LoadState=loaded\n`, FORTRESS, UID)).toThrow(/duplicate/);
    expect(() => parseFixedUnitShow(validShow.replace("LoadState=loaded", "SomethingElse=loaded"), FORTRESS, UID)).toThrow(/unknown/);
  });

  it("refuses user-selected target, unit and malformed candidate paths", () => {
    expect(parseLinuxUpgradeArgv(["--route", "disarm", "--candidate", "/root/new-daemon"]))
      .toEqual({ route: "disarm", candidate: "/root/new-daemon" });
    for (const args of [
      ["--route", "reboot", "--candidate", "relative"],
      ["--route", "disarm", "--candidate", "/root/../tmp/daemon"],
      ["--route", "disarm", "--candidate", "/root/new\u0000bad"],
      ["--route", "disarm", "--candidate", "/root/new\nbad"],
      ["--route", "disarm", "--candidate", "/root/new\u007f"],
      ["--route", "disarm", "--candidate", EXEC],
      ["--route", "disarm", "--candidate", "/root/new", "--unit", "other.service"],
      ["--fortress-id", FORTRESS, "--route", "disarm"],
    ]) expect(() => parseLinuxUpgradeArgv(args)).toThrow(/usage/);
  });

  it("refuses an untrusted checkout before any host query or stage", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      expect(await runCastleWallLinuxUpgrade(["--route", "disarm", "--candidate", "/root/new-daemon"]))
        .toBe(1);
      expect(error.mock.calls.join(" ")).toMatch(/trusted installed CLI/);
    } finally {
      error.mockRestore();
    }
  });
});
