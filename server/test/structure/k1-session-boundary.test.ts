// fail-before-exempt: This change documents an absent session authorization policy; removing a tautological check cannot create a pre-fix behavioural refusal.
import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
it("terminal device and foreground binding make no session authorization claim",()=>{
  const source=readFileSync("../castle-wall-daemon/src/business_profile/signer_peer.rs","utf8");
  const terminal=source.slice(source.indexOf("pub fn tty_check"),source.indexOf("pub fn kernel_probe"));
  expect(terminal).toContain("TIOCGDEV");expect(terminal).toContain("FOREGROUND_OFFSET");
  expect(terminal).not.toContain("getsid");expect(terminal).not.toContain("SESSION_OFFSET");
});
