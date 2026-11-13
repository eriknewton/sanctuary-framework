// fail-before-exempt: New drain production reachability and debug/release artifact witnesses read native sources and harness binaries.
import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { nativeBinary } from "../fixtures/k1-service.js";

// These item boundaries are lexical, retaining imports while excluding test-only item bodies.
function mask(source: string): string {
  return source.replace(/r(#+)"[\s\S]*?"\1|"(?:\\.|[^"\\])*"|b?'(?:\\.|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, value => value.replace(/[^\n]/g, " "));
}
function closing(source: string, start: number): number {
  const code = mask(source);
  let depth = 0;
  for (let i = start; i < code.length; i++) {
    if (code[i] === "{") depth++;
    if (code[i] === "}" && --depth === 0) return i + 1;
  }
  throw new Error("unresolved item boundary");
}
function production(source: string): string {
  // Match strings before comments, so a URL or raw string cannot hide reached code.
  source = source.replace(/r(#+)"[\s\S]*?"\1|"(?:\\.|[^"\\])*"|b?'(?:\\.|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    value => value.startsWith("//") || value.startsWith("/*") ? value.replace(/[^\n]/g, " ") : value);
  for (;;) {
    const match = /#\[cfg\((?:test|feature\s*=\s*"test-isolation")\)\]/.exec(source);
    if (!match) break;
    const tail = source.slice(match.index + match[0].length);
    const brace = tail.indexOf("{");
    const semi = tail.indexOf(";");
    // Field-level gates end at their comma, while complete items end at a brace or semicolon.
    const field = /^\s*(?:pub\s+)?\w+\s*:\s*[^\n]+,/.exec(tail);
    const end = field ? match.index + match[0].length + field[0].length
      : semi >= 0 && (brace < 0 || semi < brace) ? match.index + match[0].length + semi + 1
        : closing(source, match.index + match[0].length + brace);
    source = source.slice(0, match.index) + source.slice(end);
  }
  return source;
}
function items(source: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const match of mask(source).matchAll(/\bfn\s+(\w+)\s*(?:<[^{}]*>)?\s*\(/g)) {
    let signature = match.index! + match[0].length;
    let parentheses = 1;
    while (parentheses && signature < source.length) {
      if (source[signature] === "(") parentheses++;
      if (source[signature] === ")") parentheses--;
      signature++;
    }
    const start = source.indexOf("{", signature);
    const semi = source.indexOf(";", signature);
    if (semi >= 0 && semi < start) continue;
    if (start < 0) throw new Error("unresolved function");
    const end = closing(source, start);
    result.set(match[1], [...(result.get(match[1]) ?? []), source.slice(match.index, end)]);
  }
  return result;
}
const forbidden = /\b(?:SigningKey|signer_client|BusinessSignerClient|ClientSignerPort|Command|spawn_worker|launch_worker|sign_record|sign_preimage)\b|\.(?:sign|sign_prehash|sign_digest)\s*\(/;
function reachable(source: string, roots: string[]): string[] {
  const definitions = items(source);
  const localTypes = new Set([...mask(source).matchAll(/\b(?:struct|enum)\s+(\w+)/g)].map(match => match[1]));
  const aliases = new Map<string, string>();
  for (const match of source.matchAll(/\b(\w+)\s+as\s+(\w+)/g)) aliases.set(match[2], match[1]);
  for (const match of source.matchAll(/\btype\s+(\w+)\s*=\s*(?:\w+::)*(\w+)\s*;/g)) aliases.set(match[1], match[2]);
  const seen = new Set<string>();
  const pending = [...roots];
  while (pending.length) {
    const name = pending.pop()!;
    if (seen.has(name)) continue;
    const bodies = definitions.get(name);
    if (!bodies) throw new Error(`unresolved local edge: ${name}`);
    seen.add(name);
    for (let body of bodies) {
      for (const [alias, original] of aliases) body = body.replace(new RegExp(`\\b${alias}\\b`, "g"), original);
      if (forbidden.test(body)) throw new Error(`forbidden production item: ${name}`);
      const known = new Set(["Self", "std", "io", "libc", "hex", "serde_json", "Arc", "Vec", "String", "Box", "BTreeSet", "CString", "File", "OpenOptions", "Path", "PathBuf", "Sha256", "Authority", "Phase", "PublishOutcome", "Binding", "BusTarget", "Classifier", "Deadline", "DescriptorReader", "Diagnostics", "Directory", "EventSink", "HeldConfig", "HeldRoot", "StateLock", "Store", "StoreFaults", "WallMainBinding", "Refusal", "Operation", "Value", "signer_peer", "writer_peer", "drain_store", "anchor", "protocol", "activation_anchor", "drain_protocol", "drain_service"]);
      for (const edge of mask(body).matchAll(/\b((?:\w+::)+\w+)\s*(?:\(|\{)/g)) {
        const path = edge[1];
        const narrow = ["crate::smb::jcs::encode", "super::verify_role", "records::decode", "records::join_commitment", "writer_protocol::decode_envelope", "signer_service::canonical"].includes(path);
        if (!narrow && !known.has(path.split("::")[0])) throw new Error(`unresolved qualified edge: ${path}`);
      }

      for (const call of mask(body).matchAll(/\b(\w+)\s*(?:!|::\s*<[^;{}]*>)?\s*\(/g)) {
        if (/URL_SAFE_NO_PAD\s*\.\s*$/.test(body.slice(0, call.index))) continue;
        const qualifier = body.slice(0, call.index).match(/([\w:]+)::$/)?.[1];
        if (qualifier && qualifier !== "Self" && !localTypes.has(qualifier)) continue;
        if (definitions.has(call[1]) && !seen.has(call[1])) pending.push(call[1]);
        else if (!definitions.has(call[1]) && /\.\s*$/.test(body.slice(0, call.index))) {
          // Standard container/IO/metadata leaves and the separately audited peer/store/notifier methods.
          const methods = new Set("all and_then any append as_bytes as_mut_ptr as_os_str as_ptr as_raw_fd as_ref as_str as_u64 bytes cgroup chain check checked_add checked_mul clone cloned collect components concat contains copied copy create custom_flags dev emit encode ends_with enumerate filter find first get ino insert into into_bytes is_absolute is_ascii_digit is_dir is_empty is_err is_file is_none is_ok is_some is_some_and iter join kind len live map map_err map_or map_or_else mark_uncertain matches metadata mode mtime mtime_nsec nlink notify observe ok ok_or open parent publish_original publish_record push raw_os_error read read_to_end reconcile record remove rev saturating_add skip take to_owned try_into uid".split(" "));
          if (!methods.has(call[1])) throw new Error(`unresolved method edge: ${call[1]}`);
        }
        else if (!definitions.has(call[1]) && !qualifier && !/\.\s*$/.test(body.slice(0, call.index))) {
          const leaves = new Set(["in", "return", "let", "unsafe", "cfg", "if", "while", "for", "match", "Some", "Ok", "Err", "drop", "format", "matches", "json", "write", "writeln", "eprintln", "clock", "setup", "refused"]);
          if (!leaves.has(call[1])) throw new Error(`unresolved free edge: ${call[1]}`);
        }
      }
    }
  }
  return [...seen].sort();
}
it("reachability follows local helpers and aliases without promoting unrelated items", () => {
  expect(reachable("fn entry() { envelope(); } fn envelope() {} fn unrelated() { SigningKey::from_bytes(); }", ["entry"])).toEqual(["entry", "envelope"]);
  for (const imported of ["use ed25519_dalek::SigningKey as Hidden;", "use ed25519_dalek::{SigningKey as Hidden};", "type Hidden = ed25519_dalek::SigningKey;"]) {
    expect(() => reachable(`${imported} fn entry() { helper(); } fn helper() { Hidden::from_bytes(); }`, ["entry"])).toThrow("forbidden production item");
  }
  for (const literal of ['"https://local"', 'r#"https://local"#']) {
    expect(() => reachable(production(`fn entry() { let url = ${literal}; SigningKey::from_bytes(); }`), ["entry"])).toThrow("forbidden production item");
  }
  expect(() => reachable("fn unrelated() {}", ["entry"])).toThrow("unresolved");
  expect(() => reachable("fn entry() { unknown_module::helper(); }", ["entry"])).toThrow("unresolved");
  expect(() => reachable("fn entry() { missing_helper(); }", ["entry"])).toThrow("unresolved");
  expect(() => reachable("fn entry() { value.unknown_method(); }", ["entry"])).toThrow("unresolved");
});
it("drain production items have no key constructor, signer client or worker launcher", () => {
  const binary = production(readFileSync("../castle-wall-daemon/src/bin/sanctuary-business-drain.rs", "utf8"));
  expect(reachable(binary, ["main"])).toEqual(["execute", "main"]);
  const source = production(readFileSync("../castle-wall-daemon/src/business_profile/drain_service.rs", "utf8"));
  let graph: string[] = [];
  let failure = "";
  try { graph = reachable(source, ["production", "run", "request", "process", "verify_commit", "verify_original"]); }
  catch (error) { failure = (error as Error).message; }
  expect(failure).not.toMatch(/forbidden production item/);
  expect(failure, "production traversal must succeed; forbidden production item identifies a key-construction kill").toBe("");
  for (const item of ["descriptor", "capture", "revalidate", "prepare_socket", "publish"]) expect(graph).toContain(item);
  const writer = production(readFileSync("../castle-wall-daemon/src/business_profile/writer_protocol.rs", "utf8"));
  const pure = reachable(writer, ["decode_envelope", "envelope", "envelope_fits"]);
  expect(pure).not.toContain("from_signer");
  expect(source).not.toMatch(/records::(?:advance|verify)\s*\(/);
  // Conservatively audit complete peer, bus and store item sets while keeping the writer parser boundary item-specific.
  for (const name of ["frame", "drain_protocol", "drain_store", "activation_anchor", "signer_peer", "writer_peer", "writer_peer/bus", "records_schema"]) {
    const helper = production(readFileSync(`../castle-wall-daemon/src/business_profile/${name}.rs`, "utf8"));
    for (const body of items(helper).values()) for (const item of body) expect(item).not.toMatch(forbidden);
  }
  const selected: Record<string, string[]> = {
    "records": ["decode", "join_commitment"], "signer_service": ["canonical"],
    "mod": ["verify_role", "strict_verify", "strict_encoding_profile", "strict_point", "role_kid", "kid_from_body"],
    "signer_watchdog": ["boottime_ns"], "custody": ["read_pinned", "refused"], "writer_service": ["notify"],
  };
  for (const [module, names] of Object.entries(selected)) {
    const helper = items(production(readFileSync(`../castle-wall-daemon/src/business_profile/${module}.rs`, "utf8")));
    for (const name of names) {
      expect(helper.has(name), `unresolved external edge ${module}::${name}`).toBe(true);
      for (const item of helper.get(name)!) expect(item).not.toMatch(forbidden);
    }
  }

});
it.skipIf(process.platform !== "linux")("drain debug seam is present and release rejects arguments before production roots", () => {
  const debug = readFileSync(nativeBinary("debug", "drain"));
  const releasePath = nativeBinary("release", "drain");
  const release = readFileSync(releasePath);
  for (const marker of ["--test-root", "sanctuary-drain-test-seam-v1"]) {
    expect(debug.includes(Buffer.from(marker))).toBe(true);
    expect(release.includes(Buffer.from(marker))).toBe(false);
  }
  const result = spawnSync(releasePath, ["--test-root", "/no-drain-fixture"], { encoding: "utf8", timeout: 2000, env: { VITEST: "true" } });
  expect(result.status).toBe(1);
  expect(result.stderr).toBe("K1_REFUSED\n");
  expect(result.stdout).toBe("");
});
