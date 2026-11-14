#!/usr/bin/env python3
"""Fail when the read-only guard's bounded paths drift from daemon/unit source."""

import ast
import hashlib
import re
import sys
from pathlib import Path


# Exact byte identity of daemon nft source at repository baseline
# 17d251f50514a885d0cd9666e363d19dbc963574. This source pin is not a Rust
# parser or a claim of whole-file review. Any edit requires source review and
# an explicit pin refresh before a package can be asserted.
# Refreshed for PR-3a (2026-09-18): the only nftables.rs change since the baseline above is
# four `else { return None; }` arms of recognized_net_json rewritten with the `?` operator to
# satisfy the clippy gate; two independent-family source reviews accepted it as
# semantics-preserving before this pin moved. The guard constants it mirrors are unchanged.
# Refreshed for PR-3b slice A (2026-09-20, after code-gate rounds 3 to 5; the last move is a doc-comment correction only): nftables.rs gained the inventory-returning
# binding-set helper beside verify_owned_castle_table (the set rule shared by acquisition,
# readback and health), the shared `uid-<U>` agent-id derivation, and doc comments describing
# the frozen-cell expectation; the rule grammar, the inventory parser and its enum variants,
# the receipt mint and the net script are byte-unchanged. Two independent-family code gates
# review the slice before this pin moves. The guard constants it mirrors are unchanged.
# Refreshed for the single-uid listing fix (2026-09-24): the deny-all net recognizer and the
# live-binding reader now share one right-hand-side extractor that accepts the array form and
# the bare-scalar form nft emits for a one-member skuid set, and refuses every other shape.
# Rule grammar, the owned-table parser, the receipt mint and the net script are byte-unchanged.
# Claude and Grok code gates (three rounds, final dry) reviewed it before this pin moved.
# The guard constants it mirrors are unchanged.
# Refreshed for C2a2 (2026-09-27, builder refresh; the slice's two-family code gate reviews
# it before merge): nftables.rs gained the pid-safe bounded wait (pidfd kill, bounded
# post-kill waits, parked children), the per-origin child slot table, an NftOrigin first
# argument at every run_nft/run_nft_stdin call site, the NFT_INVOCATION_SITES inventory, the
# test-isolation --test-nft-binary seam, and tests. The rule grammar, the owned-table parser,
# the receipt mint and the net script are byte-unchanged. The guard constants it mirrors are
# unchanged.
# Refreshed for the C2a2 code-gate fix round 1 (2026-09-27): run_nft_stdin's stdin feed moved
# into feed_stdin_and_wait_with, whose write-failure path kills and joins or parks the child
# through its slot instead of returning past it; T12 and the child tests were updated. The
# rule grammar, the owned-table parser, the receipt mint and the net script are byte-unchanged.
# Refreshed for the round-2 polish (2026-09-27): ChildSlotTable::park refuses an id that is
# not in flight, and the waiter-spawn failure path recovers a poisoned cell instead of
# dropping the child. The rule grammar, parser, receipt mint and net script are unchanged.
# Refreshed for C2a2b (2026-09-27): the only nftables.rs change is a doc-comment cross-file
# pin on CastleTableOwnership ("must match JournalActivation in src/ownership_journal.rs").
# No code line changed; the rule grammar, parser, receipt mint and net script are unchanged.
# Refreshed for Linux slice B (2026-09-28, builder refresh, on top of C2a2b; the slice's two-family code gate
# reviews it before merge): nftables.rs gained the extracted set rule binding_set_rule (with
# owned_binding_inventory) now called by both owned_table_binding_set_from_json and the new
# pure agent_start_gate_verdict with its AgentStartTableVerdict, two separate re-exports
# (list_owned_castle_table_json_for_binding_set under target_os linux, NFT_CALL_WORST_CASE
# under test and linux), the two doc-comment amendments naming the two provenances of
# ExpectedAgentBinding::Confined (its variant doc and the seal doc), and TB5 tests. The rule
# grammar, the owned-table parser and its enum variants, the receipt mint and the net script
# are byte-unchanged. The guard constants it mirrors are unchanged.
# Refreshed for C2a3 after the slice-B rebase: only the NFT_CALL_WORST_CASE
# comment and its TD2n equality test changed. The test pins the 2700 ms nft
# bound against WATCHDOG_HOOK_NFT_WAIT; the rule grammar, parser, receipt mint,
# and net script remain unchanged.
# Refreshed for confined agent-id scope parsing (2026-10-11): nftables.rs gained
# CONFINED_AGENT_ID_FORM, parse_confined_agent_id, the cfg widening for
# confined_agent_id, and doc wording distinguishing the confined id from the
# audit evidence subject. The rule grammar, the owned-table parser and its enum
# variants, the receipt mint and the net script are byte-unchanged. The guard
# constants it mirrors are unchanged.
NFTABLES_SOURCE_SHA256 = "8c61c5fdd8e4c82595851b78812676f393782e567946910ceae72a844f802f17"


# The declared partition of the guard's path constants (every name in
# lifecycle-guard.py ending in _PATH or _ROOT). Must match the path constants
# in lifecycle-guard.py: each one is either SOURCE_MIRRORED (an `expected`
# entry below derives its value from daemon or unit source) or
# NOT_SOURCE_MIRRORED (with the reason no source constant exists). A new guard
# path constant in neither set refuses, which forces a decision.
SOURCE_MIRRORED = {
    "ENV_PATH", "DAEMON_PATH", "RUN_ROOT", "STATE_ROOT", "JOURNAL_PATH",
    "AUTH_KEY_PATH", "HOST_LOCK_PATH", "NFT_TABLE", "AGENT_UNIT_PATH",
}
NOT_SOURCE_MIRRORED = {
    "UNIT_PATH": "checked by the literal first-slice unit-path contract below",
    "IDENTITY_PATH": "a build output the package writes; no source constant to mirror",
    "STATUS_PATH": "dpkg-owned status database path; no source constant",
    "INFO_PATH": "dpkg-owned info directory path; no source constant",
}
PATH_SUFFIXES = ("_PATH", "_ROOT")


def fail(message):
    raise ValueError(message)


def one(pattern, text, label):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        fail(f"expected one parseable {label}; found {len(matches)}")
    return matches[0]


def exactly(pattern, text, label, count):
    """Plural sibling of one(): exactly `count` matches, in file order."""
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != count:
        fail(f"expected {count} parseable {label}; found {len(matches)}")
    return matches


def check_agent_unit(agent_unit, constants):
    # Must match the agent unit's BindsTo=/ExecStartPre= lines in
    # systemd/sanctuary-agent@.service and UNIT_NAME/DAEMON_PATH in
    # lifecycle-guard.py.
    binds = exactly(r"^BindsTo=(.+)$", agent_unit, "agent BindsTo", 1)[0].split()
    if binds != [constants.get("UNIT_NAME")]:
        fail(f"agent unit BindsTo= target differs from the guard's UNIT_NAME: {binds!r}")
    check, gate = exactly(r"^ExecStartPre=(.+)$", agent_unit, "agent ExecStartPre", 2)
    daemon = constants.get("DAEMON_PATH")
    if check.split()[0] != daemon:
        fail("agent credential-check ExecStartPre= path differs from DAEMON_PATH")
    # The gate is the `+` (full privileges) line: exactly one leading `+` is
    # required and stripped, so neither `++/usr/...` nor a missing prefix passes.
    if gate.split()[0] != "+" + daemon:
        fail("agent start-gate ExecStartPre= is not exactly '+' then DAEMON_PATH")


def check_partition(constants, expected):
    if set(expected) != SOURCE_MIRRORED:
        fail(f"SOURCE_MIRRORED differs from the expected mirror set: {sorted(set(expected) ^ SOURCE_MIRRORED)}")
    if SOURCE_MIRRORED & set(NOT_SOURCE_MIRRORED):
        fail("a path constant is declared both source-mirrored and not source-mirrored")
    guard_paths = {name for name in constants if name.endswith(PATH_SUFFIXES)}
    declared = {name for name in SOURCE_MIRRORED if name.endswith(PATH_SUFFIXES)} | set(NOT_SOURCE_MIRRORED)
    if guard_paths != declared:
        fail(f"guard path constants outside the declared partition: {sorted(guard_paths ^ declared)}")


def rust_tokens(text):
    """Strip comments and tokenize active Rust, retaining each literal as one token."""
    tokens = []
    i = 0
    while i < len(text):
        if not text[i].isascii():
            fail("non-ASCII Rust outside comments or literals")
        if text[i].isspace():
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        if text.startswith("/*", i):
            depth = 1
            i += 2
            while depth and i < len(text):
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                fail("unterminated Rust comment")
            continue
        raw = re.match(r'(?:br|cr|r)(#*)"', text[i:])
        if raw:
            end = text.find('"' + raw[1], i + raw.end())
            if end < 0:
                fail("unterminated Rust raw string")
            end += 1 + len(raw[1])
            tokens.append(text[i:end])
            i = end
            continue
        # A char has a closing quote; a lifetime such as 'a does not.
        literal = re.match(r"""(?:b|c)?"(?:\\[\s\S]|[^"\\])*"|b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[\s\S])|[^'\\\n])'""", text[i:])
        if literal:
            tokens.append(literal[0])
            i += literal.end()
            continue
        if re.match(r'(?:b|c)?"|b\x27', text[i:]):
            fail("unterminated Rust literal")
        if text[i] == "'":
            lifetime = re.match(r"'[A-Za-z_][A-Za-z_0-9]*", text[i:])
            previous = tokens[-1] if tokens else ""
            if not lifetime or (previous not in ("&", "<", ",", ":", "+", "break", "continue") and
                                not text[i + lifetime.end():].lstrip().startswith(":")):
                fail("unterminated Rust char literal")
            tokens.append(lifetime[0])
            i += lifetime.end()
            continue
        identifier = re.match(r"(?:r#)?[A-Za-z_][A-Za-z_0-9]*", text[i:])
        if identifier:
            tokens.append(identifier[0].removeprefix("r#"))
            i += identifier.end()
            continue
        tokens.append(text[i])
        i += 1
    return tokens


def rust_delimiters(tokens):
    """Pair token groups so patterns and function boundaries cannot bleed together."""
    pairs, parents, stack = {}, {}, []
    for i, token in enumerate(tokens):
        parents[i] = stack[-1] if stack else None
        if token in ("(", "[", "{"):
            stack.append(i)
        elif token in (")", "]", "}"):
            if not stack or tokens[stack[-1]] != {")": "(", "]": "[", "}": "{"}[token]:
                fail("unbalanced Rust delimiters")
            opening = stack.pop()
            pairs[opening], pairs[i] = i, opening
    if stack:
        fail("unterminated Rust group")
    return pairs, parents


def rust_bindings(tokens):
    """Return lexical declaration/pattern positions and named function extents."""
    pairs, parents = rust_delimiters(tokens)
    bindings, functions, closure_ends, arm_arrows = set(), [], set(), {}

    def until(start, stops):
        i = start
        while i < len(tokens):
            path_colon = tokens[i] == ":" and (tokens[i - 1:i] == [":"] or tokens[i + 1:i + 2] == [":"])
            if tokens[i] in stops and not path_colon:
                break
            i = pairs[i] + 1 if tokens[i] in ("(", "[", "{") else i + 1
        return i

    def parameters(start, end):
        # Types and return expressions are uses, not parameter patterns.
        while start < end:
            stop = min(until(start, {",", ":"}), end)
            bindings.update(range(start, stop))
            start = min(until(stop, {","}), end) + 1

    for i, token in enumerate(tokens):
        if token in ("const", "static", "struct", "enum", "union", "type", "fn", "mod", "trait"):
            name = i + 1
            if tokens[name:name + 1] == ["mut"]:
                name += 1
            bindings.add(name)
        elif token == "macro_rules" and tokens[i + 1:i + 2] == ["!"]:
            bindings.add(i + 2)
        elif token == "use":
            end = until(i + 1, {";"})
            bindings.update(j + 1 for j in range(i + 1, end) if tokens[j] == "as")
        elif token == "let":
            end = until(i + 1, {"=", ";"})
            bindings.update(range(i + 1, end))
        if token == "fn" and i + 2 < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", tokens[i + 1]):
            opening = i + 2
            # Generic bounds can themselves contain Fn(...) parameter groups.
            depth = 0
            while opening < len(tokens):
                current = tokens[opening]
                if depth == 0 and current in ("(", ";", "{"):
                    break
                depth += (current == "<") - (current == ">")
                opening += 1
            if opening >= len(tokens) or tokens[opening] != "(":
                fail("unsupported Rust function signature")
            closing = pairs[opening]
            parameters(opening + 1, closing)
            body = until(closing + 1, {"{", ";"})
            if body < len(tokens) and tokens[body] == "{":
                # The function's name binds in its enclosing scope; its parameters do not.
                functions.append((opening, body, pairs[body], tokens[i + 1]))
        if token == "|" and i not in closure_ends:
            previous = tokens[i - 1] if i else ""
            if (previous in ("=", "(", "[", ",", "{", ";", ":", "&", "!", "*", "return", "break", "move", "async") or
                    i - 1 in closure_ends or tokens[i - 2:i] == ["=", ">"]):
                end = until(i + 1, {"|", ";"})
                if end < len(tokens) and tokens[end] == "|":
                    closure_ends.add(end)
                    parameters(i + 1, end)
        if token == "=" and tokens[i + 1:i + 2] == [">"]:
            group = parents[i]
            if group is None or tokens[group] != "{":
                continue
            previous = arm_arrows.get(group)
            arm_arrows[group] = i
            start = group + 1 if previous is None else previous + 2
            if previous is not None:
                cursor = start
                while cursor < i:
                    if tokens[cursor] == ",":
                        start = cursor + 1
                    cursor = pairs[cursor] + 1 if tokens[cursor] in ("(", "[", "{") else cursor + 1
                if start == previous + 2:
                    # Block-valued arms can omit a comma. Skip their body and else branches.
                    cursor = until(start, {"{"})
                    while cursor < i and tokens[cursor] == "{":
                        cursor = pairs[cursor] + 1
                        if tokens[cursor:cursor + 1] == ["else"]:
                            cursor = until(cursor + 1, {"{"})
                    start = cursor
            # Names in the arm's guard or result expression are ordinary uses.
            end = min(until(start, {"if", "="}), i)
            bindings.update(range(start, end))
    return bindings, functions


def fortress_root(tokens, name, prefix):
    bindings, _ = rust_bindings(tokens)
    declarations = [i for i in sorted(bindings) if tokens[i:i + 1] == [name]]
    if len(declarations) != 1:
        fail(f"expected one {name} declaration of any kind; found {len(declarations)}")
    i = declarations[0]
    if tokens[max(0, i - 2):i + 5] != ["pub", "const", name, ":", "&", "str", "="]:
        fail(f"unexpected fortress root declaration: {name}")
    value = re.fullmatch('"(' + re.escape(prefix) + r'/[^"\n]+)"', "".join(tokens[i + 5:i + 6]))
    if not value or tokens[i + 6:i + 7] != [";"]:
        fail(f"unexpected fortress root value: {name}")
    return value[1]


def fortress_directory(tokens, name, root):
    derivation = ["let", name, "=", "PathBuf", ":", ":", "from", "(", root, ")",
                  ".", "join", "(", "&", "fortress_id", ")", ";"]
    bindings, functions = rust_bindings(tokens)
    pairs, _ = rust_delimiters(tokens)

    def owner(position):
        enclosing = [scope for scope in functions if scope[0] <= position <= scope[2]]
        return min(enclosing, key=lambda scope: scope[2] - scope[0]) if enclosing else None

    # Pin the shipping derivation's function; helpers may use the same local names.
    scopes = [scope for scope in functions if scope[3] == "defaults_for_fortress"]
    if len(scopes) != 1:
        fail("expected one defaults_for_fortress function")
    scope = scopes[0]
    derivations = []
    for i in range(len(tokens)):
        if owner(i) != scope or tokens[i:i + len(derivation)] != derivation:
            continue
        before = i - 1
        while before >= 0 and tokens[before] == "]" and tokens[pairs[before] - 1:pairs[before]] == ["#"]:
            before = pairs[before] - 2
        if before >= 0 and tokens[before] in (";", "{", "}"):
            derivations.append(i + 1)
    if len(derivations) != 1:
        fail(f"expected one fortress directory derivation: {name}; found {len(derivations)}")

    if [i for i in sorted(bindings) if tokens[i:i + 1] == [name] and owner(i) == scope] != derivations:
        fail(f"second fortress directory binding in derivation function: {name}")


def main():
    here = Path(__file__).resolve().parent
    crate = here.parent.parent
    guard = ast.parse((here / "lifecycle-guard.py").read_text())
    constants = {}
    for node in guard.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    unit = (crate / "systemd/sanctuary-castle-wall.service").read_text()
    agent_unit_file = crate / "systemd/sanctuary-agent@.service"
    agent_unit = agent_unit_file.read_text()
    config = (crate / "src/config.rs").read_text()
    journal = (crate / "src/ownership_journal.rs").read_text()
    lock = (crate / "src/runtime_lock.rs").read_text()
    nft_bytes = (crate / "src/nftables.rs").read_bytes()
    nft_sha256 = hashlib.sha256(nft_bytes).hexdigest()
    if nft_sha256 != NFTABLES_SOURCE_SHA256:
        fail(f"nftables.rs source differs from pinned baseline: {nft_sha256} != {NFTABLES_SOURCE_SHA256}")
    nft = nft_bytes.decode("utf-8")
    env = one(r"^EnvironmentFile=(\S+)$", unit, "EnvironmentFile")
    start = one(r"^ExecStart=(.+)$", unit, "ExecStart")
    runtime_dir = one(r"^RuntimeDirectory=(\S+)$", unit, "RuntimeDirectory")
    state_dir = one(r"^StateDirectory=(\S+)$", unit, "StateDirectory")
    if one(r"^WantedBy=(\S+)$", unit, "WantedBy") != "multi-user.target" or unit.count("[Install]") != 1:
        fail("pinned unit is not installable under its expected target")
    # Contract: this is a tripwire for accidental drift, not a defense against deliberately
    # disguised Rust. It catches an honest edit that changes a root literal, adds a second
    # root declaration or directory binding, moves or comments out the derivation, or leaves
    # a literal or comment unterminated. To do that it strips line and nested block comments
    # outside Rust literals, treats raw identifiers as ordinary identifiers, refuses non-ASCII
    # outside comments and literals, and counts only active declarations: each root has one
    # pub const, each directory one plain constant-derived let and no second binding in its
    # function. Ordinary uses and bindings in other functions are allowed.
    # Not guaranteed, because a text scan cannot model them (some are refused today, none is
    # promised): macro expansion (macro_rules! bodies, rebind!(state_dir.join(""))), include!,
    # any rebinding of PathBuf or fortress_id, shadows of the root names through imports, enum
    # variants, for loops, match arms, cfg attributes or keyword-spelled raw identifiers, a
    # shebang or bare carriage return that hides text, and absolute .join(...) arguments.
    # The pinned lines keep their exact form: a type annotation on a derivation or a
    # &'static str root refuses even when the value is unchanged. Any refusal fails closed
    # and the remedy is to extend this guard. Compiled values are pinned separately by the
    # resolved-path tests in config.rs.
    # Must match RAW_RUNTIME_ROOT and RAW_STATE_ROOT in castle-wall-daemon/src/config.rs.
    tokens = rust_tokens(config)
    runtime_root = fortress_root(tokens, "RAW_RUNTIME_ROOT", "/run")
    state_root = fortress_root(tokens, "RAW_STATE_ROOT", "/var/lib")
    fortress_directory(tokens, "runtime_dir", "RAW_RUNTIME_ROOT")
    fortress_directory(tokens, "state_dir", "RAW_STATE_ROOT")
    expected = {
        "ENV_PATH": env,
        "DAEMON_PATH": start.split()[0],
        "RUN_ROOT": "/run/" + runtime_dir,
        "STATE_ROOT": "/var/lib/" + state_dir,
        "JOURNAL_PATH": one(r'^pub const DEFAULT_OWNERSHIP_JOURNAL_PATH: &str = "([^"]+)";', journal, "ownership journal"),
        "AUTH_KEY_PATH": one(r'^pub const DEFAULT_JOURNAL_AUTH_KEY_PATH: &str = "([^"]+)";', journal, "journal auth key"),
        "HOST_LOCK_PATH": one(r'^pub const DEFAULT_HOST_LOCK_PATH: &str = "([^"]+)";', lock, "host lock"),
        "NFT_TABLE": one(r'^pub const CASTLE_TABLE: &str = "([^"]+)";', nft, "nft table"),
        # The package installs the agent template beside the wall unit.
        "AGENT_UNIT_PATH": "/etc/systemd/system/" + agent_unit_file.name,
    }
    check_partition(constants, expected)
    check_agent_unit(agent_unit, constants)
    if runtime_root != expected["RUN_ROOT"] or state_root != expected["STATE_ROOT"]:
        fail("fortress roots differ from unit RuntimeDirectory/StateDirectory")
    if constants.get("UNIT_PATH") != "/etc/systemd/system/sanctuary-castle-wall.service":
        fail("unit path changed outside first-slice contract")
    family = one(r'^pub const CASTLE_FAMILY: &str = "([^"]+)";', nft, "nft family")
    if family != "inet" or constants.get("NFT_FAMILY") != family:
        fail("nft family changed outside first-slice contract")
    supported_unit_roots = (
        "/etc/systemd/system.control", "/run/systemd/system.control",
        "/run/systemd/transient", "/run/systemd/generator.early",
        "/etc/systemd/system", "/etc/systemd/system.attached",
        "/run/systemd/system", "/run/systemd/system.attached",
        "/run/systemd/generator", "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system", "/run/systemd/generator.late",
    )
    if constants.get("SYSTEMD_ROOTS") != supported_unit_roots:
        fail("systemd search-root inventory drifted from pinned supported set")
    for name, value in expected.items():
        if constants.get(name) != value:
            fail(f"guard/source divergence for {name}: {constants.get(name)!r} != {value!r}")
    for name in ("JOURNAL_PATH", "AUTH_KEY_PATH", "HOST_LOCK_PATH"):
        if not constants[name].startswith(constants["STATE_ROOT"] + "/"):
            fail(f"host-global path outside bounded state root: {name}")
    if 'host_lock_path: PathBuf::from(crate::runtime_lock::DEFAULT_HOST_LOCK_PATH)' not in config or 'crate::ownership_journal::DEFAULT_OWNERSHIP_JOURNAL_PATH' not in config or 'crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH' not in config:
        fail("LinuxRuntimePaths::production no longer uses checked constants")
    print("guard paths match the pinned unit and daemon source")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, SyntaxError) as exc:
        print(f"guard source parity refused: {exc}", file=sys.stderr)
        sys.exit(1)
