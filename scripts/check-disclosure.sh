#!/usr/bin/env bash
# check-disclosure.sh — refuse to publish a defect description.
#
# THE RULE (AGENTS.md MUST-NEVER #9, tightened 2026-08-16): a pull-request
# description, and any test-file header, may never describe a defect. What it
# may carry is the capability change plus a bare private-register id. Nothing
# else.
#
# WHY THIS IS A MACHINE CHECK AND NOT A CONVENTION. The rule failed three times
# on a single pull request inside one day. One instance was a full reproduction
# with file paths written straight into a public description. TWO of the three
# were written by someone actively trying to comply: the first scrub replaced a
# file path with a vaguer sentence which, combined with what the repository
# already publishes, still narrowed the location to a single search; a reviewer
# found the third in the same section minutes later. Judgment fails here
# reliably, the surface is public the instant it is written, and the host keeps
# edit history, so the undo is incomplete. A gate that corrects after the fact
# is worth nothing on this rule. It has to refuse before the text ships.
#
# WHAT THIS CAN AND CANNOT DO (stated bound; read it before trusting a green).
# This is a TEXT scan over a body of prose. It catches an anchor (a path, a
# directory in a source tree, a path plus a line number), a claim of presence
# ("this is live on main"), the operating manual (a reproduction, an invocation,
# an attacker sentence), a severity ranking, a defect CLASS paired with a scope
# this repository already exposes (D8), and a piece of state described as
# unbounded (D10).
#
# THE BOUND, STATED SHARPLY, BECAUSE AN EARLIER VERSION OF THIS COMMENT WAS
# WRONG. It first claimed the only escape was "a description using none of this
# repository's vocabulary". That was an overclaim, and it was disproved the same
# day: two real scrubs from the triggering wave BOTH used this repository's
# vocabulary and BOTH passed. The accurate statement is narrower and less
# comfortable:
#
#   D8's class half, and D10, are ENUMERATED PHRASE LISTS. They are not a model
#   of meaning. A defect described in a phrasing that is not on those lists
#   passes, even when it names a scope, even when every word is ordinary
#   in-house vocabulary. Growing the lists is how this file improves; each
#   addition is one shape, not a class of shapes.
#
# Known gaps, named so the claim never exceeds the reach:
#   - A defect class in a phrasing absent from DEFECT_CLASS_RE. The residual and
#     resource families were added only after real text slipped through; assume
#     more families exist and are unlisted.
#   - D8 needs a scope locator. A class description carrying no scope, no path,
#     and no D10 mechanism shape passes.
#   - A protection-negation outside the resource family (see MECHANISM_NEG). The
#     family is bounded on purpose so capability-absence phrasing keeps passing,
#     and that boundary is a gap by construction, not an oversight.
#   - An image, a link to an external write-up, or an analogy carrying the
#     meaning outside the words.
#   - Under `--extract header`, only a file's leading comment block. A comment
#     further down the file is not seen.
#   - Outside a git checkout, D8 falls back to a short static scope list, which
#     is a materially weaker scan. It says so in its own report.
#
# So: a clean result means "none of the enumerated shapes is present". It does
# not mean the text is safe to publish, and it never substitutes for a reader.
#
# WHAT IT DOES NOT PRINT: the offending text. Ever. The report gives a rule id,
# a line number, and the correction. Echoing the matched sentence would relocate
# the disclosure into a build log, and build logs on a public repository are
# public. The failure mode if that is ever "improved" for debuggability: the
# gate itself becomes the leak.
#
# Usage:
#   scripts/check-disclosure.sh <path>
#   scripts/check-disclosure.sh -                       # read the body on stdin
#   cat body.md | scripts/check-disclosure.sh --label "PR body"
#   scripts/check-disclosure.sh --surface test-header --format tsv <path>...
#
# Options:
#   --label <name>      name used in the report (default: the path, or "stdin")
#   --surface <s>       pr-body (default) | test-header ; see SURFACES below
#   --format <f>        text (default) | tsv  (tsv prints "<label>\t<rule>\t<line>")
#   --extract <e>       none (default) | header — trim each input to its leading
#                       comment block before scanning, which is what "test-file
#                       header" means. Extraction lives HERE, in the one place
#                       that also does the matching, so the in-repo ratchet and
#                       a human running this by hand cannot disagree about where
#                       a header ends.
#
# Exit codes: 0 = clean, 1 = at least one rule hit, 2 = usage or I/O error.
# (Matches scripts/check-ai-tells.sh: 2 is "I could not run", never "I found
# something", so a caller can tell a broken invocation from a real refusal.)
#
# SURFACES. Two surfaces with the same D2 same-paragraph adjacency rule, but
# differing paragraph segmentation strategies to preserve their respective
# baseline ratchets and accuracy claims.
#   pr-body      Scanned as-is; callers typically pipe in the pull-request body.
#                Recognizes Markdown structural boundaries (headings, lists, tables)
#                as paragraph breaks in addition to blank lines (except inside
#                fenced code). This provides finer-grained separation and higher
#                accuracy for prose-heavy pull-request descriptions.
#   test-header  Typically paired with --extract header, which trims the input
#                to the leading comment block before scanning. Preserves the legacy
#                blank-line-only paragraph assembly and extraction semantics for
#                backward compatibility with the established baseline ratchet.
#                The same-paragraph adjacency rule on D2 still applies: an honest
#                module path passes on its own or in the same paragraph as
#                capability language, but combines with defect language.
#
# The D2 same-paragraph adjacency rule applies on both surfaces unchanged;
# Markdown structural boundaries are applied only to pr-body scans.

set -uo pipefail

# Pin the collation and character locale. Every pattern in this file is ASCII,
# and the in-repo ratchet in server/test/structure/disclosure-guard.test.ts
# compares a hit COUNT taken on an operator's Mac against one taken on the Linux
# builder. Failure mode without this line: a locale-dependent range or class
# behaves differently on the two hosts, the counts disagree, and the ratchet
# reds locally for a reason that has nothing to do with the change under review.
export LC_ALL=C

LABEL=""
SURFACE="pr-body"
FORMAT="text"
EXTRACT="none"
INPUTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --label)
      if [ $# -lt 2 ]; then echo "error: --label needs a value" >&2; exit 2; fi
      LABEL="$2"; shift 2 ;;
    --surface)
      if [ $# -lt 2 ]; then echo "error: --surface needs a value" >&2; exit 2; fi
      SURFACE="$2"; shift 2 ;;
    --format)
      if [ $# -lt 2 ]; then echo "error: --format needs a value" >&2; exit 2; fi
      FORMAT="$2"; shift 2 ;;
    --extract)
      if [ $# -lt 2 ]; then echo "error: --extract needs a value" >&2; exit 2; fi
      EXTRACT="$2"; shift 2 ;;
    -h|--help)
      echo "usage: $0 [--label <name>] [--surface pr-body|test-header] [--format text|tsv] [--extract none|header] [<path>|-]..." >&2
      exit 2 ;;
    -)
      INPUTS+=("-"); shift ;;
    -*)
      echo "error: unknown option: $1" >&2; exit 2 ;;
    *)
      INPUTS+=("$1"); shift ;;
  esac
done

case "$SURFACE" in
  pr-body|test-header) ;;
  *) echo "error: --surface must be pr-body or test-header, got: $SURFACE" >&2; exit 2 ;;
esac
case "$FORMAT" in
  text|tsv) ;;
  *) echo "error: --format must be text or tsv, got: $FORMAT" >&2; exit 2 ;;
esac
case "$EXTRACT" in
  none|header) ;;
  *) echo "error: --extract must be none or header, got: $EXTRACT" >&2; exit 2 ;;
esac

if [ "${#INPUTS[@]}" -eq 0 ]; then INPUTS=("-"); fi
if [ "${#INPUTS[@]}" -gt 1 ] && [ -n "$LABEL" ]; then
  echo "error: --label applies to a single input" >&2
  exit 2
fi

for input in "${INPUTS[@]}"; do
  if [ "$input" != "-" ] && [ ! -f "$input" ]; then
    echo "error: path does not exist: $input" >&2
    exit 2
  fi
done

RAW_FILE="$(mktemp "${TMPDIR:-/tmp}/check-disclosure.XXXXXX")"
EXTRACT_FILE="$(mktemp "${TMPDIR:-/tmp}/check-disclosure-extract.XXXXXX")"
MASKED_FILE="$(mktemp "${TMPDIR:-/tmp}/check-disclosure-masked.XXXXXX")"
# The temp files hold the text under scan; remove them on every exit path so a
# rejected body does not linger in /tmp on a shared build host.
cleanup() { rm -f "$RAW_FILE" "$EXTRACT_FILE" "$MASKED_FILE" 2>/dev/null || true; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Scope vocabulary, derived from the tree rather than hand-listed.
#
# Rule D8 needs to know which words NAME A PLACE IN THIS CODEBASE, because the
# hardest real instance localized a defect with no file path at all: a defect
# CLASS plus a scope the repository already publishes. A hand-written list of
# subsystem names would be exactly the "learned only the three past mistakes"
# guard this is supposed to not be, and it would drift the first time a
# directory is added. So the list is read from the committed tree, once.
#
# Filters: length >= 4 (a two- or three-letter directory such as `v1`, `cli`,
# `shr` collides with ordinary prose), minus a stoplist of directory names that
# are also ordinary English. Failure mode if the length filter is dropped: `v1`
# survives, and any sentence containing "v1" plus a defect phrase reds.
# ---------------------------------------------------------------------------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"

SCOPE_STOPLIST=" index types utils util common shared config test tests dist build public docs errors http node_modules "

scope_alternation() {
  local names=""
  if [ -n "$REPO_ROOT" ]; then
    names="$(git -C "$REPO_ROOT" ls-files 2>/dev/null \
      | grep -E '^(server/src/|castle-wall-[a-z]+/|menubar/|integrations/|sidecars/)' \
      | awk -F/ '{ for (i = 1; i < NF; i++) print $i }' \
      | sort -u)"
  fi
  if [ -z "$names" ]; then
    # Fallback for a scan run outside a checkout (a body piped in from a host
    # with no clone). Deliberately short: the derived list is the real
    # mechanism and this only keeps the rule from silently going dead. A scan
    # here is WEAKER than a scan inside the repo, which is why CI runs it in a
    # checkout and says so in the report.
    names="$(printf '%s\n' audit mesh federation bridge sentinel reputation fortress storage substrate handshake recovery guardian checkpoint)"
  fi
  printf '%s\n' "$names" \
    | tr 'A-Z' 'a-z' \
    | grep -E '^[a-z][a-z0-9-]{3,}$' \
    | while IFS= read -r name; do
        case "$SCOPE_STOPLIST" in
          *" $name "*) continue ;;
        esac
        printf '%s\n' "$name"
      done \
    | sort -u \
    | paste -sd'|' -
}

SCOPE_NAMES="$(scope_alternation)"
if [ -z "$SCOPE_NAMES" ]; then SCOPE_NAMES="audit|mesh|federation"; fi
SCOPE_DERIVED=1
if [ -z "$REPO_ROOT" ]; then SCOPE_DERIVED=0; fi

# A slash-separated lowercase token ("server/src/audit/", "castle-wall-daemon/")
# is a scope even when it names no file, so it counts as a D8 locator too.
PATH_SCOPE_RE='(^|[^A-Za-z0-9_./-])[a-z][a-z0-9_-]{2,}/[a-z0-9][a-z0-9._/-]*'
NAMED_SCOPE_RE="(^|[^A-Za-z0-9_-])(${SCOPE_NAMES})([^A-Za-z0-9_-]|$)"

# ---------------------------------------------------------------------------
# Pattern vocabulary.
#
# DEFECT_NOUN     — the thing itself, named.
# DEFECT_CLASS_RE — a defect described by its BEHAVIOUR rather than its name.
#                   This is the half that catches a compliant-looking scrub: a
#                   sentence can avoid every word in DEFECT_NOUN and still say
#                   "accepts a replayed head", which tells a reader exactly what
#                   to go looking for. Every alternative is a PHRASE, never a
#                   single charged word: "replay" alone appears in honest
#                   capability titles ("replay-resistant freshness"), so a
#                   bare-word list would red half this repository's real merges.
# ---------------------------------------------------------------------------
DEFECT_NOUN='(bug|defect|vulnerabilit(y|ies)|vuln|flaw|exploit|weakness|security hole|attack|regression|misbehaviou?r)'

DEFECT_CLASS_RE='(fails? open|failed open|fail-open|silently (accept|allow|pass|ignor|degrad|downgrad|skip)|accepts? (a |an |the )?(forged|replayed|stale|expired|unsigned|unverified|attacker|spoofed|tampered)|(can|could|may) be (forged|replayed|bypassed|spoofed|tampered|reused|downgraded|defeated|subverted|escalated)|(is|was|are|were) (never|not) (verified|checked|validated|authenticated|bounded|capped|enforced)|(is|are|was|were|remains?|stays?) (still )?(unverified|unchecked|unvalidated|unauthenticated|unsigned|uncapped|unbounded|ungoverned)|without (verifying|checking|validating|authenticating|a signature|authentication)|(missing|absent) (a )?(signature|bounds|input|auth|authentication|validation|verification)|no (signature|bounds|input|authentication) check|unbounded (growth|retention|memory|writes)|wrong-allow|allows? an unauthenticated|grants? [a-z ]{0,24}without (a |any )?(check|approval|verification|authentication)|trusts? (the )?(caller|client|attacker|payload)[- ]supplied|bypass(es|ed|ing) the|(further|another|additional|remaining|other|second|third) (instance|occurrence|case|call ?site|site|variant|sibling|cop(y|ies))s? of|(instance|occurrence|case|variant|sibling)s? of (the |this |that )?same|(exists?|remains?|persists?|survives?) (outside|beyond|elsewhere))'
# The last three alternatives are the RESIDUAL-EXISTENCE shape, added
# 2026-08-16 after a real scrub passed the first version of this file. A
# sentence saying that a further instance of the same class exists somewhere
# else is a defect description: it tells a reader the class recurs and roughly
# where, which is all a search needs. It carries no defect noun and no
# behavioural verb, so nothing above it matched.
#
# WHAT WAS DELIBERATELY NOT ADDED, and why. The obvious-looking fix was to match
# the nominalised forms `silent-degradation` / `silent-downgrade`, since the
# verb forms are already covered. That reds a real merged commit subject,
# "silent-downgrade detection for checkpoint signing", which is an honest
# capability name. The separator is not the phrase, it is what the sentence
# PREDICATES: naming a class you now DETECT is the capability; saying an
# instance of it EXISTS is the disclosure. Matching the noun would have made
# this guard red the honest half, and a guard that reds honest bodies is
# switched off within a week.

# Resource-exhaustion mechanism, matched WITHOUT needing a scope locator (rule
# D10). Added 2026-08-16 for a real scrub that named no path and no subsystem,
# only mechanism: a protection-negation adjective attached to a piece of state.
#
# The adjective list is the RESOURCE-BOUND family only. Deliberately excluded:
# `unproven`, `unimplemented`, `untested`, `unsupported`, `undocumented`. Those
# describe the ABSENCE OF A CAPABILITY, which MUST-NEVER #9 requires be stated
# plainly and never softened. Protection-absence is the disclosure;
# capability-absence is the honesty obligation. Failure mode if that line moves:
# the guard starts refusing "this capability is unproven on Linux", which is the
# one sentence the rule most wants written.
#
# Attributive use after a rejection verb ("rejects an unsigned checkpoint") is
# NOT matched, because that describes what the change now refuses rather than
# what the system currently lacks; only the predicate and state-noun forms are.
MECHANISM_NEG='(uncapped|unbounded|ungoverned|unlimited|unthrottled|unmetered)'
MECHANISM_STATE='(collection|map|list|queue|buffer|history|table|store|cache|set|array|growth|retention|writes?|appends?|loop|log|ledger|roster|registry)'
MECHANISM_RE="(is|are|was|were|remains?|stays?|sits?|lands?|left|goes|go) ([a-z-]+ ){0,3}${MECHANISM_NEG}|${MECHANISM_NEG} ([a-z-]+ ){0,2}${MECHANISM_STATE}|(call|calls|called|writ(e|es|ing)|append(s|ing)?|push(es|ing)?|enqueue(s|ing)?|invoke(s|d)?) [^.]{0,40}${MECHANISM_NEG}"

DEFECT_CONTEXT_RE="(${DEFECT_NOUN}|${DEFECT_CLASS_RE})"

CODE_PATH_RE='(^|[^A-Za-z0-9_.-])[A-Za-z0-9_-][A-Za-z0-9_./-]*\.(ts|tsx|js|jsx|mjs|cjs|rs|swift|py|go|java|kt|rb|c|h|cc|cpp)([^A-Za-z0-9]|$)'
# A path into a SOURCE TREE with no filename on the end (server/src,
# server/src/mesh, castle-wall-daemon/src/enforce). It is an anchor for the same
# reason a filename is, one directory coarser, and a real scrub used exactly
# this form. Rule D8 also treats it as a locator; this is the second,
# independent net, because D8's other half is an enumerated phrase list and the
# enumeration is the fragile part. Scoped to a `/src` segment on purpose:
# naming scripts/ or .github/ locates nothing, and reddening those would red
# honest bodies.
SRC_DIR_PATH_RE='(^|[^A-Za-z0-9_./-])[a-z][a-z0-9_-]*/src(/[a-z0-9_.-]+)*([^A-Za-z0-9_/-]|$)'
CONFIG_PATH_RE='(^|[^A-Za-z0-9_.-])[A-Za-z0-9_-][A-Za-z0-9_./-]*\.(yml|yaml|json|toml|sh|md|txt|cfg|conf|plist|entitlements|sql)([^A-Za-z0-9]|$)'
LINE_ANCHOR_RE='[A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z]{1,6}:[0-9]+'
INVOCATION_RE='(^|[[:space:]])(\$ |sudo |npx |npm |node |curl |wget |bash |sh |python3? |\./|printf |echo )'

PRESENT_RE="${DEFECT_NOUN}[^.]{0,60}(is|are|remains?|stays?) (still )?(live|present|current|unfixed|un-fixed|unpatched|open|exploitable|reachable|active)|(live|present|unfixed|unpatched|exploitable|reachable|vulnerable|shipping) (on|in) (main|production|the current release|the shipped release|the latest release|v[0-9])|(currently|today|still|as of (this|today|now)) (exploitable|vulnerable|unfixed|unpatched|bypassable|forgeable|replayable)|(affects|impacts) (the )?(current|latest|shipped|released|published) (release|version|build|main)"

REPRO_RE='(steps to reproduce|to reproduce|reproduc(e|es|ing|tion)|minimal repro)'
# Written with explicit boundary classes rather than \b: \b is a GNU extension
# that BSD grep honours today but is not in POSIX ERE, and this pattern's hit
# count is compared across a Mac and a Linux builder by the in-repo ratchet.
REPRO_CS_RE='(^|[^A-Za-z])(PoC|POC)([^A-Za-z]|$)'
EXPLOIT_RE='(proof[ -]of[ -]concept|(an|the|any|a remote|a local|an unprivileged) attacker (can|could|may|is able|only needs)|attacker[- ]controlled [a-z]{0,20}(invocation|payload|input)|how to trigger|trigger(s|ing)? the (bug|defect|flaw|vulnerabilit)|exploit(ation)? (path|chain|steps|invocation))'

INVOCATION_WORD_RE='(invocation|payload|command line|curl |one-liner)'

SEVERITY_CS_RE='(CRITICAL|HIGH|MEDIUM|SEV-?[0-9])[^.]{0,40}([Bb]ug|[Dd]efect|[Vv]ulnerabilit|[Ff]law|[Ff]inding|[Ww]eakness|[Ee]xploit)|([Bb]ug|[Dd]efect|[Vv]ulnerabilit|[Ff]law|[Ff]inding|[Ww]eakness)[^.]{0,40}(CRITICAL|HIGH severity|MEDIUM severity|SEV-?[0-9])'
SEVERITY_RE='severity[[:space:]]*[:=][[:space:]]*(critical|high|medium|low)'

# UNION_RE is the exact disjunction of every pattern that any rule REQUIRES.
# It is a pure speed gate: a paragraph matching none of these cannot produce a
# hit under any rule, because every rule's trigger is one of the alternatives
# below (D3, D6, D8 and D9 all additionally require DEFECT_CONTEXT_RE, which is
# here, so their prerequisites are covered).
#
# It is COMPOSED from the same variables the rules use, never retyped, so it
# cannot drift into a subset. Failure mode if someone adds a rule with a new
# pattern and forgets to add it here: that rule goes silently dead on any
# paragraph that matches nothing else. The must-fail corpus in
# server/test/structure/disclosure-guard.test.ts is what catches that, since
# every corpus entry has to still red.
UNION_RE="${LINE_ANCHOR_RE}|${CODE_PATH_RE}|${SRC_DIR_PATH_RE}|${CONFIG_PATH_RE}|${PRESENT_RE}|${REPRO_RE}|${REPRO_CS_RE}|${EXPLOIT_RE}|${SEVERITY_CS_RE}|${SEVERITY_RE}|${MECHANISM_RE}|${DEFECT_CONTEXT_RE}"

# ---------------------------------------------------------------------------
# Reporting. A hit prints the rule id, the line, why the rule exists, and the
# correction. It never prints the matched text (see the header).
# ---------------------------------------------------------------------------
TOTAL=0
FILE_HITS=0
CUR_LABEL=""

hit() { # hit <rule-id> <line> <name> <why> <instead>
  TOTAL=$((TOTAL + 1))
  FILE_HITS=$((FILE_HITS + 1))
  if [ "$FORMAT" = "tsv" ]; then
    printf '%s\t%s\t%s\n' "$CUR_LABEL" "$1" "$2"
    return 0
  fi
  printf '\nFAIL %s at %s line %s — %s\n' "$1" "$CUR_LABEL" "$2" "$3"
  printf '     why: %s\n' "$4"
  printf '     write instead: %s\n' "$5"
}

matches() { # matches <text> <pattern>  (case-insensitive)
  printf '%s' "$1" | grep -qEi -- "$2"
}
matches_cs() { # matches_cs <text> <pattern>  (case-SENSITIVE)
  printf '%s' "$1" | grep -qE -- "$2"
}

# Detect Markdown structural boundaries outside fenced code. Returns one of:
#   none       — regular text line, accumulate into paragraph
#   heading    — ATX heading (1-6 #, followed by space); check alone, then continue
#   table-row  — table row (leading optional space, then |); check alone, then continue
#   list-item  — list item (-, *, +, or digits + . or ), followed by space); start new paragraph
is_markdown_boundary() { # is_markdown_boundary <line>
  local line="$1"
  # Bash-native ERE checks; each pattern in a local variable so [[ =~ ]] matches
  # without spawning a subprocess. Failure mode if quotes wrap the variable in
  # [[ =~ ]]: the pattern is treated as a literal string, not a regex.
  # ATX heading: optional whitespace, 1-6 #, required whitespace (not end-of-line).
  local re_heading='^[[:space:]]*#{1,6}[[:space:]]'
  # Table row: optional whitespace, then literal |
  local re_table='^[[:space:]]*[|]'
  # Unordered list item: optional whitespace, then -, *, or +, then whitespace
  local re_unordered='^[[:space:]]*[-*+][[:space:]]'
  # Ordered list item: optional whitespace, digits, then . or ), then whitespace
  local re_ordered='^[[:space:]]*[0-9]+[.)][[:space:]]'

  if [[ "$line" =~ $re_heading ]]; then
    printf 'heading\n'
    return 0
  fi
  if [[ "$line" =~ $re_table ]]; then
    printf 'table-row\n'
    return 0
  fi
  if [[ "$line" =~ $re_unordered ]]; then
    printf 'list-item\n'
    return 0
  fi
  if [[ "$line" =~ $re_ordered ]]; then
    printf 'list-item\n'
    return 0
  fi
  printf 'none\n'
}

# ---------------------------------------------------------------------------
# Paragraph pass. Proximity rules bind inside ONE paragraph: a locator three
# paragraphs away from a defect phrase is not a localization, and treating the
# whole body as one window would red any body that mentions a directory
# anywhere.
# ---------------------------------------------------------------------------
DOC_HAS_DEFECT=0

check_paragraph() { # check_paragraph <text> <first-line-number>
  local text="$1" line="$2"
  [ -z "$text" ] && return 0

  # Speed gate, not a rule. See UNION_RE.
  matches "$text" "$UNION_RE" || return 0

  local has_defect=0
  if matches "$text" "$DEFECT_CONTEXT_RE"; then
    has_defect=1
    DOC_HAS_DEFECT=1
  fi

  # D1-ANCHOR — a path plus a line number. Unconditional on every surface:
  # there is no honest sentence that needs one, and it is the most precise
  # pointer a reader can be handed.
  if matches_cs "$text" "$LINE_ANCHOR_RE"; then
    hit "D1-ANCHOR" "$line" "a file-and-line anchor" \
      "MUST-NEVER #9 forbids publishing a file:line anchor into code." \
      "delete the anchor; name the capability and cite a bare register id."
  fi

  # D2-CODEPATH — a path to a source file, in the same paragraph as defect language.
  # Proximity rule on both surfaces: a path without defect language passes on both.
  # Markdown structural boundaries (headings, lists, tables) separate paragraphs so
  # they do not accumulate with surrounding prose.
  if matches_cs "$text" "$CODE_PATH_RE" || matches_cs "$text" "$SRC_DIR_PATH_RE"; then
    if [ "$has_defect" -eq 1 ]; then
      hit "D2-CODEPATH" "$line" "a path into a source tree" \
        "a path into implementation code narrows a reader to the defect without naming it, and a directory does it one level coarser." \
        "name the layer in prose ('bounded to the mesh layer'), not the path."
    fi
  fi

  # D3-CONFIGPATH — a configuration or documentation path. PROXIMITY on every
  # surface: an honest body routinely names a workflow or a runbook it adds, and
  # a guard that reds those gets switched off inside a week. It becomes an
  # anchor when it sits in the same paragraph as defect language.
  if [ "$has_defect" -eq 1 ] && matches_cs "$text" "$CONFIG_PATH_RE"; then
    hit "D3-CONFIGPATH" "$line" "a file path beside defect language" \
      "a path is a locator; next to a defect description it is an anchor." \
      "split them: describe the capability with the path, or the register id with neither."
  fi

  # D4-PRESENT — a claim that a defect is live, current, unfixed or reachable.
  # Unconditional. Note what is deliberately NOT here: absence-of-capability
  # phrasing ("Linux egress enforcement is not implemented", "unproven on
  # Linux") is an HONESTY OBLIGATION under the same rule and must keep passing.
  # The separator is presence-of-a-defect versus absence-of-a-capability; if a
  # future edit blurs it, the guard starts punishing the honest half of #9.
  if matches "$text" "$PRESENT_RE"; then
    hit "D4-PRESENT" "$line" "a claim that a defect is present" \
      "MUST-NEVER #9 forbids stating that a defect is live in current code or a release." \
      "state the capability being added; the private register carries the status."
  fi

  # D5-REPRO — reproduction and exploitation language. Unconditional. This is
  # the operating manual: the shape that turns "something is wrong somewhere"
  # into "here is how you do it". "reproducible" is deliberately NOT matched
  # (reproducible builds are an unrelated and wanted property).
  if matches "$text" "$REPRO_RE" || matches_cs "$text" "$REPRO_CS_RE"; then
    hit "D5-REPRO" "$line" "reproduction language" \
      "MUST-NEVER #9 forbids publishing a reproduction of a defect." \
      "remove it; a reproduction belongs only in the private register."
  fi
  if matches "$text" "$EXPLOIT_RE"; then
    hit "D5-REPRO" "$line" "exploitation language" \
      "MUST-NEVER #9 forbids publishing an invocation or attack path." \
      "remove it; the attack narrative belongs only in the private register."
  fi

  # D6-INVOCATION — invocation wording beside defect language. PROXIMITY,
  # because all of these are ordinary words in a protocol codebase ("signs the
  # lease payload") and only become a recipe next to a defect.
  if [ "$has_defect" -eq 1 ] && matches "$text" "$INVOCATION_WORD_RE"; then
    hit "D6-INVOCATION" "$line" "invocation wording beside defect language" \
      "an invocation next to a defect description is a reproduction in prose form." \
      "drop the invocation; describe only what the change now enforces."
  fi

  # D7-SEVERITY — a severity label attached to a defect. The LABEL is matched
  # case-sensitively on purpose: "the critical path through the verifier" is
  # ordinary prose, "a CRITICAL bug" is a ranked finding an attacker can
  # prioritize from. Roadmap severities ("a CRITICAL coming item") carry no
  # defect noun and keep passing, which is why the noun is required.
  if matches_cs "$text" "$SEVERITY_CS_RE" || matches "$text" "$SEVERITY_RE"; then
    hit "D7-SEVERITY" "$line" "a severity label on a defect" \
      "MUST-NEVER #9 forbids a severity-ranked defect an attacker could prioritize from." \
      "drop the severity; a bare register id resolves to it privately."
  fi

  # D8-LOCALIZED — the hard one, and the reason this file exists rather than a
  # checklist. A defect described by its CLASS, in the same paragraph as a place
  # this repository already publishes (a subsystem directory name, or any
  # slash-separated scope), localizes the defect without naming a file. That is
  # precisely the shape that survived a careful hand-scrub and still reached a
  # public surface. BOTH halves are required: a subsystem name alone is a normal
  # commit subject, a class phrase alone is a general statement about software.
  # D10-MECHANISM — a protection-negation attached to a piece of state, with NO
  # scope required. This is the one rule that stands alone without a locator,
  # because the shape it catches names no path and no subsystem: it describes
  # the mechanism instead ("the shared collection those entries land in is
  # uncapped"). A reader does not need the location when the mechanism is that
  # specific. It is bounded to the resource family (see MECHANISM_NEG) so that
  # capability-absence phrasing, which the rule REQUIRES be stated plainly,
  # keeps passing.
  if matches "$text" "$MECHANISM_RE"; then
    hit "D10-MECHANISM" "$line" "a piece of state described as unbounded" \
      "naming what a component lacks is a defect description even with no path and no subsystem in the sentence." \
      "state the protection this change adds ('adds a per-origin quota and an eviction rule'); the residual belongs in the private register under a bare id."
  fi

  if matches "$text" "$DEFECT_CLASS_RE"; then
    if matches "$text" "$NAMED_SCOPE_RE" || matches_cs "$text" "$PATH_SCOPE_RE"; then
      hit "D8-LOCALIZED" "$line" "a defect class beside a scope in this repository" \
        "class plus scope localizes the defect even with no file named; this is the scrub that still leaked." \
        "say what the change now guarantees, in the positive and with no scope word: 'the relying side now bounds the accepted age'."
    fi
  fi
}

scan_file() { # scan_file <source-path-or-dash> <label>
  local src="$1"
  CUR_LABEL="$2"
  FILE_HITS=0
  DOC_HAS_DEFECT=0

  # Only stdin needs to be spooled to a temp file; a path is handed straight to
  # the pipeline below. Batch mode scans hundreds of files, and a per-file `cat`
  # doubles the process count for no benefit.
  local sed_input="$src"
  if [ "$src" = "-" ]; then cat > "$RAW_FILE"; sed_input="$RAW_FILE"; fi

  # -------------------------------------------------------------------------
  # Extraction stage (--extract header). The leading comment block of a source
  # file: blank lines and comments from the top, stopping at the first line of
  # code. That is what "test-file header" means, and it lives here rather than
  # in the caller so the in-repo ratchet and a human running this by hand cannot
  # disagree about where a header ends.
  #
  # DELIBERATE BOUND: a comment further down the file is not extracted. The
  # header is the part a reader skims and the part that has historically carried
  # these descriptions; an inline comment mid-file could still hold one and
  # nothing here would see it. Stated rather than papered over.
  # -------------------------------------------------------------------------
  if [ "$EXTRACT" = "header" ]; then
    awk '
      BEGIN { inblock = 0 }
      {
        t = $0
        sub(/^[[:space:]]+/, "", t)
        sub(/[[:space:]]+$/, "", t)
        if (inblock) { print; if (index(t, "*/") > 0) inblock = 0; next }
        if (t == "") { print; next }
        if (substr(t, 1, 2) == "/*") { print; if (index(t, "*/") == 0) inblock = 1; next }
        if (substr(t, 1, 2) == "//") { print; next }
        exit
      }
    ' "$sed_input" > "$EXTRACT_FILE"
    # Written to a THIRD temp file, never back over the input: when the input is
    # stdin, sed_input already IS the spool file, and redirecting onto it
    # truncates the file awk is reading.
    sed_input="$EXTRACT_FILE"
  fi

  # -------------------------------------------------------------------------
  # Masking pass. Two token classes are masked BEFORE any rule runs, because
  # both are explicitly permitted by the rule and both would otherwise fire it.
  #
  #   1. A bare private-register id (IC-05-DG, C12-REPLAY, SYNC-APPEND-01,
  #      O-02, QI-SIBLING-02). The rule's whole point is that a register id is
  #      the SANCTIONED way to refer to a defect without describing it, so the
  #      id must not be read as prose. Unmasked, "C12-REPLAY" trips the replay
  #      phrasing and the guard reds the exact form it is trying to require.
  #      Shape: an all-caps hyphenated token containing at least one digit.
  #      Must match REGISTER_ID_SHAPE in
  #      server/test/structure/disclosure-guard.test.ts.
  #   2. A URL. The path rules look for slash-separated lowercase tokens; every
  #      URL contains one, and a link to an issue tracker is not an anchor into
  #      code.
  #
  # Failure mode if the register-id mask is ever loosened to "any all-caps
  # token": a severity label (CRITICAL, HIGH) is masked too and rule D7 goes
  # silently dead. The digit requirement is what keeps those two classes apart.
  #
  # A THIRD substitution strips a leading comment marker (`/**`, ` * `, `*/`,
  # `//`). This is what makes paragraphs mean anything inside a doc comment: the
  # "blank" line of a JSDoc block is ` *`, not an empty line, so without this
  # the entire header collapses into ONE paragraph and every proximity rule
  # widens to the whole comment. Failure mode if it is removed: a path in the
  # first sentence and a defect word in the last are treated as adjacent, and
  # honest headers red.
  # -------------------------------------------------------------------------
  # A FOURTH substitution neutralises a bare root governance document
  # (AGENTS.md, CLAUDE.md, SECURITY.md, ROADMAP.md, ...). Citing the rule you
  # are enforcing is what good prose does, and a policy document locates
  # nothing, which is the entire premise of the path rules. The `[^/]` guard
  # means a path WITH directories (docs/audit/SOMETHING.md) is untouched and
  # still counts as a locator.
  sed -E \
    -e 's#^[[:space:]]*(/\*\*?|\*/|\*|//)[[:space:]]?##' \
    -e 's#(^|[^A-Za-z0-9_/.-])[A-Z][A-Z0-9_]+\.md#\1<policy-doc>#g' \
    -e 's#https?://[^[:space:])"]*#<url>#g' \
    -e 's#(^|[^A-Za-z0-9_-])([A-Z]+-[A-Z0-9-]*[0-9][A-Z0-9-]*|[A-Z0-9]*[0-9][A-Z0-9]*-[A-Z][A-Z0-9-]*)([^A-Za-z0-9_-]|$)#\1<register-id>\3#g' \
    -e 's#(^|[^A-Za-z0-9_-])([A-Z]+-[A-Z0-9-]*[0-9][A-Z0-9-]*|[A-Z0-9]*[0-9][A-Z0-9]*-[A-Z][A-Z0-9-]*)([^A-Za-z0-9_-]|$)#\1<register-id>\3#g' \
    "$sed_input" > "$MASKED_FILE"
  # The identical substitution runs TWICE on purpose: the expression consumes
  # the delimiter after a match, so two register ids separated by a single
  # character ("IC-05-DG/O-02") leave the second unmasked on the first pass.
  # Failure mode if the second pass is deleted: an adjacent pair of register ids
  # reds a body that is following the rule exactly.

  # File-level speed gate, not a rule: if nothing in the whole file matches the
  # union of every rule trigger, no paragraph inside it can either, so the
  # per-paragraph loop is skipped. D9 is covered because it additionally
  # requires DEFECT_CONTEXT_RE, which is part of the union.
  grep -qEi -- "$UNION_RE" "$MASKED_FILE" || return 0

  local para="" para_line=0 line_no=0 in_fence=0 fence_line=0 line
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))
    case "$line" in
      '```'*) in_fence=$((1 - in_fence)) ;;
    esac
    if [ "$in_fence" -eq 1 ] && [ "$fence_line" -eq 0 ]; then
      if matches_cs "$line" "$INVOCATION_RE"; then fence_line="$line_no"; fi
    fi

    # Detect Markdown structural boundaries outside fenced code, but only for
    # pr-body surface. test-header uses legacy blank-line-only segmentation to
    # preserve the baseline ratchet. Both surfaces recognize blank lines.
    local boundary="none"
    if [ "$SURFACE" = "pr-body" ] && [ "$in_fence" -eq 0 ] && [ -n "$line" ]; then
      boundary="$(is_markdown_boundary "$line")"
    fi

    if [ "$boundary" = "heading" ] || [ "$boundary" = "table-row" ]; then
      # Headings and table rows: end current paragraph, check the boundary itself, then continue.
      check_paragraph "$para" "$para_line"
      check_paragraph "$line" "$line_no"
      para=""; para_line=0
    elif [ "$boundary" = "list-item" ]; then
      # List items: end current paragraph, start new one with this item.
      check_paragraph "$para" "$para_line"
      para="$line"; para_line="$line_no"
    elif [ -z "$line" ]; then
      # Blank line: end current paragraph (recognized on all surfaces).
      check_paragraph "$para" "$para_line"
      para=""; para_line=0
    else
      # Regular text: accumulate into paragraph.
      if [ -z "$para" ]; then para_line="$line_no"; fi
      para="$para $line"
    fi
  done < "$MASKED_FILE"
  check_paragraph "$para" "$para_line"

  # D9-FENCED-INVOCATION — a runnable command in a fenced block anywhere in a
  # body that also carries defect language. Document-scoped rather than
  # paragraph-scoped on purpose: the leak shape is "here is the problem"
  # followed several paragraphs later by "here is the command", and a paragraph
  # window would miss exactly that layout. A fenced command in a body with no
  # defect language (an ordinary usage example) still passes.
  if [ "$fence_line" -ne 0 ] && [ "$DOC_HAS_DEFECT" -eq 1 ]; then
    hit "D9-FENCED-INVOCATION" "$fence_line" "a runnable command in a body that describes a defect" \
      "a command block beside defect language is a reproduction, whatever the prose around it says." \
      "keep the command only if the defect language goes; otherwise remove the block."
  fi
}

for input in "${INPUTS[@]}"; do
  label="$LABEL"
  if [ -z "$label" ]; then
    if [ "$input" = "-" ]; then label="stdin"; else label="$input"; fi
  fi
  scan_file "$input" "$label"
done

if [ "$FORMAT" = "tsv" ]; then
  if [ "$TOTAL" -eq 0 ]; then exit 0; fi
  exit 1
fi

printf '\n----------------------------------------\n'
if [ "$TOTAL" -eq 0 ]; then
  printf 'clean: no disclosure shapes found (surface: %s)\n' "$SURFACE"
  if [ "$SCOPE_DERIVED" -eq 0 ]; then
    printf 'NOTE: run outside a checkout, so rule D8 used the short fallback scope\n'
    printf 'list instead of the tree-derived one. This scan was WEAKER than a scan\n'
    printf 'run inside the repository.\n'
  fi
  printf 'BOUND: the class rules (D8, D10) are ENUMERATED PHRASE LISTS, not a model\n'
  printf 'of meaning. A defect described in a phrasing that is not on those lists\n'
  printf 'passes, even when it names a scope and uses ordinary in-house words: two\n'
  printf 'real scrubs did exactly that. Also unseen: an image, an external link, an\n'
  printf 'analogy, and (under --extract header) anything below the leading comment.\n'
  printf 'Clean means "none of the enumerated shapes is present", NOT "safe to\n'
  printf 'publish". A human still reads it. Full gap list: top of this script.\n'
  exit 0
fi

printf 'BLOCKED: %s disclosure rule hit(s)\n' "$TOTAL"
printf '\n'
printf 'THE RULE: a pull-request description, and any test-file header, may never\n'
printf 'describe a defect. Write the capability change plus a bare private-register\n'
printf 'id, and nothing else. The private register is where the defect is described.\n'
printf '\n'
printf 'The offending text is deliberately not echoed here: this log is public.\n'
exit 1
