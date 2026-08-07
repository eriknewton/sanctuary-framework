#!/usr/bin/env bash
# check-ai-tells.sh — scan public-facing artifacts for LLM writing tells.
#
# WHY THIS EXISTS (2026-07-31, measured):
# Hacker News changed its guidelines to ban generated or AI-edited text, runs an
# automated classifier that kills posts, and its readers maintain public lists of
# the exact words that trigger the reflex. A reader who decides a piece was written
# by an LLM stops reading before judging the content. Verbatim from that research:
# "If the author didn't put much effort into writing it, should I expect them to
# have put much effort into fact-checking it?"
#
# Our published writing is drafted with Claude. That makes this a distribution
# problem, not a style preference. Evidence: Wiki/concepts/hacker-news-traction-mechanics-2026-07-31.md
#
# This script is a REFLEX CHECK, not an oracle. It cannot tell you whether prose is
# good. It tells you which phrases a hostile reader will point at. Detection tools
# in the wild have severe false-positive rates (genuinely pre-LLM text flags at
# 27-74%; non-native-speaker essays at 61%), so treat every hit as "a reader may
# stop here", never as proof of anything.
#
# Usage:
#   scripts/check-ai-tells.sh <path> [<path>...]
#   scripts/check-ai-tells.sh --strict <path>   # exit 1 on any hit (for CI)
#
# Exit codes: 0 = no hits (or non-strict), 1 = hits found under --strict.

set -uo pipefail

STRICT=0
if [ "${1:-}" = "--strict" ]; then STRICT=1; shift; fi
if [ $# -eq 0 ]; then
  echo "usage: $0 [--strict] <path> [<path>...]" >&2
  exit 2
fi

TOTAL=0
report() { # report <label> <pattern> <why>
  local label="$1" pattern="$2" why="$3" hits
  hits=$(grep -rInE --include='*.md' --include='*.html' --include='*.txt' \
         -- "$pattern" "${PATHS[@]}" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    local n
    n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    TOTAL=$((TOTAL + n))
    printf '\n== %s (%s hits)\n   why: %s\n' "$label" "$n" "$why"
    printf '%s\n' "$hits" | head -12 | sed 's/^/   /'
    if [ "$n" -gt 12 ]; then printf '   ... and %s more\n' "$((n - 12))"; fi
  fi
}

PATHS=("$@")
for path in "${PATHS[@]}"; do
  if [ ! -e "$path" ]; then
    echo "error: path does not exist: $path" >&2
    exit 2
  fi
done

echo "AI-tell scan over: ${PATHS[*]}"

# Tier 1 — highest citation frequency on HN. Treat a hit as a real problem.
report "em dash" \
  '—' \
  "the most-cited surface tell; our no-em-dash rule (2026-04-21) already forbids these in public artifacts"

report "contrastive negation" \
  "([Ii]t'?s not just .{1,40}(,|;) it'?s|[Ii]t'?s not .{1,40}(,|;) it'?s|not just .{1,40}, but|[Tt]he (question|point|problem) (isn'?t|is not) .{1,40}\. [Tt]he|(is|are|was|were) not .{1,60}\. +[Ii]t (is|was)|(is|are|was|were) not .{1,50}, it (is|was))" \
  "named 'the single most commonly identified AI writing tell'; creates false profundity by framing everything as a reframe"

report "Claude lexical cluster" \
  '\b(load-bearing|earn(s|ed) its keep|blast radius|smoking gun|belt.and.suspenders|tracer bullets?|the unlock|that.s the wedge|paper-cuts?)\b' \
  "appears verbatim on user-maintained HN banned-word lists; 'load-bearing' is currently the hottest single Claude tell"

# Tier 2 — supporting tells. A couple is fine; a cluster is the problem.
# The \b atoms below intentionally rely on the BSD/GNU grep behavior available
# on supported macOS and Linux operator hosts.
# The appositive reframe ("an answer key, not a test") is the dominant form of
# contrastive negation in our own drafts, but a bare "A, not B" is also ordinary
# English ("use foo, not bar"), so it sits in Tier 2 on purpose. Judge the
# CLUSTER, not the single hit: the 2026-07-31 neutrality draft carried roughly
# ten in a two-page document while the Tier 1 pattern reported zero.
report "contrastive appositive" \
  ", not (a|an|the|just|merely|simply|only) [a-z]+[.;]|, not [a-z]+(ed|ing)[.;]" \
  "the reframe tell in appositive form; one is fine, a cluster reads as generated"

report "hedge / filler openers" \
  "\b([Ii]t'?s worth noting|[Ii]t'?s important to note|[Ll]et me be clear|[Aa]t the end of the day|[Ii]n today'?s .{0,30}landscape|[Gg]reat question)\b" \
  "filler that adds no information; classic generated-prose padding"

report "empty intensifiers" \
  '\b(genuinely|quietly) (surfaced|outperform|better|different|new|matters|works)\b' \
  "'genuinely'/'quietly' used to imply secret knowledge without evidence"

report "stacked anaphora" \
  '(No [A-Za-z]+\. No [A-Za-z]+\.|Not [A-Za-z]+\. Not [A-Za-z]+\.)' \
  "the 'No X. No Y. Just Z.' staccato pattern"

report "emoji checkmark bullets" \
  '^[[:space:]]*[-*][[:space:]]*(✅|❌|✔️|✓|🚀|🔥)' \
  "emoji-tick bullet lists in a README read as generated at a glance"

printf '\n----------------------------------------\n'
if [ "$TOTAL" -eq 0 ]; then
  echo "clean: no tells found"
  exit 0
fi
echo "TOTAL: $TOTAL hit(s)"
echo
echo "Judgment required. These are reflex triggers, not errors. Rewrite the Tier 1"
echo "hits; for Tier 2, ask whether the sentence carries information without the"
echo "phrase. Never 'fix' by paraphrasing into something equally generic: the"
echo "durable answer is a specific number, a real name, or a concrete failure."
[ "$STRICT" -eq 1 ] && exit 1
exit 0
