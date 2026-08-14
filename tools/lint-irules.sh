#!/usr/bin/env bash
#
# Reject Tcl constructs that TMM cannot run.
#
# iRules execute in TMM's embedded Tcl, which is 8.4-era: every command added in
# Tcl 8.5+ is missing, and a desktop tclsh (8.6) runs them happily. So neither
# `tclsh tests/` nor code review catches this class — only the BIG-IP does, at
# iRule load time, with:
#
#   01070151:3: Rule [...] error: ...: error: [undefined procedure: dict][...]
#
# which surfaces after deploy, when the template is already on the box. This
# lint moves that failure to CI. It is deliberately a denylist of constructs we
# know TMM lacks, not a Tcl parser: a false negative costs a lab round-trip, a
# false positive would block a legitimate merge.
#
# Usage: tools/lint-irules.sh [file ...]
#        (defaults to every iRule the template embeds: iRules/ and HSSR/)
set -euo pipefail

# Tcl 8.5+/8.6+ commands (TMM has none of them), then commands TMM omits because
# it has no filesystem, stdio, or event loop of its own.
BANNED='dict|lassign|lreverse|lrepeat|apply|chan|try|throw|coroutine|yield|puts|exec|open|socket|glob|cd|pwd|vwait|update|trace|source'

# A plain glob rather than `mapfile`, which macOS's bash 3.2 does not have; and
# "$#" rather than "${#files[@]}", which is an unbound-variable error on an
# empty array there under `set -u`.
if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=(iRules/*.tcl HSSR/*.tcl)
fi

status=0

for f in "${files[@]}"; do
  # Only whole-line comments are stripped. A trailing "# ..." cannot be removed
  # safely (a # inside a string or regex is not a comment), and leaving it in
  # only risks a false positive, which fails loud rather than silent.
  #
  # Command position is what makes `dict` a command rather than a word: start of
  # line, or immediately after [ { ; or ]. That keeps prose like "predicted" and
  # "dictionary" in comments from matching.
  if hits=$(grep -nE "(^|[][{;])[[:space:]]*($BANNED)[[:space:]]" "$f" \
            | grep -vE '^[0-9]+:[[:space:]]*#' ); then
    echo "::error file=$f::TMM cannot run these Tcl constructs (8.5+ or unsupported in iRules):"
    echo "$hits" | sed 's/^/  /'
    status=1
  fi

  # {*} argument expansion is 8.5 syntax, not a command, so it needs its own check.
  if hits=$(grep -nE '\{\*\}' "$f" | grep -vE '^[0-9]+:[[:space:]]*#'); then
    echo "::error file=$f::{*} argument expansion is Tcl 8.5 syntax; TMM cannot parse it:"
    echo "$hits" | sed 's/^/  /'
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "iRule lint: no TMM-incompatible constructs found in ${#files[@]} file(s). ✔"
fi

exit "$status"
