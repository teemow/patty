#!/bin/bash
# Regenerates the marked blocks in the docs from what the binary itself
# knows, so the docs cannot drift from the code. `make docs` runs it; CI
# runs it and fails when the result differs from what is committed.
set -euo pipefail
cd "$(dirname "$0")/.."

splice() { # splice FILE NAME COMMAND...: replace the block NAME in FILE with the output of COMMAND
  local file=$1 name=$2
  shift 2
  local begin="<!-- BEGIN GENERATED: $name -->" end="<!-- END GENERATED: $name -->"
  grep -qF "$begin" "$file" && grep -qF "$end" "$file" || {
    echo "$file: no '$begin' … '$end' block" >&2
    exit 1
  }
  BODY=$("$@") BEGIN=$begin END=$end awk '
    $0 == ENVIRON["BEGIN"] { print; print ""; print ENVIRON["BODY"]; print ""; skip = 1; next }
    $0 == ENVIRON["END"]   { skip = 0 }
    !skip                  { print }
  ' "$file" > "$file.tmp"
  mv "$file.tmp" "$file"
}

splice docs/how-it-works.md "patty kinds" go run . kinds
