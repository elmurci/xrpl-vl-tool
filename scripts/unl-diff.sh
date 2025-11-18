#!/usr/bin/env bash
set -euo pipefail

# Usage: unl-diff.sh URL1 URL2
# Optionally set XRPL_VL_TOOL (defaults to ./xrpl_vl_tool)
#   XRPL_VL_TOOL=/path/to/xrpl_vl_tool ./unl-diff.sh https://vl.ripple.com https://unl.xrplf.org

XRPL_VL_TOOL="${XRPL_VL_TOOL:-./xrpl_vl_tool}"
URL1="${1:?usage: $0 URL1 URL2}"
URL2="${2:?usage: $0 URL1 URL2}"

load() { "$XRPL_VL_TOOL" load "$1"; }

summarize() {
  load "$1" | awk '
    BEGIN { cnt=""; seqno=""; expires_str=""; ver=""; master="" }
    /^There are/ {
      cnt=$3
      tmp=$0
      sub(/^.*Sequence is:[[:space:]]*/, "", tmp)
      seqno=tmp; sub(/[^0-9].*$/, "", seqno)

      tmp=$0
      sub(/^.*Expires:[[:space:]]*/, "", tmp)
      expires_str=tmp; sub(/[[:space:]]*\|.*$/, "", expires_str)

      tmp=$0
      sub(/^.*Version:[[:space:]]*/, "", tmp)
      ver=tmp; sub(/[^0-9].*$/, "", ver)
    }
    /^Publisher Master Public Key:/ {
      sub(/^Publisher Master Public Key:[[:space:]]*/, "", $0)
      master=$0
    }
    END {
      printf "count=%s sequence=%s expires=\"%s\" version=%s master=%s\n", cnt, seqno, expires_str, ver, master
    }
  '
}

# HEX-only (for set math)
keys() {
  load "$1" | awk '/^Validator:/ { print $2 }' | LC_ALL=C sort -u
}

# HEX|NODE|DOMAIN (NODE is base58 in parens; DOMAIN may be empty)
key_node_domain() {
  load "$1" | awk -F'|' '
    /^Validator:/ {
      left = $1
      sub(/^Validator:[[:space:]]*/, "", left)

      # HEX is the first token before any space
      hex = left
      sub(/[[:space:]].*$/, "", hex)

      # NODE: extract text between first "(" and next ")"
      node = ""
      lp = index(left, "(")
      if (lp > 0) {
        rest = substr(left, lp + 1)
        rp = index(rest, ")")
        if (rp > 0) {
          node = substr(rest, 1, rp - 1)
        }
      }

      # DOMAIN is field 3 (after the second "|"), if present
      dom = ($3 == "" ? "" : $3)
      sub(/^[[:space:]]*/, "", dom)

      print hex "|" node "|" dom
    }
  ' | LC_ALL=C sort -u
}

# Temp files
k1=$(mktemp); k2=$(mktemp)
f1=$(mktemp); f2=$(mktemp)
trap 'rm -f "$k1" "$k2" "$f1" "$f2"' EXIT

keys "$URL1" > "$k1"
keys "$URL2" > "$k2"
key_node_domain "$URL1" > "$f1"
key_node_domain "$URL2" > "$f2"

echo "== Summary =="
echo "URL1: $URL1"
summarize "$URL1"
echo "URL2: $URL2"
summarize "$URL2"
echo

# Added
echo "== Added (present in URL2, not in URL1) =="
comm -13 "$k1" "$k2" | awk -v F="$f2" '
  BEGIN {
    FS="|"
    while ((getline < F) > 0) { m[$1]=$2 "|" $3 }
    close(F)
  }
  {
    hex=$0
    split(m[hex], parts, "|")
    node=parts[1]; dom=parts[2]
    printf " + %s", hex
    if (node != "") printf " (%s)", node
    if (dom  != "") printf " | %s", dom
    printf "\n"
  }
'
echo

# Removed
echo "== Removed (present in URL1, not in URL2) =="
comm -23 "$k1" "$k2" | awk -v F="$f1" '
  BEGIN {
    FS="|"
    while ((getline < F) > 0) { m[$1]=$2 "|" $3 }
    close(F)
  }
  {
    hex=$0
    split(m[hex], parts, "|")
    node=parts[1]; dom=parts[2]
    printf " - %s", hex
    if (node != "") printf " (%s)", node
    if (dom  != "") printf " | %s", dom
    printf "\n"
  }
'
echo

# Domain changes
echo "== Domain changes (same key, different domain) =="
awk -F'|' '
  FNR==NR { node1[$1]=$2; dom1[$1]=$3; next }
  {
    hex=$1; node2=$2; dom2=$3
    if (hex in dom1 && dom1[hex] != dom2) {
      printf " * %s", hex
      if (node2 != "") printf " (%s)", node2
      printf "\n     URL1: %s\n     URL2: %s\n", dom1[hex], dom2
    }
  }
' "$f1" "$f2" || true
echo