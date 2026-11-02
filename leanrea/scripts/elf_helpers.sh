#!/usr/bin/env bash
# leanrea elf_helpers.sh - Fast CLI helpers for reverse engineering stripped Linux ELF binaries.
# Source this file: source elf_helpers.sh

# 1. str2va <binary> <needle>
# Finds the first occurrence of needle in binary, locates its ELF section, and outputs its virtual address.
# Essential for objdump, which annotates RIP-relative loads with a hex address rather than the string literal.
str2va() {
  local bin="$1" needle="$2" off n a f s
  if [ -z "$bin" ] || [ -z "$needle" ]; then
    echo "Usage: str2va <binary> <needle>" >&2
    return 1
  fi
  off=$(grep -obUa -- "$needle" "$bin" 2>/dev/null | head -1 | cut -d: -f1)
  [ -n "$off" ] || return 1

  while read -r n a f s; do
    a=$((16#$a))
    f=$((16#$f))
    s=$((16#$s))
    if (( a && off >= f && off < f + s )); then
      printf '%x %s\n' $((a + off - f)) "$n"
      return 0
    fi
  done < <(readelf -SW "$bin" 2>/dev/null | sed -n 's/^ *\[ *[0-9]*\] *//p' | awk '$1!="NULL" && $3~/^[0-9a-f]+$/ {print $1,$3,$4,$5}')
  return 1
}

# 2. fstarts <disassembly_file>
# Detects function start addresses in stripped x86-64 ELF binaries. Modern Linux distributions
# (Ubuntu, Debian, Fedora, Arch) compile with CET enabled (-fcf-protection=full), beginning functions with endbr64.
fstarts() {
  local dis="$1"
  [ -f "$dis" ] || { echo "File not found: $dis" >&2; return 1; }
  awk '/^[0-9a-f]+ <.*>:$/{sec=$2} sec!~/plt/ && /endbr64/{sub(":","",$1); print $1}' "$dis"
}

# 3. fnof <disassembly_file> <target_hex_address>
# Returns the start address of the function enclosing the given instruction address.
fnof() {
  local dis="$1" target="$2" at best="" s
  [ -f "$dis" ] || { echo "File not found: $dis" >&2; return 1; }
  at=$((16#${target#0x}))
  for s in $(fstarts "$dis"); do
    if (( 16#$s <= at )); then
      best="$s"
    else
      break
    fi
  done
  echo "$best"
}

# 4. trail <disassembly_file> <function_hex_address>
# Slices the disassembly of a single function and extracts key structural instructions
# (calls, LEAs with RIP-relative comments, comparisons, tests, and returns).
trail() {
  local dis="$1" fn="${2#0x}"
  [ -f "$dis" ] || { echo "File not found: $dis" >&2; return 1; }
  awk -v s="${fn}:" '$1==s{p=1} p&&/endbr64/&&$1!=s{exit} p' "$dis" | grep -E 'call|lea .*#|cmp|test|ret'
}

# 5. elf_recon <binary> [out_dir]
# One-shot batch probe for any ELF executable or shared library.
elf_recon() {
  local bin="$1"
  [ -f "$bin" ] || { echo "Binary not found: $bin" >&2; return 1; }
  local out_dir="${2:-${TMPDIR:-/tmp}/re-$(basename "$bin")}"
  mkdir -p "$out_dir"

  echo "=== FILE ==="
  file -b "$bin"
  echo "=== ELF HEADER ==="
  readelf -hW "$bin" | grep -E 'Class|Machine|Type|Entry point'
  echo "=== DYNAMIC / NEEDED ==="
  readelf -dW "$bin" | grep -E 'NEEDED|RUNPATH|RPATH|SONAME'
  echo "=== EXPORTS (Dynamic) ==="
  nm -D --defined-only "$bin" 2>/dev/null | head -150
  echo "=== IMPORTS ==="
  nm -D --undefined-only "$bin" 2>/dev/null | awk '{print $NF}' | tr '\n' ' '; echo
  echo "=== STRINGS (Preview) ==="
  strings -a -n 5 "$bin" | grep -v -E '^[_.$]|^GLIBC|^GCC' | head -300
  echo "=== DISASSEMBLY ==="
  objdump -d -M intel --no-show-raw-insn -C "$bin" > "$out_dir/dis.txt"
  echo "Disassembly written to: $out_dir/dis.txt"
  echo "=== FUNCTIONS ==="
  grep -E '^[0-9a-f]+ <.*>:$' "$out_dir/dis.txt" | grep -v '@plt>' | head -150
}
