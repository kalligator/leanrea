# macOS Mach-O & Native Reverse Engineering Guide

This guide details fast, native reverse engineering of macOS Mach-O binaries, dynamically linked libraries (`.dylib`), and native Node addons (`.node`).

## 1. One-Shot Reconnaissance for Mach-O

```sh
T=./target_bin; D=$(mktemp -d "${TMPDIR:-/tmp}/re-$(basename "$T").XXXXXX")
echo "Extraction directory: $D"
file "$T"
lipo -info "$T"
otool -L "$T"
echo '--- EXPORTS'; nm -gU "$T" | head -150
echo '--- IMPORTS'; nm -u "$T" | rg -v '^__Z|napi_' | tr '\n' ' '; echo
echo '--- STRINGS'; strings -a -n 6 "$T" | rg -v '^[_$.]' | head -300
otool -tV "$T" > "$D/dis.txt"
echo '--- FUNCTIONS'; rg '^[_a-zA-Z].*:$' "$D/dis.txt" | rg -v '^_?_?Z?N?St3' | head -150
```

Read one function:
```sh
awk '/^FUNC_LABEL:$/{p=1;next} p&&/^[_a-zA-Z].*:$/{exit} p' "$D/dis.txt" | rg 'bl|b\.|cmp|literal|mov\s+w2'
```

## 2. Dynamic Linker & Entitlements

- **Dyld Imports & Exports**: `xcrun dyld_info -exports -imports "$T"`
- **Code Signing & Entitlements**: `codesign -d --entitlements :- "$T"`
- **Rpath & Build Versions**: `otool -l "$T" | rg -A 3 'LC_(RPATH|BUILD_VERSION)'`
- **Objective-C Classes & Methods**: `otool -ov "$T" | head -200`
- **Swift Demangling**: `nm -gU "$T" | xcrun swift-demangle --compact`

## 3. String Literal Pool Reference Pattern
`otool -tV` annotates literal pool accesses with comments like `literal pool for: "String"`.
To identify the function utilizing a string:
```sh
rg -n 'literal pool for: "NEEDLE"' "$D/dis.txt"
```
Then inspect the enclosing function label directly above that line.
