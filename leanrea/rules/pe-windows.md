# Windows PE & Native Reverse Engineering Guide

This guide details fast, reliable reverse engineering of Windows PE binaries (`.exe`, `.dll`, `.sys`) using local command-line tools without requiring Visual Studio or heavy GUI decompilers.

## 1. Tool Mapping (macOS/Linux Equivalent on Windows)

When analyzing Windows targets (via Git Bash, MSYS2, WSL, or native cmd/PowerShell):

| Purpose | Linux / macOS Tool | Windows Local Tool |
|---|---|---|
| File identity | `file -b target` | `file -b target` (or check PE magic `MZ` / `PE\0\0`) |
| Headers & COFF info | `readelf -h` / `lipo` | `llvm-objdump -p target.exe` or `llvm-readobj --file-headers target.exe` |
| DLL Imports | `otool -L` / `readelf -dW` | `llvm-readobj --coff-imports target.exe` |
| Export Table | `nm -gU` / `nm -D --defined` | `llvm-nm --extern-only --defined-only target.exe` |
| Strings | `strings -a -n 6` | `llvm-strings -n 6` (or `python3 leanrea/scripts/pe_strings_mmap.py`) |
| Disassembly | `objdump -d` / `otool -tV` | `llvm-objdump -d target.exe` |
| Resource section (`.rsrc`) | `wrestool` | `llvm-readobj --coff-resources target.exe` or `pefile` |
| .NET Decompilation | `ilspycmd` | `ilspycmd -p -o out/ target.dll` |

## 2. One-Shot Reconnaissance for PE Binaries

```sh
T=./target.exe; D=$(mktemp -d "${TEMP:-/tmp}/re-$(basename "$T").XXXXXX")
echo "Extraction directory: $D"
file -b "$T"
llvm-objdump -p "$T" | head -60
echo '--- IMPORTS'; llvm-readobj --coff-imports "$T" 2>/dev/null | grep -E 'Name:|Symbol:' | head -100
echo '--- EXPORTS'; llvm-nm --extern-only --defined-only "$T" | head -150
echo '--- STRINGS'; python3 leanrea/scripts/pe_strings_mmap.py "$T" -m 150
llvm-objdump -d "$T" > "$D/dis.txt"
echo '--- FUNCTIONS'; rg -n '^[0-9a-f]+ <' "$D/dis.txt" | head -150
```

Read one function:
```sh
awk '/^[0-9a-f]+ <NAME>:/{p=1} p&&/^[0-9a-f]+ <.*>:/&&!/NAME/{exit} p' "$D/dis.txt" | rg 'call|jmp|cmp|lea|mov'
```

## 3. Real-World Traps on Windows

### A. Large Binary `llvm-strings` Truncation Bug
On PE files over ~100 MB (such as Electron main executables), `llvm-strings` frequently terminates early and prints empty output without returning an error code.
**Solution**: Use memory-mapped search:
```sh
python3 leanrea/scripts/pe_strings_mmap.py target.exe "search_term"
```

### B. UTF-16LE Wide Characters
Strings in Windows APIs, registry paths, and Electron constants are frequently encoded in UTF-16LE. A standard byte grep or ASCII-only string dump will miss them. `pe_strings_mmap.py` scans both ASCII and UTF-16LE automatically.

### C. GnuWin32 `file` Misclassification Bug
GnuWin32 `file 5.03` has an outdated magic database that frequently misclassifies modern 64-bit Electron PE binaries as `Mono/.Net assembly`.
**Cross-check**: Check if companion files exist in the same directory (`icudtl.dat`, `LICENSES.chromium.html`, `chrome_100_percent.pak`). If they exist, it is an Electron/Chromium app, not .NET.

### D. .NET IL Applications
If the binary is genuinely .NET (`mscoree.dll` import / CLR header):
```sh
# Install ILSpy command line tool
dotnet tool install -g ilspycmd
# Decompile entire assembly to C# files
ilspycmd -p -o "$D/dotnet_src" target.dll
# Search P/Invoke native interop calls
rg -n 'DllImport' "$D/dotnet_src"
```
