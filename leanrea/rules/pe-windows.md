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

---

## 4. Analyzing Windows PEs from Linux (Host: Linux)

Linux is a first-class host for reverse engineering Windows binaries. You do not need a Windows VM for static analysis.

### A. Headers, Imports & Sections (Native Linux Tools)
Standard GNU `objdump` on Linux natively parses PE32 / PE32+ (COFF):
```sh
# Headers and section table:
objdump -p target.exe | head -60

# Import DLLs and imported functions:
objdump -p target.exe | grep -A 10 'DLL Name:'

# Or via LLVM (if installed):
llvm-readobj --coff-imports target.exe
```

### B. Python `pefile` (Fast, Deep Structural Inventory)
```sh
# One-liner to dump DLL imports and functions:
python3 -c "import pefile, sys; pe = pefile.PE(sys.argv[1]); [print(f'=== {e.dll.decode()} ===\n' + '\n'.join(i.name.decode() for i in e.imports if i.name)) for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])]" target.exe

# Dump exports:
python3 -c "import pefile, sys; pe = pefile.PE(sys.argv[1]); [print(e.name.decode() if e.name else hex(e.ordinal), hex(e.address)) for e in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])]" target.exe
```

### C. Disassembly & Decompilation on Linux
```sh
# Disassemble x86/x64 PE with Intel syntax:
objdump -d -M intel target.exe > dis.txt

# Decompile full PE to C pseudocode with headless Ghidra on Linux:
analyzeHeadless /tmp/ghidra_proj temp -import target.exe -loader-libraryLoadDepth 0 -scriptPath leanrea/scripts -postScript DecompileAll.java /tmp/decomp.c -deleteProject
```

### D. Windows Resources & Manifests on Linux
```sh
# List resources (.rsrc section: icons, manifests, version info):
wrestool -l target.exe

# Extract embedded application manifest (shows elevation level, DPI awareness):
wrestool -x -t 24 target.exe

# Extract main application icon:
wrestool -x -t 14 -n 1 target.exe > icon.ico
```

### E. Extracting Windows Installers on Linux
```sh
# NSIS installer or self-extracting archive (built-in 7z on Linux):
7z x setup.exe -o/tmp/extracted

# InnoSetup installer (via native Linux innoextract):
innoextract -d /tmp/extracted setup.exe

# Windows Installer MSI (via native Linux msitools):
msiextract -C /tmp/extracted setup.msi
```

### F. Dynamic API Call Tracing via Wine (Optional)
When static analysis needs runtime confirmation, Wine can trace every Windows API call on Linux without a VM:
```sh
# Trace all Windows API DLL calls (relay trace):
WINEDEBUG=+relay wine target.exe 2>&1 | rg -v 'ntdll|kernelbase|gdi32' | head -200

# Attach Wine GDB:
winedbg --gdb target.exe
```
