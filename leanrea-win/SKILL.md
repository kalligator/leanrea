---
name: leanrea-win
description: Reverse engineer shipped software on Windows with plain local CLI tools, no MCP needed. Shell is PowerShell 7. Covers PE/.NET native Windows binaries, Electron/JS bundles, ELF and Mach-O cross-analysis via LLVM binutils, Go/Rust/WASM binaries, APKs, SQLite, pcaps, installers (MSI/NSIS/InnoSetup), firmware and websites. Use to explain how a feature works, extract versions/deps, compare builds, or rebuild a feature.
---

# leanrea-win: fast path (Windows, PowerShell 7)

You already know these tools. This file only lists the fastest command for each target, and the traps.
Shell is PowerShell 7 (pwsh). Baseline tools (`rg`, `python`+`pefile`, `node`) are on almost every Windows dev box; LLVM binutils (one `winget install LLVM.LLVM`) cover PE+ELF+Mach-O from a single install; WSL is the universal fallback. If your agent shell is Git Bash instead, read the appendix at the bottom.

## Rules
- Work on a copy. Put each extraction in a new dir under `$env:TEMP\re\<name>`. Reuse an extraction if one exists.
- Route by magic bytes first (one-liner below; pwsh has no `file`). Run the cheapest inventory next. Only then decompile or read code.
- **Quoting:** for `python -c` / `node -p` payloads use DOUBLE quotes outside and SINGLE quotes inside — pwsh strips double quotes from single-quoted args at the native boundary, but single quotes pass through. Avoid `$` in payloads (pwsh expands it inside double quotes; escape as `` `$ ``). Longer snippets: pipe a literal here-string `@' ... '@ | python - T`.
- Pipe caps: `| Select-Object -First N` everywhere; `| Sort-Object -Unique` for uniq; markers `Write-Host '--- NAME'`. Batch independent probes into ONE call with `;`.
- `rg` patterns go in single quotes (pwsh leaves them alone). `rg` skips hidden and ignored files, and bundlers hide code (Electron: `.webpack/`, `.vite/`): search extracted trees with `rg -uu`.
- No `awk` in pwsh. Function slices: `rg -A N '<label>' file | rg 'call|cmp'`.
- Never read a big or minified file whole. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | Select-Object -First 20`. Dump a disassembly once to a file, then grep that file. Native `>` redirection writes UTF-8 (pwsh 7).
- `strings`/`objdump`/`nm`/`readelf` from an old `C:\cygwin64\bin` on PATH are ghosts that crash with `fhandler size mismatch` (half-updated install). Test with `objdump --version` before trusting; real alternatives: `rg -a -o '[ -~]{6,}' F` for strings, mingw-w64 or LLVM binutils, `pip install pefile` for PE.
- Answer from evidence. In the answer, mark each claim as **seen** (cite file:offset, or a symbol/string) or **inferred**. A fact you did not find is **unknown**, not "absent". Static reading is not observed execution.
- A missing tool is not a blocker. Use the fallback in the same row, or install if the user allows (Install row at the bottom). WSL gives the full Linux toolchain: `wsl -e <cmd> (wsl wslpath -a 'D:\path\F')`.
- Turns cost more than bytes. Aim for 2–4 tool calls: one batched recon call, one or two targeted slices, then answer. Stop when every item you were asked has evidence. Do not re-verify what you already saw.

## Magic bytes (pwsh has no `file`)
```powershell
python -c "import sys;d=open(sys.argv[1],'rb').read(16);m={b'MZ':'PE',b'\x7fELF':'ELF',b'\xcf\xfa\xed\xfe':'Mach-O 64le',b'\xce\xfa\xed\xfe':'Mach-O 32le',b'PK\x03\x04':'zip/jar/APK',b'\x00asm':'WASM',b'SQLite format 3\x00':'SQLite',b'\xd4\xc3\xb2\xa1':'pcap-le',b'\x0a\x0d\x0d\x0a':'pcapng'};print(next((v for k,v in m.items() if d.startswith(k)),'unknown'),d[:16].hex())" T
```
.NET check on a PE: `rg -a -c -m1 '_CorExeMain|mscorelib|System.Runtime' T`. asar: trust the `.asar` extension; the first ~64 bytes contain `"files"`.

## First move: one call each, paste and run
Native PE (pefile path — zero external binutils needed):
```powershell
$T='.\bin.exe'; $D="$env:TEMP\re\$([IO.Path]::GetFileName($T))"; New-Item -ItemType Directory -Force $D | Out-Null; Copy-Item $T $D; Write-Host '--- VERSIONINFO'; (Get-Item $T).VersionInfo | fl ProductName,FileVersion,FileDescription,CompanyName; Write-Host '--- IMPORTS/EXPORTS'; python -c "import pefile,sys;p=pefile.PE(sys.argv[1],fast_load=True);p.parse_data_directories();print('DLLS:',*[e.dll.decode() for e in getattr(p,'DIRECTORY_ENTRY_IMPORT',[])]);print('EXPORTS:',*[(s.name or b'ord%d'%s.ordinal).decode() for s in getattr(getattr(p,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])][:120])" $T; Write-Host '--- STRINGS'; rg -a -o '[ -~]{6,}' $T | rg -v '^[_$.@]' | Select-Object -First 400 > "$D\strings.txt"; (Get-Content "$D\strings.txt").Count; Write-Host '--- IMPORTS via objdump'; objdump -p $T | rg 'DLL Name:' | Sort-Object -Unique
```
Disassembly needs a real disassembler (mingw64 objdump / `llvm-objdump` / r2 / Ghidra — see the native rows); strings + DLL list + exports usually answer "what is this" without it. When you have one: `objdump -d -M intel -C $T > "$D\dis.txt"`, index functions with `rg -n '^[0-9a-f]+ <[^>]+>:' "$D\dis.txt" | Select-Object -First 150`, slice one with `rg -A 80 '<FUNC_LABEL>:?' "$D\dis.txt" | rg 'call|cmp|lea|mov ' | Select-Object -First 40`.

Electron (Windows app: `resources\app.asar` under the install dir, e.g. `$env:LOCALAPPDATA\Programs\<App>`):
```powershell
$A='.\resources\app.asar'; $X="$env:TEMP\re\asar"; Remove-Item -Recurse -Force $X -ErrorAction SilentlyContinue; npx -y @electron/asar extract $A $X; node -p "const p=require(process.argv[1]+'/package.json');[p.name,p.version,'main:'+p.main].join(' ')" $X; rg --files -g '*.js' -g '*.node' -g '!**/node_modules/**' $X | Select-Object -First 60; Get-ChildItem "$A.unpacked\node_modules" -ErrorAction SilentlyContinue | Select-Object -First 20 Name; rg -uu -l --glob '!**/node_modules/**' 'exposeInMainWorld' $X
```
Then slice the needle across the bundle: `rg -uu -o --glob '!**/node_modules/**' '.{0,250}NEEDLE.{0,250}' $X | Select-Object -First 20`.

.NET:
```powershell
$T='.\Lib.dll'; $D="$env:TEMP\re\$([IO.Path]::GetFileName($T))"; New-Item -ItemType Directory -Force $D | Out-Null; ilspycmd -p -o "$D\src" $T; rg -n 'DllImport' "$D\src" -g '*.cs' | Select-Object -First 30
```

Go: `go version -m $T` alone usually answers the question.

## Router
| Target (detect) | Fastest path (Windows, pwsh) |
|---|---|
| Electron app (`resources\app.asar`) | `npx -y @electron/asar extract app.asar X` (also see `app.asar.unpacked\` for `.node` addons). Entry point: `node -p "require('./X/package.json').main"`. Surface: `rg -n -o '.{0,120}(ipcMain\.(handle\|handleOnce\|on\|once)\|ipcRenderer\.(invoke\|send\|sendSync\|on)\|contextBridge\.exposeIn(Main\|Isolated)World\|webPreferences\|preload:\|nodeIntegration\|contextIsolation\|sandbox\|\.node\b).{0,160}' -uu X --glob '!**/node_modules/**'`. App-specific IPC wrappers often hide the channels: also `rg -uu -o '"[a-z]+:[a-z0-9:-]+"' X\<main> \| Sort-Object -Unique`. Fuses: `npx -y @electron/fuses read --app <dir>` (cross-platform). |
| Web bundle / minified JS | Find `sourceMappingURL`. If the map has `sourcesContent`, dump the sources: `node -p "JSON.parse(require('fs').readFileSync(process.argv[1])).sources.join('\n')" F.map`. For webpack, grep the module ids, then slice around the hit. Pretty-print: `npx -y prettier --parser babel F > F.pretty.js`, then read with line ranges (`Get-Content F.pretty.js -TotalCount 40`, `-Tail`, or `Select-Object -Skip N -First 40`). |
| Hermes / bytenode / V8 snapshot | Hermes magic `c6 1f bc 03` (`index.android.bundle`): `pip install hermes-dec`, then `hermes-dec`/`hbc-decompiler`. `.jsc` (bytenode) cannot be decompiled: use strings and runtime hooks. |
| PE (MZ) | `pip install pefile` then the one-liner from First move (DLLs, exports; zero binutils). Or `llvm-readobj --coff-imports --coff-exports --file-headers T`, or `objdump -p/-x T` if yours is not a cygwin ghost, or with VS: `dumpbin /DEPENDENTS /IMPORTS /EXPORTS T`. Version info in one builtin call: `(Get-Item T).VersionInfo \| fl`. Resources/icons: pefile. |
| Native code logic | `objdump -d -M intel -C T > $D\dis.txt` or `llvm-objdump -d --no-show-raw-insn -C T` (both also do ELF; Mach-O needs `llvm-objdump --macho -d`). Find the function: `rg -n '<FuncName>?:' $D\dis.txt`. Slice: `rg -A 80 '<FuncName>:?' $D\dis.txt \| rg 'call\|cmp\|lea'`. Only for real pseudocode: Ghidra `analyzeHeadless.bat $D p -import T -postScript DecompileAll.java -deleteProject` or `r2 -qc 'aaa; pdc @ sym.X' T`. |
| Mach-O from Windows (`cf fa ed fe`) | Install LLVM once, it is cross-host: `llvm-lipo -info T` (arch/fat), `llvm-objdump --macho --syms --bind --lazy-bind --weak-bind T` (bindings = imports), `llvm-objdump --macho -d T` (disasm), `llvm-nm T`. ObjC class list: `llvm-objdump --macho --objc-meta-data T`. codesign/entitlements need macOS — mark unknown. |
| ELF from Windows (`7f 45 4c 46`) | `llvm-readobj --file-headers --program-headers --section-headers --dynamic-table T` (dependable), `llvm-nm T`; `readelf -hlSW`/`nm -D` only if not cygwin ghosts. Disasm: native row. |
| Go (`__go_buildinfo`, `.go.buildinfo`) | `go version -m T` gives toolchain, path, module, deps and build flags in one call. Without Go: `rg -a -o 'go1\.[0-9][^ ]{0,20}' T \| Sort-Object -Unique`. Symbols survive stripping: `go tool nm T \| rg 'main\.'`. |
| Rust | Deps (cargo-auditable): `cargo audit bin T`, or extract `.dep-v0` and zlib-inflate it. Compiler: `rg -a -o '/rustc/[0-9a-f]{40}' T \| Sort-Object -Unique`. Crates from paths: `rg -a -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' T \| Sort-Object -Unique`. |
| .NET (`_CorExeMain`/`mscorelib`) | `ilspycmd -p -o X T.dll` (install: `dotnet tool install -g ilspycmd`), then `rg`. P/Invoke: `rg DllImport X`. NativeAOT/IL2CPP are native: use the native rows. |
| Android APK | `jadx -d X --show-bad-code a.apk` then `rg` (needs Java). Manifest/resources only, no Java: `pip install androguard`, `androguard apkid a.apk`. Quick look: `tar -tf a.apk` (System32 bsdtar, built-in) — zip/jar/APK all list. `lib/*/libflutter.so` means Flutter (Dart AOT: `blutter`); `libhermes.so` means React Native (Hermes row). |
| Flutter snapshot hash | In `libapp.so`, find magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash: `rg -a -o 'f5f5dcdc.{40}' libapp.so` or dump the offset with `Format-Hex -Offset <off> -Count 64`. Map it to a Dart version. |
| WASM (`00 61 73 6d`) | `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT; zip/scoop build). Fallback: WSL. |
| SQLite | Copy the db, plus the `-wal` file if present. `sqlite3 'file:C?mode=ro' '.schema'`, then `SELECT * FROM t LIMIT 20`. Without sqlite3.exe: `python -c "import sqlite3,sys;c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);[print(r) for r in c.execute('select name from sqlite_master')]" C`. |
| plist (mac artifacts) | `python -c "import plistlib,pprint,sys;pprint.pprint(plistlib.load(open(sys.argv[1],'rb')))" Info.plist`. Info.plist holds bundle id, URL schemes, privacy strings. |
| pcap / HAR | tshark (Wireshark install, full path `& 'C:\Program Files\Wireshark\tshark.exe'`): `-r C -q -z conv,tcp`; `-T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri \| Sort-Object -Unique`. HAR: `python -c "import json,sys;[print(e['request']['method'],e['request']['url']) for e in json.load(open(sys.argv[1]))['log']['entries']]" C.har`. |
| Firmware | `binwalk -e F` (`pip install binwalk`) or WSL `unblob`. Then route each extracted binary through this table. Containers first: `tar -tf F` (bsdtar handles zip). |
| Installers (Windows-flavored) | MSI, built-in extract: `msiexec /a setup.msi /qn TARGETDIR=D:\re\out` (or `lessmsi x`). NSIS: `7z x setup.exe`. InnoSetup: `innounp -x -dD setup.exe`. Then route the payload through this table. |
| Website | `curl.exe -sL URL` for the HTML and script srcs (use `curl.exe`, not the `curl` alias for Invoke-WebRequest), then fetch the JS and slice it. For runtime behavior, use a headless browser with a network log (Playwright `page.on('request')`) or Chrome `--remote-debugging-port`. |
| Running app / runtime (Windows) | Crash info (builtin): `Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000} -MaxEvents 3 \| fl`. Loaded DLLs (builtin): `tasklist /m /fi "PID eq N"`. File/registry/net trace: Sysinternals ProcMon (`procmon /Quiet /Minimized /BackingFile t.pml`, later `/OpenLog t.pml /SaveAs t.csv`), `handle64 -p N`, `tcpvcon -a -n`. Packet capture, builtin: `pktmon start --capture -p N` … `pktmon etl2pcapng`. Debug: `frida -p PID -l hook.js` (pip, works on Windows), x64dbg (GUI). Electron main: `--inspect` (only if the fuses allow it). |

## Speed patterns
- For any PE, `(Get-Item T).VersionInfo | fl` answers version/company in one builtin call — try it before strings.
- Strings and imports first. On a small binary, the DLL list + strings + export list usually answer "what does it do" with no disassembly.
- To find who uses a string: `rg -n 'needle' $D\dis.txt` gives the address/context; then find the enclosing function label above that line.
- A C++ name in a `call` target already tells you the protocol (for example `getpeereid`, `write`, `std::hash`). Read the call sequence, not every instruction.
- For JS, go from the native/JS boundary inward: find the native call, then its caller class, then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (DLL list, exports, `go version -m`) before you diff any code.
- Rebuilding: write the minimal reimplementation, then test it against the original (same inputs, same outputs).

## Install (only on request)
`winget install LLVM.LLVM WiresharkFoundation.Wireshark Microsoft.OpenJDK.17` · `choco install 7zip sysinternals` · `npm i -g @electron/asar` · `dotnet tool install -g ilspycmd` · `pip install pefile androguard frida-tools hermes-dec binwalk` · `cargo install cargo-audit`. Ghidra: zip from ghidra-sre.org. If an id moved: `winget search <name>` / `choco search <name>`.

## Appendix: Git Bash (MSYS) shells — known issues
If the agent shell is Git Bash instead of pwsh, same router, different plumbing. The gotchas, collected:
- **MSYS rewrites `/switch` args of native exes into paths.** Prefix `MSYS_NO_PATHCONV=1` (dumpbin `/IMPORTS`, `msiexec /a`, `tar`). Paths are `/c/...` style; native exes that reject them want `cygpath -w P`.
- Temp dirs: `$TMPDIR` is often unset; `/tmp` works and maps into the Windows temp.
- **Quoting is inverted:** `python -c` payloads in single quotes with DOUBLE quotes inside (bash does not expand `$` in single quotes; pwsh-style double-wrapping gets `$`-expanded by bash).
- `jq` is not bundled: use `node -p` / `python -c`.
- `strings`/`objdump`/`nm`/`readelf` may be missing or be broken cygwin64 ghosts (see Rules). `head`, `sort -u`, `awk` (function slices), `find`, `ls` exist there — use them instead of `Select-Object`/`rg -A`.
- Running Windows exes that need quoting care: call pwsh explicitly: `pwsh -NoProfile -c '<command>'`.
