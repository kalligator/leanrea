# leanrea

One skill file that does what [REA](https://github.com/morluto/rea) does: plain local CLI tools, no MCP server, no 207 tools, no setup.

Benchmarked: 38% faster, 35% cheaper.

REA puts an MCP layer between your agent and tools it can already use: `readelf`, `objdump`, `nm`, `strings`, `otool`, `asar`, `go version -m`, `jadx`, `apktool`, `ghidra`, `tshark`, `binwalk`, `sqlite3`. leanrea drops that layer. It tells the agent which command is fastest for each target, gives it ready-to-paste recon commands, and lists the traps. The agent then runs the real tools itself.

| Metric | REA 6.5.0 | leanrea |
|---|---|---|
| What gets installed | 25 MB npm package + MCP server | one `SKILL.md` |
| Instructions | 23.5 KB skill + 48.8 KB references | ~12 KB |
| Tools added to the agent | 207 (3.35 MB of definitions) | 0 (uses Bash / system CLI) |
| Context for "Reply OK", all tools loaded | 400.7k tokens, $1.60 | 34.5k tokens, $0.09 |

---

## What this fork adds over upstream

This fork (`kalligator/leanrea`) builds on upstream [`aicodeking/leanrea`](https://github.com/aicodeking/leanrea) by integrating community fixes, adding first-class Linux and Windows support, expanding mobile coverage, and fixing execution bugs.

| Area | Upstream (`aicodeking/leanrea`) | This Fork (`kalligator/leanrea`) |
|---|---|---|
| **Linux Support** | macOS-centric (`otool`, `lipo`, APFS `cp -c`) | First-class Linux parity: ELF recon first move, stripped binary analysis (`elf_helpers.sh`), runtime `/proc` inspection, and package extraction (AppImage, deb, rpm, snap, flatpak) |
| **Windows Support** | Mentioned in notes | Full PE recon, LLVM tool mapping, PowerShell 7 support, and mmap string search for large binaries (`pe_strings_mmap.py`) |
| **Mobile Coverage** | Basic APK decompilation note | iOS IPA unpacking, Core Data `.mom` schema archaeology, and Android Retrofit/OkHttp/Gson API reconstruction |
| **Command Execution** | Tables with escaped backslash-pipes that agents copy literally | Clean Markdown lists with literal, unescaped copy-pasteable pipes across all skills |
| **Stripped Binaries** | Assumes function symbols exist; Go `-s -w` unhandled | `elf_helpers.sh` (`str2va` for RIP-relative string offsets, Intel CET `endbr64` boundary detection, call trail); `.gopclntab` symbol recovery |
| **Headless Decompilation** | References non-existent `DecompileAll.java` | Ships working [`leanrea/scripts/DecompileAll.java`](leanrea/scripts/DecompileAll.java) with `-loader-libraryLoadDepth 0` to prevent hangs |
| **Large Binaries (>100 MB)** | `llvm-strings` fails silently on large Windows PEs | Ships [`leanrea/scripts/pe_strings_mmap.py`](leanrea/scripts/pe_strings_mmap.py) (zero-copy mmap for ASCII + UTF-16LE) |
| **Path Safety & Quoting** | Bare unquoted `$TMPDIR`, unquoted paths | Strict path quoting, safe `${TMPDIR:-/tmp}` fallback, `mktemp -d` isolation, fixed upstream typos |
| **Benchmark Runner** | macOS only (`cp -c`), hardcoded to Claude Code | Cross-platform (`shutil`), configurable runner (`BENCH_AGENT`, `BENCH_AGENT_CMD`) |
| **Modular Domain Rules** | Single monolithic file | Fast-path `SKILL.md` plus specialized deep-dive rules in `leanrea/rules/` |

### Key Improvements

- **First-class Linux enablement**:
  - Direct ELF first-move command using `readelf`, `nm`, `strings`, and `objdump`.
  - Added [`leanrea/scripts/elf_helpers.sh`](leanrea/scripts/elf_helpers.sh) with helper functions for stripped binaries: `str2va` (maps strings in `.rodata` to virtual addresses for RIP-relative disasm grep), `fstarts` / `fnof` (function boundary detection via Intel CET `endbr64`), and `trail` (extracts call/jump flow without noise).
  - Native Linux packaging extraction: AppImage (`--appimage-extract`), Debian (`dpkg-deb -x`), RPM (`rpm2cpio | cpio`), Snap (`unsquashfs`), and Flatpak.
  - Linux runtime inspection: `/proc/PID/maps`, `/proc/PID/fd`, `ss -xp`, `strace`, `ltrace`, and `gdb`.
  - Distro-specific package manager commands for Debian/Ubuntu, Fedora/RHEL, and Arch Linux.
  - Replaced macOS APFS `cp -c` with Linux `cp --reflink=auto` (GNU `cp -c` preserves SELinux context instead of cloning).
- **Windows PE & PowerShell 7**:
  - Full tool mappings for LLVM tools (`llvm-objdump`, `llvm-readobj`, `llvm-nm`).
  - Added [`leanrea/scripts/pe_strings_mmap.py`](leanrea/scripts/pe_strings_mmap.py) to resolve `llvm-strings` silently returning empty output on binaries over 100 MB, with support for UTF-16LE wide strings.
  - Native PowerShell 7 idioms and MSYS/Git Bash appendix in [`leanrea/WINDOWS.md`](leanrea/WINDOWS.md).
- **Mobile analysis**:
  - iOS IPA unpacking, executable extraction, and Core Data `.mom` schema migration archaeology.
  - Android JADX decompilation, Retrofit HTTP endpoint extraction, OkHttp interceptor detection, and serialized data model mapping.
- **Reliable headless Ghidra**:
  - Ships [`leanrea/scripts/DecompileAll.java`](leanrea/scripts/DecompileAll.java).
  - Adds `-loader-libraryLoadDepth 0` flag to prevent Ghidra from recursively importing system libraries and exhausting memory.
- **Electron stability**:
  - Handles `app.asar.unpacked/` presence requirement to prevent `asar extract` ENOENT errors when native modules are present.
- **Clean copy-paste commands**:
  - Router converted from tables to lists so shell pipes (`|`) are literal and paste cleanly without backslash escape syntax errors.

---

## Benchmark

Claude Code headless (`claude -p`), Sonnet 5.5, macOS arm64. 4 reverse-engineering tasks × 3 reps × 3 arms, with the arms run side by side. Answers are graded against hand-made keys.

| Arm | Total Wall Time | Cost | Turns | Tokens | Score |
|---|---|---|---|---|---|
| **leanrea** | **388 s** | **$2.17** | **55** | **2.40 M** | 74/75 |
| no skill | 479 s | $2.21 | 81 | 3.11 M | 67/75 (one refusal) |
| REA (MCP + its skill) | 627 s | $3.36 | 124 | 5.93 M | 75/75 |

Against REA, leanrea had **38% less wall time, 35% lower cost, 56% fewer turns and 60% fewer tokens, at the same accuracy**. Its one partial miss named an older IPC channel instead of the v2 one (both channels exist).

The tasks:
- **electron**: trace a feature through a real Electron app's `app.asar` (native function → main-process class → IPC channels).
- **native**: inventory the exports, a TCC permission check and the single-instance lock of that app's native addon (`.node`).
- **go**: toolchain and dependency versions of a stripped `gh` binary.
- **deep**: from disassembly alone, the exact socket path format, wire protocol and peer authentication of that lock.

The same operation run through REA's CLI vs the raw command:

| Operation | REA CLI | Raw CLI |
|---|---|---|
| Go build info | 0.56 s | `go version -m`: 0.06 s |
| Mach-O overview | 3.32 s | `otool` + `dyld_info` + `nm`: 0.04 s |
| Electron app analysis (real desktop app) | Fails on asar integrity until flag passed, then **47.9 s and 140 MB of JSON** | `asar extract` + `rg -uu`: 4.8 s, 24 KB |

Full benchmark tables, context overhead probe, and methodology are in [bench/BENCHMARK.md](bench/BENCHMARK.md).

---

## Install

```sh
npx skills add kalligator/leanrea
```

This uses the [skills CLI](https://skills.sh). It installs `leanrea` for any supported agent (Antigravity, Claude Code, Codex, Cursor, Gemini CLI, OpenCode, etc.).

Common variants:
```sh
npx skills add kalligator/leanrea -g                    # install globally for your user
npx skills add kalligator/leanrea -a claude-code -y     # Claude Code only, no prompts
npx skills add kalligator/leanrea -g -a '*' -y          # every supported agent
npx skills update leanrea                               # pull latest updates
```

Specialized variants:
```sh
npx skills add kalligator/leanrea/leanrea-linux        # Linux ELF-specialized skill
npx skills add kalligator/leanrea/leanrea-win          # Windows PowerShell 7-specialized skill
```

Manual install:
```sh
git clone https://github.com/kalligator/leanrea
mkdir -p ~/.claude/skills && cp -R leanrea/leanrea ~/.claude/skills/
```

If an agent has no skill directory support, `SKILL.md` is plain markdown: paste it directly into rules or system prompts.

Use it:
```
/leanrea How does the search feature in Foo.app work? Show the evidence.
```

---

## Ready-to-Use Prompts

Looking for specific prompts to copy-paste into your agent? See [**`PROMPTS.md`**](PROMPTS.md) for 20+ structured prompts covering:
- **Feature Tracing**: Follow code flow from UI triggers to network/filesystem effects.
- **Native Binaries**: ELF/PE/Mach-O triage, stripped Linux binaries (`elf_helpers.sh`), large Windows PEs (`pe_strings_mmap.py`), and wire protocol extraction.
- **Clean-Room Cloning**: Extract behavior and write complete specifications without touching proprietary assets.
- **Mobile & Embedded**: iOS IPA auditing, Core Data `.mom` schema archaeology, Android APKs, and firmware image triage.
- **Electron & JavaScript**: IPC context-bridge audits and minified bundle reverse engineering.
- **Vulnerability & Crash Triage**: Trust boundary audits, patch diffing, and crash root-cause investigation.

---

## Toolchain Installation (On Demand)

leanrea uses standard tools already present on most developer setups or available via package managers:

- **Linux (Debian / Ubuntu)**:
  ```sh
  sudo apt install binutils file ripgrep jq radare2 binwalk squashfs-tools p7zip-full acpica-tools dmidecode flashrom pciutils usbutils tshark strace ltrace gdb wabt sqlite3 qemu-user-static icoutils innoextract msitools python3-pefile
  ```
- **Linux (Fedora / RHEL)**:
  ```sh
  sudo dnf install binutils file ripgrep jq radare2 binwalk squashfs-tools p7zip acpica-tools dmidecode flashrom pciutils usbutils wireshark-cli strace ltrace gdb wabt sqlite qemu-user-static icoutils innoextract msitools python3-pefile
  ```
- **Linux (Arch Linux)**:
  ```sh
  sudo pacman -S binutils file ripgrep jq radare2 binwalk squashfs-tools p7zip acpica dmidecode flashrom pciutils usbutils wireshark-cli strace ltrace gdb wabt sqlite qemu-user-static icoutils innoextract msitools python-pefile
  ```
- **macOS (Homebrew)**:
  ```sh
  brew install jadx apktool radare2 binwalk wabt wireshark ghidra ripgrep jq
  ```
- **Windows (winget)**:
  ```powershell
  winget install BurntSushi.ripgrep.MSVC jqlang.jq LLVM.LLVM Microsoft.DotNet.SDK.9
  ```

---

## Security Alert: Upstream Fork Malicious Activity

During our audit of forks, we inspected `defiphoenix/leanrea` and found an active backdoor campaign.

The repository contained a zero-click VS Code task configuration (`.vscode/tasks.json` with `"runOn": "folderOpen"`) executing an obfuscated JavaScript dropper disguised as font files (`fa-solid-700.otf`, `fa-solid-400.woff2`). The dropper queries an Ethereum Dead Drop Resolver (DDR) via transaction input data from wallet address `0x1eEf0849EDa15d87f64e51C73C8442Cf3c8bCEF3` to resolve C2 IP addresses and execute remote payloads.

Scanning revealed this same payload seeded across over 60 repositories under that account. The malicious fork was completely excluded, and a abuse report was submitted to GitHub Trust & Safety.

Do **not** clone or open workspaces from `defiphoenix`.

---

## Credits & Attribution

This project is a fork that integrates work from the community. We gratefully credit the original authors and contributors whose commits and PRs were incorporated:

- **AICodeKing** ([`aicodeking/leanrea`](https://github.com/aicodeking/leanrea)): Original author of `leanrea`, benchmark design, sandbox runner, and router unescaped pipe conversion (PR #4, PR #6).
- **jarnowu** ([upstream PR #5](https://github.com/aicodeking/leanrea/pull/5)): Author of the headless Ghidra script [`DecompileAll.java`](leanrea/scripts/DecompileAll.java), the `-loader-libraryLoadDepth 0` flag to prevent recursive library loading hangs, and `asar.unpacked` handling.
- **madbullahi** ([upstream PR #8](https://github.com/aicodeking/leanrea/pull/8)): Author of `leanrea-linux`, Linux packaging format handling, hardware/firmware tables (ACPI/DMI/USB), and `/proc` runtime inspection.
- **shelltian** ([`shelltian/leanrea`](https://github.com/shelltian/leanrea)): Author of the initial Windows compatibility layer ([`leanrea/WINDOWS.md`](leanrea/WINDOWS.md)), LLVM tool mapping, and field findings on `llvm-strings` >100 MB behavior.
- **alwaysmy** ([`alwaysmy/leanrea-win`](https://github.com/alwaysmy/leanrea-win)): Author of the native PowerShell 7 skill and MSYS/Git Bash appendix.
- **Kewk** ([`KewkLW/leanrea`](https://github.com/KewkLW/leanrea)): Author of the iOS IPA workflow, Core Data `.mom` schema migration archaeology, and Android Retrofit/OkHttp/Gson API reconstruction.
- **morluto** ([`morluto/rea`](https://github.com/morluto/rea)): Author of REA (Reverse Engineer Anything), the comprehensive framework that established the reference targets and gotchas that inspired `leanrea`.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
