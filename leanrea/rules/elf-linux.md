# Linux ELF & Native Reverse Engineering Guide

This guide details high-efficiency reverse engineering techniques for Linux ELF executables and shared libraries (`.so`), with special focus on stripped binaries, modern packaging formats, and runtime inspection.

## 1. Quick Reconnaissance (One Tool Call)

```sh
T=./target_bin; D=$(mktemp -d "${TMPDIR:-/tmp}/re-$(basename "$T").XXXXXX")
echo "Extraction directory: $D"
file -b "$T"
echo '--- HEADER'; readelf -hW "$T" | rg 'Class|Machine|Type|Entry point'
echo '--- DYNAMIC DEPENDENCIES'; readelf -dW "$T" | rg 'NEEDED|RUNPATH|RPATH|SONAME'
echo '--- EXPORTED SYMBOLS'; nm -D --defined-only "$T" 2>/dev/null | head -150
echo '--- IMPORTED SYMBOLS'; nm -D --undefined-only "$T" 2>/dev/null | awk '{print $NF}' | tr '\n' ' '; echo
echo '--- STRINGS'; strings -a -n 5 "$T" | rg -v '^[_.$]|^GLIBC|^GCC' | head -300
objdump -d -M intel --no-show-raw-insn -C "$T" > "$D/dis.txt"
echo '--- FUNCTIONS'; rg '^[0-9a-f]+ <.*>:$' "$D/dis.txt" | rg -v '@plt>' | head -150
```

## 2. Stripped Binaries Without Labels

When `strip --strip-all` or `strip --strip-unneeded` has been run, function labels are absent from `.text` (only `<.text>` appears). Use these techniques:

### A. String to Virtual Address (`str2va`)
`objdump` comments RIP-relative references with addresses, not string literals. Find the address of a string in `.rodata`:
```sh
# Calculate VA of string in ELF section
source leanrea/scripts/elf_helpers.sh
VA=$(str2va "$T" "needle_string" | cut -d' ' -f1)
echo "String VA: 0x$VA"
# Grep disassembly for instructions referencing this address
rg -n "# $VA <" "$D/dis.txt"
```

### B. Function Boundary Recovery (`endbr64`)
Modern Linux distributions (Ubuntu >= 20.04, Debian >= 11, Fedora, Arch) compile C/C++ with Intel CET (`-fcf-protection=full`). Every function entry point begins with the `endbr64` instruction.
```sh
# Locate function starts and trace the target function:
fstarts "$D/dis.txt" | head -30
FN=$(fnof "$D/dis.txt" <ref-address>)
echo "Function start: 0x$FN"
trail "$D/dis.txt" "$FN"
```
The resulting call/branch trail reveals external calls (`connect`, `send`, `write`, `getpeername`), comparisons, and logic without manual disassembly of every opcode.

### C. Fallback for Non-CET Stripped Binaries
If `endbr64` is absent:
- Use radare2: `r2 -qc 'aaa; axt @ str.needle' "$T"`
- Use headless Ghidra: `analyzeHeadless "$D" proj -import "$T" -loader-libraryLoadDepth 0 -scriptPath leanrea/scripts -postScript DecompileAll.java "$D/out.c" -deleteProject`

## 3. Go Binaries Stripped with `-s -w`
Go binaries built with `-ldflags="-s -w"` report "no symbols" to `go tool nm`. However:
1. Toolchain, module path, and dependency versions are still present: `go version -m "$T"`
2. Function and file names are retained in the runtime `.gopclntab` table:
```sh
strings -a "$T" | rg -m 1 -A 200 'Go buildinf'
strings -a "$T" | rg '(main\.[A-Za-z0-9_]+|github\.com/[A-Za-z0-9_/-]+)' | sort -u | head -100
```

## 4. Linux Packaging Formats to `app.asar` or Native Binaries

- **AppImage**:
  `chmod +x app.AppImage && ./app.AppImage --appimage-extract` (extracts to `./squashfs-root/`)
- **Debian (`.deb`)**:
  `dpkg-deb -x package.deb "$D/deb_root"`
- **Red Hat / Fedora (`.rpm`)**:
  `rpm2cpio package.rpm | (cd "$D" && cpio -idmv)`
- **Snap**:
  `unsquashfs -d "$D/snap" /var/lib/snapd/snaps/package.snap`
- **Flatpak**:
  Inspect `/var/lib/flatpak/app/<app-id>/current/active/files/`

## 5. Runtime Inspection (`/proc`)
- Memory mappings and loaded libraries: `cat /proc/$PID/maps`
- Open file descriptors and sockets: `ls -l /proc/$PID/fd`
- Network socket binding: `ss -tlpn | rg "$PID"`
- Unix domain sockets: `ss -xp | rg "$PID"`
- Syscall tracing: `strace -f -s 512 -e trace=network,file -p "$PID"`
