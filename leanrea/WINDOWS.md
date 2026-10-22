# Windows 兼容层（本地补丁）

这个技能原版是 macOS 写的，`first move` 里大量用 `otool` / `lipo` / `nm -gU`（Mach-O 专属）。
在 Windows 上请按下面的映射执行，**不要照抄原文件里的 macOS 命令**。

## 已装工具

| 工具 | 命令 | 来源 |
|---|---|---|
| ripgrep | `rg` | winget: BurntSushi.ripgrep.MSVC |
| jq | `jq` | winget: jqlang.jq |
| file | `file` | winget: GnuWin32.File → `C:\Program Files (x86)\GnuWin32\bin` |
| strings | `llvm-strings`（**不要用 Sysinternals 的 `strings`，本机实测输出为空**） | winget: LLVM.LLVM |
| objdump / nm / readobj | `llvm-objdump` `llvm-nm` `llvm-readobj` | winget: LLVM.LLVM → `C:\Program Files\LLVM\bin` |
| PE 解析库 | `pefile` `capstone` | venv: `C:\Users\w30812.H3C\.workbuddy-ai\binaries\python\envs\default` |
| node / npx | `npx` | 已装（Electron asar 提取可用） |

不可用：`otool` `lipo` `dtrace` `fs_usage` `lldb`（无 Xcode）；`wsl` 被安全策略禁用。

## 命令映射（macOS → Windows）

| 用途 | macOS（原技能写法） | Windows 用这个 |
|---|---|---|
| 文件类型 | `file -b T` | `file -b T`（相同） |
| 架构信息 | `lipo -info T` | `llvm-objdump -p T \| head -5` |
| 导入表 | `otool -L T` | `llvm-objdump -p T`（看 `DLL Name:` 段）或 `llvm-readobj --coff-imports T` |
| 导出符号 | `nm -gU T` | `llvm-nm --extern-only --defined-only T` 或 `llvm-objdump -p T`（`Export Table`） |
| 未定义符号 | `nm -u T` | `llvm-nm --undefined-only T` |
| 反汇编 | `otool -tV T` | `llvm-objdump -d T` |
| 字符串 | `strings -a -n 6 T` | `llvm-strings -n 6 T` |
| 头部/节表 | `readelf -hlSW` | `llvm-readobj --file-headers --sections T` |
| 动态依赖 | `readelf -dW` | `llvm-readobj --coff-imports T` |
| 资源节 | `wrestool` | `llvm-readobj --coff-resources T` |
| 临时目录 | `$TMPDIR` | `%TEMP%`（Git Bash 里是 `$TEMP` 或 `/tmp`） |
| 硬链接复制 | `cp -c`（APFS 快照） | `cp -r`（Windows 无 CoW，直接复制） |
| 装工具 | `brew install X` | `winget install X` |

## Windows 版 first move（PE 可执行文件，一条命令跑完）

```sh
T=./target.exe; D="${TEMP:-/tmp}/re/$(basename $T)"; mkdir -p "$D"
file -b "$T"
llvm-objdump -p "$T" | head -60
echo '--- IMPORTS'; llvm-readobj --coff-imports "$T" 2>/dev/null | grep -E 'Name:|Symbol:' | head -80
echo '--- EXPORTS'; llvm-nm --extern-only --defined-only "$T" | head -150
echo '--- STRINGS'; llvm-strings -n 6 "$T" | rg -v '^[_$.]' | head -300
llvm-objdump -d "$T" > "$D/dis.txt"; echo '--- FUNCS'; rg -n '^[0-9a-f]+ <' "$D/dis.txt" | head -150
```

读单个函数：

```sh
awk '/^[0-9a-f]+ <NAME>:/{p=1} p&&/^[0-9a-f]+ <.*>:/&&!/NAME/{exit} p' "$D/dis.txt" | rg 'call|jmp|cmp|lea|mov'
```

## Windows 版 Electron 提取（可用，与原版一致）

```sh
A=./app.asar; X="${TEMP:-/tmp}/re/asar"; rm -rf "$X"
npx -y @electron/asar extract "$A" "$X"
jq '{name,version,main}' "$X/package.json"
rg -uu -l --glob '!node_modules' 'exposeInMainWorld|contextBridge' "$X" | head -20
```

## .NET 程序

`llvm-objdump` 对 .NET 只能看到 CLR 头。要读 IL 请用：

```sh
winget install Microsoft.DotNet.SDK.9
dotnet tool install -g ilspycmd
ilspycmd target.dll > out.cs
```

## 明确不可用的部分

- **Mach-O / iOS / macOS 二进制分析**：`otool`、`lipo`、`dyld_info`、code signing 相关全部不可用。请换 macOS 机器。
- **Sysinternals `strings`**：本机实测无输出（疑似 EULA 交互被非交互环境阻断），请统一改用 `llvm-strings`。
- **运行时追踪**：`dtrace`、`fs_usage`、`log stream`、`lldb -p` 在 Windows 上都不存在。替代是 Sysinternals 的 `procexp` / `procmon`（winget 可装）。
- **Android（jadx/apktool/adb）**：工具可装，但需要 Android SDK 与设备，未在本机配置。

## 环境变量生效说明

新加的 PATH（GnuWin32、LLVM）已经写入用户级环境变量，但**当前已打开的终端和应用不会自动刷新**。
如果在本会话里发现 `file` 或 `llvm-objdump` 找不到，先在命令前加上：

```sh
export PATH="/c/Program Files/LLVM/bin:/c/Program Files (x86)/GnuWin32/bin:$PATH"
```

## 实战反馈（2026-10-22，首次运行）

以下两条是分析 `C://Program Files\aiwork\aiwork.exe`（195 MB Electron 应用）时实际踩到的，
已在真实目标上复现：

### 1. `llvm-strings` 在大文件上失效
对一个 195 MB 的 PE，`llvm-strings -n 6 T | rg ...` **不报错但输出为空**（对 3 MB 以内的文件正常）。
超过约 100 MB 时改用 Python mmap 分块搜索：

```sh
python -c "
import mmap
p=r'TARGET.exe'; f=open(p,'rb'); m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
b=b'Chrome/'; i=m.find(b)
print(m[i:i+60].split(b'\x00')[0].decode('ascii','replace') if i>=0 else 'not found')"
```

同时要搜 UTF-16LE（`pat.encode('utf-16-le')`）：Electron 的窗口名、路径常量多为宽字符。

### 2. GnuWin32 `file` 会误判新版 Electron
`file -b` 对 Electron 主程序返回 `PE32+ executable ... Mono/.Net assembly` —— **这是误报**，
GnuWin32 file 5.03 的 magic 库太老。不要据此判定为 .NET。
交叉验证方式：看节表里有没有 `.text` 超过 100 MB、以及 `LICENSES.chromium.html` / `icudtl.dat` / `chrome_*.pak` 是否同目录。

### 3. 不要对超大 PE 做全量反汇编
165 MB 的 `.text` 会产生数十 GB 文本。用 `llvm-objdump -p`（只读头部）+ `pefile` + 定向字符串，
三者组合足以回答"这是什么、什么版本、依赖什么、怎么打包"。
