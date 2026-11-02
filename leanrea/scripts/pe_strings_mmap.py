#!/usr/bin/env python3
"""
pe_strings_mmap.py - Fast memory-mapped string search for large PE / ELF / Mach-O binaries.
Solves the llvm-strings truncation / empty output bug on binaries > 100 MB.
Searches both ASCII and UTF-16LE (wide strings) with zero-copy mmap.

Usage:
    python3 pe_strings_mmap.py <target_binary> [search_pattern] [--max-results 50]
"""

import sys, os, mmap, re, argparse

def search_binary(path, pattern_str=None, min_len=6, max_results=50, encoding="both"):
    if not os.path.exists(path):
        print(f"Error: file '{path}' does not exist", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(path)
    if file_size == 0:
        print(f"File '{path}' is empty", file=sys.stderr)
        return

    with open(path, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception as e:
            print(f"mmap failed: {e}", file=sys.stderr)
            sys.exit(1)

        results = 0
        if pattern_str:
            patterns = []
            if encoding in ("both", "ascii"):
                patterns.append(("ASCII", pattern_str.encode("utf-8", "ignore")))
            if encoding in ("both", "utf16"):
                patterns.append(("UTF-16LE", pattern_str.encode("utf-16-le", "ignore")))

            for enc_label, needle in patterns:
                pos = 0
                while results < max_results:
                    pos = mm.find(needle, pos)
                    if pos == -1:
                        break
                    start = max(0, pos - 40)
                    end = min(len(mm), pos + len(needle) + 60)
                    context = mm[start:end]
                    
                    # Clean snippet for display
                    if enc_label == "ASCII":
                        snippet = context.decode("ascii", "replace").replace("\n", " ").replace("\r", " ")
                    else:
                        snippet = context.decode("utf-16-le", "replace").replace("\n", " ").replace("\r", " ")
                    
                    print(f"[0x{pos:08x}] ({enc_label}) ... {snippet} ...")
                    results += 1
                    pos += 1
        else:
            # Extract printable ASCII strings >= min_len
            regex = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
            for match in re.finditer(regex, mm):
                if results >= max_results:
                    break
                print(f"[0x{match.start():08x}] {match.group().decode('ascii', 'ignore')}")
                results += 1

        mm.close()

def main():
    parser = argparse.ArgumentParser(description="Memory-mapped ASCII & UTF-16LE string search for large binaries.")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("pattern", nargs="?", default=None, help="Specific substring to find (ASCII + UTF-16LE)")
    parser.add_argument("-n", "--min-len", type=int, default=6, help="Minimum string length when dumping (default: 6)")
    parser.add_argument("-m", "--max-results", type=int, default=50, help="Max results to print (default: 50)")
    parser.add_argument("--encoding", choices=["both", "ascii", "utf16"], default="both", help="Encoding to search")
    args = parser.parse_args()

    search_binary(args.binary, args.pattern, min_len=args.min_len, max_results=args.max_results, encoding=args.encoding)

if __name__ == "__main__":
    main()
