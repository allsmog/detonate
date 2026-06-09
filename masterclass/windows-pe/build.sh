#!/usr/bin/env bash
# build.sh — cross-compile the Windows PE training samples on Linux.
# Requires mingw-w64:  sudo apt-get install gcc-mingw-w64-x86-64
# Produces gitignored .exe files you analyze statically (pefile/objdump) and,
# for the dynamic steps, run in a Windows VM or Detonate's Windows sandbox.
set -euo pipefail
cd "$(dirname "$0")"
CC=x86_64-w64-mingw32-gcc

echo "[*] win_imports.exe (file + persistence + network imports)"
$CC -O2 win_imports.c  -o win_imports.exe  -ladvapi32 -lwininet
echo "[*] win_antidbg.exe (IsDebuggerPresent + direct PEB read)"
$CC -O2 win_antidbg.c  -o win_antidbg.exe
echo "[+] built win_imports.exe, win_antidbg.exe"
file win_imports.exe win_antidbg.exe
