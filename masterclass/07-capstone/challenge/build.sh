#!/usr/bin/env bash
# build.sh — produce the capstone challenge binary `crackmalware` from source.
#
# Instructors run this to generate the artifact learners analyze. The compiled
# binary is gitignored (no committed binaries — SAFETY.md); learners receive
# only `crackmalware`, NOT challenge_src.c or SOLUTION.md.
#
# Requires: gcc, upx
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] compiling challenge_src.c ..."
gcc -O2 -no-pie -s challenge_src.c -o crackmalware_unpacked   # -s strips symbols

echo "[*] UPX-packing -> crackmalware ..."
upx -q --best -o crackmalware crackmalware_unpacked >/dev/null

rm -f crackmalware_unpacked
echo "[+] built ./crackmalware"
echo "    sha256: $(sha256sum crackmalware | cut -d' ' -f1)"
echo "    Hand learners ONLY ./crackmalware (not the source or SOLUTION.md)."
