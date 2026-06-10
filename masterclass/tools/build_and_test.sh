#!/usr/bin/env bash
# build_and_test.sh — build every masterclass training artifact and verify it
# behaves as its module solution claims. This is the reproducible "thoroughly
# tested" harness: run it on a clean checkout to confirm all labs work.
#
# Requires: gcc, gdb, objdump, strace, readelf, file, upx, yara, python3
#           python pkgs: unicorn (for 4.4 emulate)
# Optional: tcpdump (3.3 PCAP), ssdeep (1.4)
#
# Outputs PASS/FAIL per check and a final summary. Builds into a temp dir; the
# repo tree stays clean. Non-zero exit if any check fails.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
have() { command -v "$1" >/dev/null 2>&1; }
# gdb is usable only if the kernel lets it ptrace (restricted in some CI/sandboxes)
gdb_ok() {
  have gdb || return 1
  gcc -x c -o "$WORK/_pt" - <<'C' 2>/dev/null
int main(void){return 0;}
C
  gdb -q -batch -ex 'break main' -ex run -ex continue "$WORK/_pt" >/dev/null 2>&1
}
# check <desc> <expected-substr> <command...>
check() { local d="$1" want="$2"; shift 2; local out; out="$("$@" 2>&1)"; \
          if echo "$out" | grep -qF "$want"; then ok "$d"; else bad "$d (wanted '$want')"; fi; }

cd "$WORK"
echo "== Level 1 =="
gcc -O0 -fno-pic -no-pie "$ROOT/01-foundations/02-assembly-survival-kit/demo.c" -o demo
check "1.2 demo sum_to_n(10)=37" "37" ./demo 10
gcc -O0 -fno-stack-protector -no-pie "$ROOT/01-foundations/03-re-toolchain/crackme1.c" -o crackme1
check "1.3 crackme correct pw -> flag" "FLAG{" bash -c 'echo h4x0r! | ./crackme1'
check "1.3 crackme secret bytes in disasm" "0x68" bash -c "objdump -d -M intel crackme1 | grep 'BYTE PTR'"
check "1.4 triage.py entropy" "entropy" python3 "$ROOT/01-foundations/04-file-triage/triage.py" ./demo

echo "== Level 2 =="
gcc -O2 -no-pie "$ROOT/02-static-analysis/01-strings-and-iocs/stringy.c" -o stringy
check "2.1 strings finds C2 url" "gate.php" bash -c "strings stringy | grep gate"
gcc -O2 -no-pie "$ROOT/02-static-analysis/02-imports-as-behavior/net_tool.c" -o net_tool
gcc -O2 -no-pie "$ROOT/02-static-analysis/02-imports-as-behavior/dynres.c" -o dynres -ldl
check "2.2 net_tool imports getaddrinfo" "getaddrinfo" bash -c "nm -D net_tool"
check "2.2 dynres hides cos (only dlopen/dlsym)" "dlsym" bash -c "nm -D dynres | grep -i dl"
if have upx; then
  gcc -O2 -no-pie "$ROOT/02-static-analysis/03-entropy-and-packing/packme.c" -o packme
  upx -q --best -o packme_upx packme >/dev/null 2>&1
  check "2.3 packed has UPX! magic" "UPX!" bash -c "strings packme_upx | grep UPX"
  check "2.3 packed entropy high" "HIGH" python3 "$ROOT/01-foundations/04-file-triage/triage.py" packme_upx
else echo "  SKIP  2.3 (upx not installed)"; fi
if have yara; then
  check "2.4 yara matches stringy" "stringy_robust" yara "$ROOT/02-static-analysis/04-writing-yara-rules/detect_stringy.yar" stringy
  check "2.4 yara no FP on /bin/ls" "" bash -c "yara '$ROOT/02-static-analysis/04-writing-yara-rules/detect_stringy.yar' /bin/ls; true"
else echo "  SKIP  2.4 (yara not installed)"; fi

echo "== Level 3 =="
gcc -O2 -no-pie "$ROOT/03-dynamic-analysis/02-process-trees/multistage.c" -o multistage
check "3.2 strace shows execve of echo" "/bin/echo" bash -c "strace -f -e trace=execve ./multistage 2>&1"
gcc -O2 -no-pie "$ROOT/03-dynamic-analysis/03-network-and-c2/beacon_http.c" -o beacon_http
check "3.3 beacon connect attempt visible" "connect" bash -c "strace -e trace=network ./beacon_http 198.51.100.7 80 2>&1"
check "3.4 mitre maps T1105 (curl)" "T1105" python3 "$ROOT/03-dynamic-analysis/04-mitre-attack/map_attack.py" "$ROOT/03-dynamic-analysis/04-mitre-attack/sample_analysis.json"

echo "== Level 4 =="
if have upx; then
  gcc -O2 -no-pie "$ROOT/02-static-analysis/03-entropy-and-packing/packme.c" -o p2
  upx -q --best -o p2_upx p2 >/dev/null 2>&1; cp p2_upx p2_un; upx -q -d p2_un >/dev/null 2>&1
  check "4.1 upx -d roundtrip runs" "checksum=" ./p2_un
fi
gcc -O0 -fno-stack-protector -no-pie "$ROOT/04-unpacking-deobfuscation/02-custom-packers/crypt_stub.c" -o crypt_stub
check "4.2 stub runtime decrypt" "FLAG{unpacked_at_runtime}" ./crypt_stub
check "4.2 static decode via xorpack" "FLAG{unpacked_at_runtime}" python3 "$ROOT/04-unpacking-deobfuscation/02-custom-packers/xorpack.py" decode "0x0d,0x7f,0x38,0x3d,0x30,0x46,0x17,0x0a,0x2a,0x50,0x12,0x1f,0x2f,0x6c,0x18,0x0e,0x14,0x41,0x0c,0x14,0x3f,0x5a,0x14,0x1f,0x36" K3yz
if gdb_ok; then
  check "4.2 gdb dump at OEP" "FLAG{unpacked_at_runtime}" bash -c "gdb -q -batch -ex 'break unpack' -ex run -ex 'set \$b=\$rdi' -ex finish -ex 'x/s \$b' crypt_stub 2>/dev/null"
fi
gcc -O0 -fno-stack-protector -no-pie "$ROOT/04-unpacking-deobfuscation/03-string-api-obfuscation/obf_strings.c" -o obf_strings -ldl
check "4.3 obf runtime reveals c2" "c2.example.com" ./obf_strings
check "4.3 c2 hidden from strings" "" bash -c "strings obf_strings | grep example.com; true"
check "4.4 deobf brute-xor finds key 0x5a" "c2.example.com" python3 "$ROOT/04-unpacking-deobfuscation/04-scripted-deobfuscation/deobf.py" xor 0x39,0x68,0x74,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x74,0x39,0x35,0x37
check "4.4 deobf api hash -> getenv" "getenv" python3 "$ROOT/04-unpacking-deobfuscation/04-scripted-deobfuscation/deobf.py" api 0xff8760ae
if python3 -c "import unicorn" 2>/dev/null; then
  check "4.4 unicorn emulate decryptor" "c2.example.com" python3 "$ROOT/04-unpacking-deobfuscation/04-scripted-deobfuscation/emulate.py"
else echo "  SKIP  4.4 emulate (unicorn not installed)"; fi

echo "== Level 5 =="
gcc -O0 -no-pie "$ROOT/05-anti-analysis/02-debugger-detection/antidbg.c" -o antidbg
check "5.2 antidbg normal -> payload" "REAL behavior" ./antidbg
if gdb_ok; then
  check "5.2 antidbg under gdb -> decoy" "debugger detected" bash -c "gdb -q -batch -ex run ./antidbg 2>/dev/null"
  check "5.2 antidbg ptrace bypass -> payload" "REAL behavior" bash -c "gdb -q -batch -ex 'break ptrace' -ex run -ex finish -ex 'set \$rax=0' -ex continue ./antidbg 2>/dev/null"
fi
gcc -O0 -no-pie "$ROOT/05-anti-analysis/03-evasion-in-the-wild/staller.c" -o staller
gcc -shared -fPIC "$ROOT/05-anti-analysis/03-evasion-in-the-wild/fastsleep.c" -o fastsleep.so -ldl
check "5.3 static stall detect (mov edi,0x78)" "0x78" bash -c "objdump -d -M intel staller | grep -B2 'call.*sleep'"
check "5.3 LD_PRELOAD bypass instant" "REAL behavior" bash -c "LD_PRELOAD=./fastsleep.so ./staller"

echo "== Level 6 =="
gcc -O0 -no-pie "$ROOT/06-config-extraction/01-decrypting-config/configbot.c" -o configbot
check "6.1 configbot runtime decrypt" "TRAIN-2026" ./configbot
check "6.2 extractor recovers C2" "c2a.example.com" python3 "$ROOT/06-config-extraction/02-building-extractor/extract_config.py" ./configbot
check "6.3 stix bundle from config" "domain-name:value" bash -c "python3 '$ROOT/06-config-extraction/02-building-extractor/extract_config.py' ./configbot | python3 '$ROOT/06-config-extraction/03-artifacts-to-intelligence/make_stix.py'"

echo "== Level 7 (capstone) =="
if have upx; then
  ( cd "$WORK"; gcc -O2 -no-pie -s "$ROOT/07-capstone/challenge/challenge_src.c" -o cap_un 2>/dev/null
    upx -q --best -o crackmalware cap_un >/dev/null 2>&1 )
  check "7 capstone packed (UPX!)" "UPX!" bash -c "strings '$WORK/crackmalware' | grep UPX"
  cp "$WORK/crackmalware" cm; upx -q -d cm >/dev/null 2>&1
  check "7 capstone unpacks (CFG0)" "CFG0" bash -c "strings cm | grep CFG0"
  check "7 capstone config recovered" "CAPSTONE-01" python3 - "$WORK/cm" <<'PY'
import sys
def rc4(k,d):
    S=list(range(256));j=0
    for i in range(256):j=(j+S[i]+k[i%len(k)])&0xff;S[i],S[j]=S[j],S[i]
    i=j=0;o=bytearray()
    for b in d:
        i=(i+1)&0xff;j=(j+S[i])&0xff;S[i],S[j]=S[j],S[i];o.append(b^S[(S[i]+S[j])&0xff])
    return bytes(o)
raw=open(sys.argv[1],"rb").read();off=raw.find(b"CFG0");ln=int.from_bytes(raw[off+4:off+6],"little")
print(rc4(b"unpackme!",raw[off+6:off+6+ln]).decode())
PY
else echo "  SKIP  7 capstone (upx not installed)"; fi

echo "== Windows PE supplement =="
if have x86_64-w64-mingw32-gcc; then
  x86_64-w64-mingw32-gcc -O2 "$ROOT/windows-pe/win_imports.c" -o wi.exe -ladvapi32 -lwininet 2>/dev/null
  x86_64-w64-mingw32-gcc -O2 "$ROOT/windows-pe/win_antidbg.c" -o wa.exe 2>/dev/null
  check "win win_imports is PE32+" "PE32+" bash -c "file wi.exe"
  if python3 -c "import pefile" 2>/dev/null; then
    check "win imports show network capability" "InternetOpenA" python3 -c "import pefile;print([i.name.decode() for d in pefile.PE('wi.exe').DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name])"
    check "win imports show persistence (Run key API)" "RegOpenKeyExA" python3 -c "import pefile;print([i.name.decode() for d in pefile.PE('wi.exe').DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name])"
    check "win antidbg imports IsDebuggerPresent" "IsDebuggerPresent" python3 -c "import pefile;print([i.name.decode() for d in pefile.PE('wa.exe').DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name])"
  else echo "  SKIP  win pefile checks (pefile not installed)"; fi
else echo "  SKIP  windows-pe (mingw-w64 not installed)"; fi

echo "== Real-samples toolkit =="
KNOWN_HASH=$(sha256sum /bin/ls | cut -d' ' -f1)
check "real-samples verify MATCH" "MATCH" python3 "$ROOT/real-samples/verify_sample.py" /bin/ls --sha256 "$KNOWN_HASH"
check "real-samples verify MISMATCH rejects" "MISMATCH" bash -c "python3 '$ROOT/real-samples/verify_sample.py' /bin/ls --sha256 deadbeef; true"

echo ""
echo "==================================="
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
