/*
 * win_antidbg.c — Windows PE anti-debug training sample. BENIGN.
 *
 * The Windows analogue of Module 5.2. Demonstrates the two most common Windows
 * anti-debug checks so you can recognize them statically in a real PE:
 *
 *   1. IsDebuggerPresent()  — a kernel32 import; reads PEB->BeingDebugged.
 *   2. Direct PEB read      — checks BeingDebugged without the API, so no
 *                             tell-tale import appears (stealthier).
 *
 * If it thinks it's being debugged it runs a decoy; otherwise the "payload"
 * (benign — just prints). Analyze the import table and the PEB access pattern.
 *
 * Build:  x86_64-w64-mingw32-gcc -O2 win_antidbg.c -o win_antidbg.exe
 * Static: pefile shows IsDebuggerPresent in kernel32 imports.
 * Dynamic: run in your Windows VM / Detonate Windows (QEMU) sandbox; bypass by
 *          patching the checks (same idea as Module 5.2's ptrace bypass).
 */
#include <windows.h>
#include <stdio.h>

/* Read PEB->BeingDebugged directly (x64: gs:[0x60] -> PEB, +0x02 = BeingDebugged).
 * We read the raw byte so no API import (and no winternl struct) is needed. */
static int peb_being_debugged(void) {
#if defined(__x86_64__)
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    return peb[2];   /* offset 0x02 = BeingDebugged */
#else
    return 0;
#endif
}

int main(void) {
    if (IsDebuggerPresent() || peb_being_debugged()) {
        printf("system check failed\n");   /* decoy */
        return 0;
    }
    printf("[payload] REAL behavior executed\n");
    return 0;
}
