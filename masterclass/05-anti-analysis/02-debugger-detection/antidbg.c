/*
 * antidbg.c — training sample for Module 5.2 (anti-debug). BENIGN.
 *
 * Uses the classic Linux self-debug check: a process can be ptrace'd by only
 * ONE tracer. The program calls ptrace(PTRACE_TRACEME): if it SUCCEEDS, no
 * debugger is attached (it just became its own tracer); if it FAILS (-1), a
 * debugger is already attached — so it bails out with a decoy.
 *
 * Your job: detect the check and bypass it so the real payload runs even under
 * a debugger.
 *
 * Build:  gcc -O0 -no-pie antidbg.c -o antidbg
 * Normal: ./antidbg                 -> real payload
 * Traced: gdb ./antidbg ; run       -> "debugger detected" (until you bypass)
 */
#include <stdio.h>
#include <sys/ptrace.h>

static void real_payload(void) {
    printf("[payload] REAL behavior executed\n");
}

int main(void) {
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == -1) {
        printf("[decoy] debugger detected — going dormant\n");
        return 0;
    }
    real_payload();
    return 0;
}
