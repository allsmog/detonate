/*
 * staller.c — training sample for Module 5.3 (evasion in the wild). BENIGN.
 *
 * Models a STALLING sample: it sleeps for a long time before doing its real
 * work, betting that an automated sandbox with a short timeout will give up
 * first and never observe the payload. Your job: detect the long sleep and
 * defeat it so the payload runs immediately.
 *
 * Build:  gcc -O0 -no-pie staller.c -o staller
 * Slow:   ./staller                          # waits ~120s, then payload
 * Fast:   LD_PRELOAD=./fastsleep.so ./staller # sleep neutralized -> instant
 */
#include <stdio.h>
#include <unistd.h>

static void real_payload(void) {
    printf("[payload] REAL behavior executed (sandbox already gave up?)\n");
}

int main(void) {
    printf("[staller] sleeping to outlast the sandbox...\n");
    fflush(stdout);
    sleep(120);                 /* the stall — longer than a typical sandbox run */
    real_payload();
    return 0;
}
