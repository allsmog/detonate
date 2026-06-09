/*
 * fastsleep.c — an LD_PRELOAD shim that neutralizes sleep/nanosleep, defeating
 * the staller's time-based evasion (Module 5.3). This is the portable, testable
 * analogue of patching out a Sleep() call: instead of editing the binary, we
 * intercept the library call and make it return immediately.
 *
 * Build:  gcc -shared -fPIC fastsleep.c -o fastsleep.so -ldl
 * Use:    LD_PRELOAD=./fastsleep.so ./staller
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>

/* Intercept sleep(): return 0 (slept fully) without waiting. */
unsigned int sleep(unsigned int seconds) {
    (void)seconds;
    fprintf(stderr, "[fastsleep] sleep(%u) -> skipped\n", seconds);
    return 0;
}

/* Intercept nanosleep() too (glibc sleep may route here / malware may call it). */
int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)req;
    if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; }
    return 0;
}
