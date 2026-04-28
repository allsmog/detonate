/*
 * sleep_patch.so - LD_PRELOAD shim that compresses long sleep/usleep/
 * nanosleep/clock_nanosleep calls to a small bounded value, defeating
 * common time-based sandbox evasion (Sleep(600000), nanosleep(60s) etc).
 *
 * Build:  gcc -shared -fPIC -O2 sleep_patch.c -o sleep_patch.so -ldl
 * Use:    LD_PRELOAD=/opt/agent/sleep_patch.so ./sample
 *
 * The compression policy: anything <= SHIM_PASSTHROUGH_MS passes through
 * untouched; anything longer is clamped to SHIM_MAX_MS (default 50ms)
 * with the original duration logged to /tmp/sleep_patch.log.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

static unsigned long shim_max_ms = 50;          /* clamp to this */
static unsigned long shim_passthrough_ms = 5;   /* shorter than this -> untouched */

typedef unsigned int  (*orig_sleep_t)(unsigned int);
typedef int           (*orig_usleep_t)(useconds_t);
typedef int           (*orig_nanosleep_t)(const struct timespec *, struct timespec *);
typedef int           (*orig_clock_nanosleep_t)(clockid_t, int, const struct timespec *, struct timespec *);

static FILE *log_file = NULL;

__attribute__((constructor))
static void _shim_init(void)
{
    const char *m = getenv("SLEEP_PATCH_MAX_MS");
    if (m) shim_max_ms = strtoul(m, NULL, 10);
    const char *p = getenv("SLEEP_PATCH_PASSTHROUGH_MS");
    if (p) shim_passthrough_ms = strtoul(p, NULL, 10);

    log_file = fopen("/tmp/sleep_patch.log", "a");
}

static void _log(const char *fn, double original_ms, double clamped_ms)
{
    if (!log_file) return;
    fprintf(log_file, "%s original_ms=%.2f clamped_ms=%.2f\n", fn, original_ms, clamped_ms);
    fflush(log_file);
}

unsigned int sleep(unsigned int seconds)
{
    static orig_sleep_t real_sleep = NULL;
    if (!real_sleep) real_sleep = (orig_sleep_t)dlsym(RTLD_NEXT, "sleep");

    double ms = seconds * 1000.0;
    if (seconds == 0 || ms <= shim_passthrough_ms) return real_sleep(seconds);

    double clamped_ms = shim_max_ms;
    _log("sleep", ms, clamped_ms);
    struct timespec ts = { (time_t)(clamped_ms / 1000), (long)((clamped_ms - ((long)(clamped_ms/1000))*1000) * 1000000L) };
    nanosleep(&ts, NULL);
    return 0;
}

int usleep(useconds_t usec)
{
    static orig_usleep_t real_usleep = NULL;
    if (!real_usleep) real_usleep = (orig_usleep_t)dlsym(RTLD_NEXT, "usleep");

    double ms = usec / 1000.0;
    if (ms <= shim_passthrough_ms) return real_usleep(usec);

    double clamped_ms = shim_max_ms;
    _log("usleep", ms, clamped_ms);
    return real_usleep((useconds_t)(clamped_ms * 1000));
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    static orig_nanosleep_t real_nanosleep = NULL;
    if (!real_nanosleep) real_nanosleep = (orig_nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!req) { errno = EINVAL; return -1; }

    double ms = req->tv_sec * 1000.0 + req->tv_nsec / 1e6;
    if (ms <= shim_passthrough_ms) return real_nanosleep(req, rem);

    double clamped_ms = shim_max_ms;
    _log("nanosleep", ms, clamped_ms);
    struct timespec ts = { (time_t)(clamped_ms / 1000), (long)((clamped_ms - ((long)(clamped_ms/1000))*1000) * 1000000L) };
    return real_nanosleep(&ts, rem);
}

int clock_nanosleep(clockid_t clk, int flags, const struct timespec *req, struct timespec *rem)
{
    static orig_clock_nanosleep_t real_cns = NULL;
    if (!real_cns) real_cns = (orig_clock_nanosleep_t)dlsym(RTLD_NEXT, "clock_nanosleep");
    if (!req) return EINVAL;

    /* Absolute-time requests are tricky; clamp the relative case only. */
    if (flags == 0) {
        double ms = req->tv_sec * 1000.0 + req->tv_nsec / 1e6;
        if (ms > shim_passthrough_ms) {
            double clamped_ms = shim_max_ms;
            _log("clock_nanosleep", ms, clamped_ms);
            struct timespec ts = { (time_t)(clamped_ms / 1000), (long)((clamped_ms - ((long)(clamped_ms/1000))*1000) * 1000000L) };
            return real_cns(clk, 0, &ts, rem);
        }
    }
    return real_cns(clk, flags, req, rem);
}
