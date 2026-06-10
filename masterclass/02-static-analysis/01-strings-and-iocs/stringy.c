/*
 * stringy.c — training sample for Module 2.1 (strings & embedded IOCs). BENIGN.
 *
 * It does nothing harmful — it just *contains* the kinds of strings malware
 * leaks: a C2-looking URL, an IP, a registry-key path, an email, a mutex name,
 * and a base64 blob. None of these are real/live; the IPs/domains are
 * documentation-reserved or defanged-by-design. The point is to practice
 * pulling and categorizing IOCs from a binary with `strings`.
 *
 * Build:  gcc -O2 -no-pie stringy.c -o stringy
 *
 * NOTE: the "C2" host is example.com (inert) and the IP is in the
 * documentation range (TEST-NET-1, 192.0.2.0/24, RFC 5737). Safe.
 */
#include <stdio.h>

/* These literals live in .rodata and are trivially recoverable with `strings`. */
const char *C2_URL      = "http://example.com/gate.php?id=";
const char *C2_IP       = "192.0.2.123";
const char *REG_PERSIST = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char *DROP_PATH    = "C:\\Users\\Public\\svchost32.exe";
const char *CONTACT     = "operator@example.com";
const char *MUTEX       = "Global\\TrainingMutex_8f3a";
/* base64("hello from the training sample") */
const char *B64_BLOB    = "aGVsbG8gZnJvbSB0aGUgdHJhaW5pbmcgc2FtcGxl";

int main(void) {
    /* Reference them so the optimizer keeps them in the binary. */
    printf("loaded %p%p%p%p%p%p%p\n",
           (void*)C2_URL, (void*)C2_IP, (void*)REG_PERSIST,
           (void*)DROP_PATH, (void*)CONTACT, (void*)MUTEX, (void*)B64_BLOB);
    return 0;
}
