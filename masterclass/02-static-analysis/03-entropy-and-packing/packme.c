/*
 * packme.c — training sample for Module 2.3 (entropy & packing) and Module 4.1
 * (UPX unpacking). BENIGN.
 *
 * It's a normal program with some bulk so UPX has something to compress. You'll
 * build it, measure its entropy, then UPX-pack it and watch entropy spike and
 * section names change — the static tells of packing.
 *
 * Build:        gcc -O2 -no-pie packme.c -o packme
 * Pack:         upx --best -o packme_upx packme
 * Compare:      python3 ../../01-foundations/04-file-triage/triage.py packme
 *               python3 ../../01-foundations/04-file-triage/triage.py packme_upx
 */
#include <stdio.h>
#include <string.h>

/* A chunk of low-entropy, compressible data so packing has visible effect. */
static char buffer[8192];

int main(void) {
    for (int i = 0; i < (int)sizeof(buffer); i++)
        buffer[i] = (char)('A' + (i % 26));   /* highly regular -> low entropy */
    int checksum = 0;
    for (int i = 0; i < (int)sizeof(buffer); i++)
        checksum += buffer[i];
    printf("checksum=%d len=%zu\n", checksum, strlen(buffer) ? strlen(buffer) : sizeof(buffer));
    return 0;
}
