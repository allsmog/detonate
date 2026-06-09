/*
 * challenge_src.c — SOURCE for the self-contained capstone challenge. BENIGN.
 *
 * Instructors build this and UPX-pack it to produce `crackmalware`, which
 * learners analyze WITHOUT this source (see build.sh). It deliberately combines
 * every technique from Levels 1-6 so the capstone exercises the whole kill
 * chain:
 *
 *   - Level 4: UPX packing (applied by build.sh) + RC4-encrypted config
 *   - Level 4: XOR-obfuscated string (User-Agent)
 *   - Level 5: ptrace anti-debug
 *   - Level 6: RC4 config behind a "CFG0" marker (campaign, C2 list, mutex)
 *   - Level 3: beacon attempt to the (decoded) C2
 *
 * All IOCs are inert (example.com/.net). Nothing harmful happens.
 *
 * >>> Learners: do NOT read this file until after you've written your report. <<<
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <netdb.h>
#include <sys/socket.h>

static const unsigned char KEY[] = "unpackme!";

/* "CFG0" | uint16 len(88) | RC4(config, "unpackme!") */
static unsigned char blob[] = {
    'C','F','G','0', 0x58, 0x00,
    0x87,0xb8,0x44,0xa9,0xe7,0x81,0x1b,0x10,0x22,0xf0,0xcf,0xee,0xd4,0x26,0xbb,0xf7,
    0xb5,0xb1,0x78,0x35,0x56,0x7e,0xdd,0xd4,0xee,0xd3,0x2d,0x31,0xc5,0xfc,0xcf,0x39,
    0x5e,0x45,0x4c,0xf3,0x39,0x47,0xdd,0xca,0x64,0x2f,0xce,0x19,0x2b,0xb6,0x6c,0xe4,
    0xaf,0x52,0xe5,0x44,0xae,0x98,0xca,0x8b,0x62,0x63,0xbd,0xb2,0xc5,0x61,0xaf,0xff,
    0xe5,0x80,0xff,0x06,0xb6,0xd0,0xae,0xb4,0x8e,0x35,0x71,0x21,0x88,0x12,0x7b,0xe9,
    0x16,0x35,0x5f,0xda,0x30,0xf3,0x66,0x1e
};

/* XOR(0x6b) of "Mozilla/5.0 (CapstoneBot)" */
static unsigned char enc_ua[] = {
    0x26,0x04,0x11,0x02,0x07,0x07,0x0a,0x44,0x5e,0x45,0x5b,0x4b,0x43,0x28,0x0a,0x1b,
    0x18,0x1f,0x04,0x05,0x0e,0x29,0x04,0x1f,0x42
};

static void rc4(const unsigned char *key, size_t klen, unsigned char *d, size_t n) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) { j = (j + S[i] + key[i % klen]) & 0xff;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t; }
    int i = 0; j = 0;
    for (size_t k = 0; k < n; k++) { i = (i + 1) & 0xff; j = (j + S[i]) & 0xff;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t; d[k] ^= S[(S[i] + S[j]) & 0xff]; }
}

static void beacon(const char *host, const char *port, const char *ua) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return;
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) == 0) {
        char req[512];
        snprintf(req, sizeof(req),
                 "GET /panel/gate.php?bot=CAPSTONE-01 HTTP/1.1\r\nHost: %s\r\n"
                 "User-Agent: %s\r\n\r\n", host, ua);
        send(s, req, strlen(req), 0);
    }
    if (s >= 0) close(s);
    freeaddrinfo(res);
}

int main(void) {
    /* anti-debug */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        printf("system check failed\n");      /* decoy */
        return 0;
    }

    /* decode User-Agent */
    char ua[64];
    for (size_t i = 0; i < sizeof(enc_ua); i++) ua[i] = enc_ua[i] ^ 0x6b;
    ua[sizeof(enc_ua)] = '\0';

    /* decrypt config */
    uint16_t len = blob[4] | (blob[5] << 8);
    unsigned char cfg[256];
    memcpy(cfg, blob + 6, len); rc4(KEY, strlen((const char *)KEY), cfg, len);
    cfg[len] = '\0';

    printf("[ok] config=%s\n[ok] ua=%s\n", cfg, ua);

    /* parse primary C2 host:port and beacon (inert offline) */
    char *c2 = strstr((char *)cfg, "c2=");
    if (c2) {
        c2 += 3;
        char host[128]; int p = 0;
        while (c2[p] && c2[p] != ':' && c2[p] != ',') { host[p] = c2[p]; p++; }
        host[p] = '\0';
        beacon(host, "8443", ua);
    }
    return 0;
}
