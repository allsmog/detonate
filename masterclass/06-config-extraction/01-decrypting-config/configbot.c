/*
 * configbot.c — training sample for Modules 6.1 & 6.2 (config extraction).
 * BENIGN. Models a commodity bot that carries an RC4-encrypted CONFIG blob
 * (campaign id, C2 list, mutex) and decrypts it at runtime. All IOCs are inert
 * (example.com/.net). A 4-byte magic "CFG0" precedes the blob so an extractor
 * can locate it by signature — a realistic convention.
 *
 * Layout in the binary:   "CFG0" | uint16 len | <RC4(config, key)>
 * RC4 key: "s3cr3tk3y"
 *
 * Build:  gcc -O0 -no-pie configbot.c -o configbot
 * Run:    ./configbot        # prints the decrypted config
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const unsigned char KEY[] = "s3cr3tk3y";

/* "CFG0" magic + length(85) little-endian + RC4(config) */
static unsigned char blob[] = {
    'C','F','G','0', 0x55, 0x00,    /* magic, len=0x0055=85 */
    0xe8, 0x1c, 0x69, 0x1f, 0x02, 0x77, 0x04, 0xc3, 0xeb, 0xc9, 0x7d, 0x28,
    0xf8, 0xc1, 0x12, 0x02, 0x3d, 0xcf, 0x43, 0xd3, 0x08, 0x2e, 0x04, 0x9b,
    0x36, 0x37, 0xb2, 0xa7, 0x03, 0x18, 0x3a, 0xa6, 0xf6, 0xe3, 0x7f, 0x94,
    0x01, 0x1b, 0xa3, 0x4e, 0x58, 0xb9, 0xb3, 0xef, 0x19, 0x82, 0x4a, 0xa5,
    0x2d, 0xb0, 0xf8, 0xf9, 0x1c, 0xa8, 0x48, 0x17, 0x37, 0x0a, 0xc0, 0xe3,
    0x2f, 0x4f, 0xbc, 0x8c, 0x91, 0x80, 0xcf, 0x82, 0xd8, 0x1a, 0x46, 0x17,
    0xf0, 0x94, 0x0f, 0xa2, 0xba, 0x7b, 0x20, 0xc6, 0xf2, 0xd1, 0x6c, 0xea,
    0xc1
};

static void rc4(const unsigned char *key, size_t klen,
                unsigned char *data, size_t dlen) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xff;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i = 0; j = 0;
    for (size_t n = 0; n < dlen; n++) {
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xff];
    }
}

int main(void) {
    uint16_t len = blob[4] | (blob[5] << 8);
    unsigned char cfg[256];
    memcpy(cfg, blob + 6, len);
    rc4(KEY, strlen((const char *)KEY), cfg, len);
    cfg[len] = '\0';
    printf("[config] %s\n", cfg);
    return 0;
}
