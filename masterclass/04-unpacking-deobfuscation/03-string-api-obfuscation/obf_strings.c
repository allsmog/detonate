/*
 * obf_strings.c — training sample for Module 4.3 (string & API obfuscation).
 * BENIGN. Demonstrates the three code-level obfuscations you'll meet most:
 *
 *   1. XOR-encrypted string  : the "C2" host is single-byte-XOR encoded, so
 *                              `strings` shows garbage, not c2.example.com.
 *   2. Stack string          : "/tmp/.sysd" is built byte-by-byte at runtime,
 *                              so it never appears as a contiguous string.
 *   3. API hashing           : instead of importing/naming functions, it
 *                              resolves them by a djb2 HASH of the name — so the
 *                              import table and string table hide which APIs it
 *                              uses. Here it resolves `getenv` by hash.
 *
 * Nothing harmful happens; it just prints what it decoded/resolved.
 *
 * Build:  gcc -O0 -fno-stack-protector -no-pie obf_strings.c -o obf_strings -ldl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* (1) XOR(0x5A) of "c2.example.com" — recover with single-byte XOR */
static unsigned char enc_c2[] = {
    0x39, 0x68, 0x74, 0x3f, 0x22, 0x3b, 0x37, 0x2a,
    0x36, 0x3f, 0x74, 0x39, 0x35, 0x37
};

/* (3) djb2 hash, the resolver malware uses to avoid naming APIs */
static unsigned int djb2(const char *s) {
    unsigned int h = 5381;
    for (; *s; s++) h = (h * 33) + (unsigned char)*s;
    return h;
}

/* Resolve a libc symbol by the HASH of its name (brute over a small set). */
static void *resolve_by_hash(unsigned int want) {
    static const char *candidates[] = {
        "open", "read", "write", "getenv", "system", "connect", "socket", NULL
    };
    void *libc = dlopen("libc.so.6", RTLD_NOW);
    for (int i = 0; candidates[i]; i++)
        if (djb2(candidates[i]) == want)
            return dlsym(libc, candidates[i]);
    return NULL;
}

int main(void) {
    /* (1) decode XOR string */
    char c2[32];
    for (size_t i = 0; i < sizeof(enc_c2); i++) c2[i] = enc_c2[i] ^ 0x5A;
    c2[sizeof(enc_c2)] = '\0';
    printf("c2  = %s\n", c2);

    /* (2) stack string */
    char path[16];
    path[0]='/'; path[1]='t'; path[2]='m'; path[3]='p'; path[4]='/';
    path[5]='.'; path[6]='s'; path[7]='y'; path[8]='s'; path[9]='d'; path[10]='\0';
    printf("path= %s\n", path);

    /* (3) API resolved by hash: 0xff8760ae == djb2("getenv") */
    char *(*getenv_fn)(const char *) = (char *(*)(const char *))resolve_by_hash(0xff8760aeU);
    if (getenv_fn) printf("api : resolved getenv by hash; HOME=%s\n", getenv_fn("HOME"));
    return 0;
}
