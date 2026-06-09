/*
 * sample_beacon.c  —  BENIGN training binary for the Detonate Masterclass.
 *
 * This program is NOT malware. It deliberately *mimics the shape* of simple
 * malware behavior so you can practice reading dynamic telemetry safely:
 *
 *   1. Spawns a child process (so you see a parent->child process tree).
 *   2. Writes a "dropped" file to /tmp (so you see filesystem telemetry).
 *   3. Performs a DNS lookup + TCP connect to a sinkhole-style host
 *      (so you see network telemetry) — but sends nothing sensitive and
 *      does no harm whether or not the connection succeeds.
 *
 * It has no payload, no persistence, no obfuscation, and does nothing
 * destructive. Read the source — that's the point.
 *
 * Build (inside your lab):
 *     gcc -O0 sample_beacon.c -o sample_beacon
 *
 * Then submit `sample_beacon` to Detonate per the module README.
 *
 * Network note: point BEACON_HOST at a host you control or a known sinkhole.
 * "example.com" is used by default and is safe/inert. With the sandbox network
 * set to "none", the connect simply fails — the telemetry still shows the
 * *attempt*, which is what you're learning to read.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BEACON_HOST "example.com"
#define BEACON_PORT "80"
#define DROP_PATH   "/tmp/.beacon_marker"

/* Write a small marker file — stands in for a malware "drop". */
static void drop_marker(void) {
    FILE *f = fopen(DROP_PATH, "w");
    if (f) {
        fprintf(f, "training-marker pid=%d\n", (int)getpid());
        fclose(f);
    }
}

/* Resolve + TCP connect to the beacon host. Sends nothing. */
static void beacon(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(BEACON_HOST, BEACON_PORT, &hints, &res) != 0 || !res) {
        return; /* DNS failed (e.g. offline sandbox) — that's fine. */
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s >= 0) {
        /* Connect attempt is the observable behavior. Ignore the result. */
        connect(s, res->ai_addr, res->ai_addrlen);
        close(s);
    }
    freeaddrinfo(res);
}

int main(void) {
    drop_marker();

    pid_t pid = fork();           /* create a child -> visible in process tree */
    if (pid == 0) {
        /* child */
        beacon();
        _exit(0);
    }

    /* parent */
    beacon();
    sleep(1);                     /* give the sandbox time to capture telemetry */
    return 0;
}
