/*
 * beacon_http.c — training sample for Module 3.3 (network behavior & C2).
 * BENIGN. Performs a DNS lookup and an HTTP-shaped GET to a host:port, then
 * exits. It sends a recognizable "beacon" request line so you can find it in a
 * PCAP. It does nothing with any response and causes no harm.
 *
 * For a self-contained, OFFLINE lab, point it at a local listener:
 *     Terminal A:  python3 sinkhole.py            # listens on 127.0.0.1:8888
 *     Terminal B:  sudo tcpdump -i lo -w beacon.pcap port 8888 &
 *                  ./beacon_http 127.0.0.1 8888
 *                  # then read beacon.pcap (see README)
 *
 * Build:  gcc -O2 -no-pie beacon_http.c -o beacon_http
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char *port = (argc > 2) ? argv[2] : "8888";

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
        printf("dns/resolve failed (offline?) — the attempt is still telemetry\n");
        return 0;
    }
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) == 0) {
        /* A recognizable beacon request — your IOC to find in the PCAP. */
        const char *req =
            "GET /gate.php?id=TRAINING-BOT-01 HTTP/1.1\r\n"
            "Host: c2.example.com\r\n"
            "User-Agent: TrainingBeacon/1.0\r\n\r\n";
        send(s, req, strlen(req), 0);
        printf("beacon sent to %s:%s\n", host, port);
    } else {
        printf("connect to %s:%s failed — attempt still visible in telemetry\n", host, port);
    }
    if (s >= 0) close(s);
    freeaddrinfo(res);
    return 0;
}
