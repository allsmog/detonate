/*
 * net_tool.c — training sample A for Module 2.2 (imports as behavior). BENIGN.
 * Imports networking + DNS functions, so its import table broadcasts
 * "this program talks to the network" before you read a line of logic.
 * Build:  gcc -O2 -no-pie net_tool.c -o net_tool
 */
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    /* getaddrinfo (DNS) + socket + connect = network capability, visible as imports */
    if (getaddrinfo("example.com", "80", &hints, &res) == 0 && res) {
        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s >= 0) { connect(s, res->ai_addr, res->ai_addrlen); close(s); }
        freeaddrinfo(res);
    }
    printf("done\n");
    return 0;
}
