/*
 * calc_tool.c — training sample B for Module 2.2. BENIGN.
 * Pure computation, no network/crypto/process imports — its import table is
 * boring on purpose, the contrast case to net_tool.
 * Build:  gcc -O2 -no-pie calc_tool.c -o calc_tool
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    long acc = 0;
    for (int i = 1; i < argc; i++) acc += atol(argv[i]);
    printf("sum = %ld\n", acc);
    return 0;
}
