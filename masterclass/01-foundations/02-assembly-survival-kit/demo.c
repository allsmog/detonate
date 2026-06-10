/*
 * demo.c — training source for Module 1.2 (x86/x64 assembly survival kit).
 * BENIGN. Compile at two optimization levels and compare the disassembly:
 *     gcc -O0 -fno-pic -no-pie demo.c -o demo_O0
 *     gcc -O2 -fno-pic -no-pie demo.c -o demo_O2
 *     objdump -d -M intel demo_O0 | sed -n '/<sum_to_n>:/,/ret/p'
 *
 * sum_to_n is deliberately a simple counted loop with a branch so you can map
 * C control flow to instructions (cmp/jle/add/jmp) and watch the optimizer
 * transform it.
 */
#include <stdio.h>
#include <stdlib.h>

/* Sum 1..n, but skip multiples of 3 — gives us a loop AND a branch. */
int sum_to_n(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++) {
        if (i % 3 == 0)
            continue;
        total += i;
    }
    return total;
}

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 10;
    printf("sum_to_n(%d) = %d\n", n, sum_to_n(n));
    return 0;
}
