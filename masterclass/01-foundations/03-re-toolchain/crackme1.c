/*
 * crackme1.c — training "crackme" for Module 1.3 (the RE toolchain). BENIGN.
 *
 * It asks for a password and prints a flag only if correct. There is nothing
 * harmful here — it's a vehicle for practicing static (Ghidra/objdump) and
 * dynamic (gdb) analysis. You can solve it three ways:
 *   1. strings / static read of the comparison
 *   2. decompiler (Ghidra) reading check_password()
 *   3. gdb breakpoint on the comparison, inspecting registers
 *
 * Build:  gcc -O0 -fno-stack-protector -no-pie crackme1.c -o crackme1
 */
#include <stdio.h>
#include <string.h>

/* The "secret" is assembled at runtime so a naive `strings` won't hand it over
 * on a silver platter — you have to read the code or watch it in a debugger. */
static int check_password(const char *input) {
    char secret[8];
    secret[0] = 'h';
    secret[1] = '4';
    secret[2] = 'x';
    secret[3] = '0';
    secret[4] = 'r';
    secret[5] = '!';
    secret[6] = '\0';
    return strcmp(input, secret) == 0;
}

int main(void) {
    char buf[64];
    printf("password: ");
    if (!fgets(buf, sizeof(buf), stdin))
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (check_password(buf))
        printf("FLAG{you_can_read_a_debugger}\n");
    else
        printf("nope\n");
    return 0;
}
