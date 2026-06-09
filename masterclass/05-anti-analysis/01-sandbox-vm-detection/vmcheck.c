/*
 * vmcheck.c — training sample for Module 5.1 (sandbox/VM detection). BENIGN.
 *
 * Mimics environment-aware malware: it checks two classic VM/sandbox tells and,
 * if it thinks it's being analyzed, goes DORMANT (prints a decoy and exits
 * without doing its "real" work). Your job is to detect the checks and force
 * the real path — the analyst's counter to evasion.
 *
 *   Check 1: CPUID hypervisor-present bit (leaf 1, ECX bit 31). Set inside most
 *            hypervisors/VMs; clear on bare metal.
 *   Check 2: DMI product name containing "QEMU"/"VirtualBox"/"VMware".
 *
 * Build:  gcc -O0 -no-pie vmcheck.c -o vmcheck
 */
#include <stdio.h>
#include <string.h>

static int hypervisor_bit(void) {
    unsigned int ecx = 0;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
    return (ecx >> 31) & 1;     /* bit 31 of ECX = "hypervisor present" */
}

static int dmi_is_vm(void) {
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (!f) return 0;
    char buf[128] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    return strstr(buf, "QEMU") || strstr(buf, "VirtualBox") || strstr(buf, "VMware");
}

static void real_payload(void) {
    /* The behavior an analyst wants to see. Benign: just announces itself. */
    printf("[payload] REAL behavior executed: would drop + beacon here\n");
}

int main(void) {
    if (hypervisor_bit() || dmi_is_vm()) {
        printf("[decoy] nothing interesting here (environment looks analyzed)\n");
        return 0;       /* evade: skip the real payload */
    }
    real_payload();
    return 0;
}
