/*
 * dynres.c — training sample C for Module 2.2. BENIGN.
 *
 * Demonstrates DYNAMIC import resolution — the Linux analogue of Windows
 * LoadLibrary + GetProcAddress. The interesting function (here, just `cos` from
 * libm) is resolved at RUNTIME via dlopen/dlsym, so it does NOT appear in the
 * static import table. That's exactly how malware hides which APIs it really
 * uses. Your static import view will show only dlopen/dlsym — a red flag in
 * itself.
 *
 * Build:  gcc -O2 -no-pie dynres.c -o dynres -ldl
 */
#include <stdio.h>
#include <dlfcn.h>

int main(void) {
    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (!h) { printf("no libm\n"); return 1; }
    double (*fn)(double) = (double (*)(double))dlsym(h, "cos");
    if (fn) printf("cos(0) = %f\n", fn(0.0));
    dlclose(h);
    return 0;
}
