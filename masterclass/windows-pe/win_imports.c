/*
 * win_imports.c — Windows PE training sample for the Windows supplement. BENIGN.
 *
 * Real-world malware RE is overwhelmingly Windows/PE. This sample exists so you
 * can practice "imports as behavior" (Module 2.2) on an ACTUAL PE: it imports
 * functions from three capability families, so its Import Address Table
 * broadcasts what it can do before you read any code:
 *
 *   - File:        CreateFileA / WriteFile          (kernel32)
 *   - Persistence: RegOpenKeyExA / RegSetValueExA   (advapi32)  <- Run key!
 *   - Network:     InternetOpenA / InternetOpenUrlA (wininet)
 *
 * It does nothing harmful — every call targets inert/benign resources and the
 * results are ignored. The point is the import table, not the behavior.
 *
 * Cross-compile on Linux (Module setup):
 *   x86_64-w64-mingw32-gcc -O2 win_imports.c -o win_imports.exe -ladvapi32 -lwininet
 *
 * Analyze statically with pefile / objdump (no Windows needed):
 *   python3 -c "import pefile;pe=pefile.PE('win_imports.exe'); \
 *     print([d.dll.decode() for d in pe.DIRECTORY_ENTRY_IMPORT])"
 */
#include <windows.h>
#include <wininet.h>

int main(void) {
    /* File capability */
    HANDLE h = CreateFileA("nul", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h, "x", 1, &written, NULL);
        CloseHandle(h);
    }

    /* Persistence capability — reads the Run key (a classic autostart location) */
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegCloseKey(key);
    }

    /* Network capability — opens an inert documentation URL */
    HINTERNET inet = InternetOpenA("TrainingAgent/1.0",
                                   INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (inet) {
        HINTERNET url = InternetOpenUrlA(inet, "http://example.com/", NULL, 0, 0, 0);
        if (url) InternetCloseHandle(url);
        InternetCloseHandle(inet);
    }
    return 0;
}
