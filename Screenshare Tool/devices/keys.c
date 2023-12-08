#include "keys.h"

void MouseKeys() {
    setConsoleTextColor(BrightGreen);
    wprintf(L"[Device Scanner] Running checks for MouseKeys autoclickers.\n");
    resetConsoleTextColor();

    // Detects if MouseKeys are enabled in the registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Accessibility\\MouseKeys", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR value[256] = { 0 };
        DWORD size = sizeof(value);

        if (RegQueryValueExW(hKey, L"Flags", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            int intValue = _wtoi(value);

            // If the value is 63 means enabled
            if (intValue == 63) {
                wprintf(L"[!] MouseKeys detected. Ban the user if the attack control is binded to a keyboard key instead of a \"Button key\".\n");
                wprintf(L"[!] To do so, go to the minecraft window and check Options > Controls and check \"Attack\".\n");
            }
        }
        else {
            RegCloseKey(hKey);
        }

        RegCloseKey(hKey);
    }
    else {
    }
}
