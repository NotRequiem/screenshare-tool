#include "..\gui\color.hpp"
#include "evthandler.hpp"

void EventlogBypass() {
    Console::SetColor(ConsoleColor::Gray, ConsoleColor::Black);
    std::wcout << "[System Scanner] Running checks to detect eventlog bypasses... " << std::endl;
    Console::ResetColor();
    HKEY hKey;
    const char* registryPath = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\System";
    const char* valueName = "File";
    const char* expectedValue = "%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx";

    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD dataSize;
        result = RegQueryValueExA(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);

        if (result == ERROR_SUCCESS) {
            char* buffer = new char[dataSize];
            result = RegQueryValueExA(hKey, valueName, nullptr, nullptr, (LPBYTE)buffer, &dataSize);

            if (result == ERROR_SUCCESS) {
                std::string value(buffer);

                // Perform case-insensitive comparison to avoid false flags
                if (_stricmp(value.c_str(), expectedValue) != 0) {
                    std::cout << "[!] Eventlog bypass detected. Ban the user." << std::endl;
                }
            }

            delete[] buffer;
        }

        RegCloseKey(hKey);
    }
}
