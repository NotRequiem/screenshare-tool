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
                if (value != expectedValue) {
                    std::cout << "[!] Eventlog bypass detected. Ban the user." << std::endl;
                }
            }
            else {
                std::cerr << "Error reading registry value. Error code: " << result << std::endl;
            }

            delete[] buffer;
        }
        else {
            std::cerr << "Error querying registry value size. Error code: " << result << std::endl;
        }

        RegCloseKey(hKey);
    }
    else {
        std::cerr << "Error opening registry key. Error code: " << result << std::endl;
    }
}
