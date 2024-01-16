#include "evthandler.hpp"

// Function to check for event log bypasses by inspecting the registry
void EventlogBypass() {
    // Set console color for information display
    setConsoleTextColor(Gray);
    std::wcout << L"[System Scanner] Running checks to detect event log bypasses...\n";
    resetConsoleTextColor();

    // Registry path and value information
    HKEY hKey;
    const wchar_t* registryPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System";
    const wchar_t* valueName = L"File";
    const wchar_t* expectedValue = L"%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx";

    // Open the registry key for the specified path
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

    // Check if the key is successfully opened
    if (result == ERROR_SUCCESS) {
        // Query the size of the registry value
        DWORD dataSize;
        result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);

        // Check if the value is successfully queried
        if (result == ERROR_SUCCESS) {
            // Allocate memory for the registry value
            wchar_t* buffer = new wchar_t[dataSize / sizeof(wchar_t)];

            // Query the actual value data
            result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)buffer, &dataSize);

            // Check if the value data is successfully queried
            if (result == ERROR_SUCCESS) {
                // Convert the value to a std::wstring for comparison
                std::wstring value(buffer);

                // Perform case-insensitive comparison to avoid false flags
                if (_wcsicmp(value.c_str(), expectedValue) != 0) {
                    // Display a warning message if the value does not match the expected value
                    std::wcout << L"[!] Event log bypass detected. Ban the user.\n";
                }
            }

            // Deallocate the memory used for the buffer
            delete[] buffer;
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
}
