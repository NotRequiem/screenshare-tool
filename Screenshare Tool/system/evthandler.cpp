#include "evthandler.hpp"

// Function to check for event log bypasses by inspecting the registry
void EventlogBypass() {
    // Set console color for information display
    setConsoleTextColor(Gray);
    std::wcout << "[System Scanner] Running checks to detect event log bypasses... " << std::endl;
    resetConsoleTextColor();

    // Registry path and value information
    HKEY hKey;
    const char* registryPath = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\System";
    const char* valueName = "File";
    const char* expectedValue = "%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx";

    // Open the registry key for the specified path
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

    // Check if the key is successfully opened
    if (result == ERROR_SUCCESS) {
        // Query the size of the registry value
        DWORD dataSize;
        result = RegQueryValueExA(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);

        // Check if the value is successfully queried
        if (result == ERROR_SUCCESS) {
            // Allocate memory for the registry value
            char* buffer = new char[dataSize];

            // Query the actual value data
            result = RegQueryValueExA(hKey, valueName, nullptr, nullptr, (LPBYTE)buffer, &dataSize);

            // Check if the value data is successfully queried
            if (result == ERROR_SUCCESS) {
                // Convert the value to a std::string for comparison
                std::string value(buffer);

                // Perform case-insensitive comparison to avoid false flags
                if (_stricmp(value.c_str(), expectedValue) != 0) {
                    // Display a warning message if the value does not match the expected value
                    std::cout << "[!] Event log bypass detected. Ban the user." << std::endl;
                }
            }

            // Deallocate the memory used for the buffer
            delete[] buffer;
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
}
