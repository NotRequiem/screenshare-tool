#include "evthandler.hpp"

static void LastPCBootTime(SYSTEMTIME& lastBootTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    // Get the current local time
    GetLocalTime(&lastBootTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&lastBootTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime((FILETIME*)&startDateTime, &lastBootTime);
}

void EventlogBypass() {
    HKEY hKey;
    SYSTEMTIME lastBootTime, lastWriteTime;
    FILETIME ftLastWriteTime, ftLastBootTime{};

    // Open the registry key
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Get the last write time of the registry key
        if (RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ftLastWriteTime) == ERROR_SUCCESS) {
            // Convert the last write time to SYSTEMTIME
            FileTimeToSystemTime(&ftLastWriteTime, &lastWriteTime);

            // Get the last system boot time
            LastPCBootTime(lastBootTime);

            // Compare the last write time with the last system boot time
            if (CompareFileTime(&ftLastWriteTime, &ftLastBootTime) == 1) {
                std::cout << "[!] Eventlog bypass detected. Ban the user." << std::endl;
            }
        }
        else {
            std::cerr << "Error querying registry key information while detecting eventlog bypasses." << std::endl;
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
    else {
        std::cerr << "Error opening registry key while detecting eventlog bypasses.." << std::endl;
    }
}
