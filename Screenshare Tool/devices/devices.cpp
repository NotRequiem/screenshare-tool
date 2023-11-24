#include "devices.hpp"

// Function to retrieve the system's last boot time
static void LastComputerBootTime(SYSTEMTIME& startTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    // Get the current local time
    GetLocalTime(&startTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&startTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime((FILETIME*)&startDateTime, &startTime);
}

static void FileTimeToLocalTimeString(const FILETIME& fileTime, std::wstring& localTimeString) {
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);

    WCHAR buffer[256];
    GetDateFormatEx(
        LOCALE_NAME_USER_DEFAULT,
        0,
        &systemTime,
        L"yyyy-MM-dd",
        buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        nullptr
    );

    localTimeString = buffer;

    // Append the time part (HH:mm:ss)
    GetTimeFormatEx(
        LOCALE_NAME_USER_DEFAULT,
        0,
        &systemTime,
        L"HH:mm:ss",
        buffer,
        sizeof(buffer) / sizeof(buffer[0])
    );

    localTimeString += L" " + std::wstring(buffer);
}

static void EnumerateSubkeys(const std::wstring& parentKeyPath, const SYSTEMTIME& lastBootTime, int depth = 0) {
    HKEY hKey;
    LONG result;

    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        parentKeyPath.c_str(),
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey
    );

    if (result == ERROR_SUCCESS) {
        DWORD index = 0;
        DWORD subkeyNameSize = MAX_PATH;
        WCHAR* subkeyName = new WCHAR[subkeyNameSize];

        while (RegEnumKeyExW(hKey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring subkeyPath = parentKeyPath + L"\\" + subkeyName;

            // Retrieve the last modified time of the subfolder
            FILETIME lastModifiedTime = { 0 };
            HKEY subKey;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &subKey) == ERROR_SUCCESS) {
                DWORD size = sizeof(lastModifiedTime);
                RegQueryInfoKeyW(subKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lastModifiedTime);
                RegCloseKey(subKey);

                // Convert FILETIME to local time string
                std::wstring localTimeString;
                FileTimeToLocalTimeString(lastModifiedTime, localTimeString);

                // Compare last boot time with the last modified time
                FILETIME ftBootTime;
                SystemTimeToFileTime(&lastBootTime, &ftBootTime);

                if (CompareFileTime(&lastModifiedTime, &ftBootTime) > 0) {
                    // Extract the relevant part of the key path
                    size_t pos = subkeyPath.find(L"USB\\");
                    if (pos != std::wstring::npos) {
                        subkeyPath = subkeyPath.substr(pos + 4); // Exclude "USB\" from the path
                    }

                    std::wcout << "Warning: Unplugged device detected - " << subkeyPath << std::endl;
                    std::wcout << "    Device was unplugged at: " << localTimeString << std::endl;
                }
            }

            // Recursively enumerate subkeys of the current subkey if depth is not reached
            if (depth > 0) {
                EnumerateSubkeys(subkeyPath, lastBootTime, depth - 1);
            }

            index++;
            subkeyNameSize = MAX_PATH;
        }
        RegCloseKey(hKey);
        delete[] subkeyName;
    }
    else {
        std::wcerr << "Failed to open the registry key: " << parentKeyPath << std::endl;
    }
}

void UnpluggedDevices() {
    std::wcout << "Running checks for unplugged devices... " << std::endl;
    std::wstring parentKeyPath = L"SYSTEM\\ControlSet001\\Enum\\USB";

    // Get the system's last boot time
    SYSTEMTIME lastBootTime;
    LastComputerBootTime(lastBootTime);

    // Call EnumerateSubkeys with the last boot time and one level depth (so we can detect unplugged usbs)
    EnumerateSubkeys(parentKeyPath, lastBootTime, 1);
}
