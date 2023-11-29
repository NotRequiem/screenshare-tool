#include "devices.hpp"
#include "..\gui\color.hpp"

// Function to retrieve the system's last boot time
static void LastComputerBootTime(SYSTEMTIME& lastBootTime) {
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

// Function to convert FILETIME to a local time string
static void FileTimeToLocalTimeString(const FILETIME& fileTime, std::wstring& localTimeString) {
    // Convert FILETIME to SYSTEMTIME
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);

    // Buffer to store the formatted date
    WCHAR buffer[256];

    // Format the date part (yyyy-MM-dd)
    GetDateFormatEx(
        LOCALE_NAME_USER_DEFAULT,
        0,
        &systemTime,
        L"yyyy-MM-dd",
        buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        nullptr
    );

    // Assign the formatted date to the output string
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

    // Append the formatted time to the output string
    localTimeString += L" " + std::wstring(buffer);
}

// Function to enumerate subkeys and detect unplugged devices
static void EnumerateSubkeys(const std::wstring& parentKeyPath, const SYSTEMTIME& lastBootTime, int depth = 0) {
    SYSTEMTIME systemTime;

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
        static std::set<std::wstring> flaggedDevices;

        while (RegEnumKeyExW(hKey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring subkeyPath = parentKeyPath + L"\\" + subkeyName;

            // Retrieve the last modified time of the subfolder
            FILETIME lastModifiedTime = { 0 };
            HKEY subKey;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &subKey) == ERROR_SUCCESS) {
                DWORD size = sizeof(lastModifiedTime);
                RegQueryInfoKeyW(subKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lastModifiedTime);

                // Convert FILETIME to local time so that we can make a comparison later
                FILETIME localLastModifiedTime;
                FileTimeToLocalFileTime(&lastModifiedTime, &localLastModifiedTime);
                FileTimeToSystemTime(&localLastModifiedTime, &systemTime);

                RegCloseKey(subKey);

                // Convert FILETIME to local time string
                std::wstring localTimeString;
                FileTimeToLocalTimeString(localLastModifiedTime, localTimeString);

                // Compare last boot time with the last modified time
                FILETIME ftBootTime;
                SystemTimeToFileTime(&lastBootTime, &ftBootTime);

                // Calculate the time difference in seconds
                ULARGE_INTEGER lastModifiedTime;
                lastModifiedTime.LowPart = localLastModifiedTime.dwLowDateTime;
                lastModifiedTime.HighPart = localLastModifiedTime.dwHighDateTime;

                ULARGE_INTEGER bootTime;
                bootTime.LowPart = ftBootTime.dwLowDateTime;
                bootTime.HighPart = ftBootTime.dwHighDateTime;

                ULARGE_INTEGER diff;
                diff.QuadPart = lastModifiedTime.QuadPart - bootTime.QuadPart;
                diff.QuadPart /= 10000000; // Convert 100-nanosecond intervals to seconds

                // Check if the last write time is significantly after the last boot time
                const int thresholdSeconds = 10; // Adjust this threshold as needed
                if (localLastModifiedTime.dwHighDateTime > ftBootTime.dwHighDateTime && static_cast<int>(diff.QuadPart) > thresholdSeconds) {
                    // Extract the relevant part of the key path
                    size_t pos = subkeyPath.find(L"USB\\");
                    if (pos != std::wstring::npos) {
                        subkeyPath = subkeyPath.substr(pos + 4); // Exclude "USB\" from the path
                    }

                    // Check if this device has already been flagged
                    if (flaggedDevices.find(subkeyPath.substr(0, 17)) == flaggedDevices.end()) {
                        std::wcout << "[!] Warning: Unplugged device detected:  " << subkeyPath << ". Ban the user." << std::endl;
                        std::wcout << "    Device was unplugged at: " << localTimeString << std::endl;

                        // Add the device to the flagged set
                        flaggedDevices.insert(subkeyPath.substr(0, 17));
                    }
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
}

// Function to check for unplugged devices
void UnpluggedDevices() {
    Console::SetColor(ConsoleColor::BrightGreen, ConsoleColor::Black);
    std::wcout << "[Device Scanner] Running checks for unplugged devices... " << std::endl;
    Console::ResetColor();
    std::wstring parentKeyPath = L"SYSTEM\\ControlSet001\\Enum\\USB";

    // Get the system's last boot time
    SYSTEMTIME lastBootTime{};
    LastComputerBootTime(lastBootTime);

    // Call EnumerateSubkeys with the last boot time and one level depth (so that we can detect unplugged usbs)
    EnumerateSubkeys(parentKeyPath, lastBootTime, 1);
}
