#include "disk.hpp"

// Function to check if a file exists at the given file path
static bool FileExists(const std::wstring& filePath) {
    return std::filesystem::exists(filePath) && !std::filesystem::is_directory(filePath);
}

// Function to get the system's last boot time
static time_t GetLastBootTime() {
    // Get the current tick count
    DWORD64 tickCount = GetTickCount64();
    // Calculate the last boot time in seconds
    return time(nullptr) - (static_cast<time_t>(tickCount) / 1000);
}

// Function to get the last modified time of a file
static time_t GetLastModifiedTime(const std::wstring& filePath) {
    // Check if the file exists before attempting to get its last modified time
    if (FileExists(filePath)) {
        WIN32_FILE_ATTRIBUTE_DATA fileInfo{};
        // Get file attributes, including the last write time
        if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            FILETIME ft = fileInfo.ftLastWriteTime;
            ULARGE_INTEGER li{};
            li.LowPart = ft.dwLowDateTime;
            li.HighPart = ft.dwHighDateTime;
            // Convert the file time to seconds since the epoch
            return static_cast<time_t>(li.QuadPart / 10000000ULL - 11644473600ULL);
        }
    }
    // Return 0 if there is an error getting file attributes or if the file doesn't exist
    return 0;
}

// Function to check for disks that have been replaced since the last boot
void ReplacedDisks() {
    setConsoleTextColor(Yellow);
    std::wcout << "[Disk Scanner] Running checks for replaced drives bypass... \n";
    resetConsoleTextColor();

    try {
        // Get a list of drive letters on the system
        std::vector<std::wstring> driveLetters;
        DWORD drives = GetLogicalDrives();
        for (wchar_t i = L'A'; i <= L'Z'; i++) {
            if ((drives & 1) == 1) {
                std::wstring driveLetter(1, i);
                driveLetters.push_back(driveLetter);
            }
            drives >>= 1;
        }

        // Get the system's last boot time
        time_t lastBootTime = GetLastBootTime();

        // Check each drive for replacement
        for (const std::wstring& driveLetter : driveLetters) {
            // Skip the C: drive
            if (driveLetter == L"C") {
                continue;
            }

            // Construct paths for the root and the "System Volume Information" directory
            std::wstring rootPath = driveLetter + L":\\";
            std::wstring systemInfoPath = rootPath + L"System Volume Information";

            // Check if the path exists before attempting to get the last modified time
            if (FileExists(systemInfoPath)) {
                // Get the last modified time of the "System Volume Information" directory
                time_t lastModifiedTime = GetLastModifiedTime(systemInfoPath);

                // Check if the "System Volume Information" directory was modified after the last boot
                struct tm timeInfo {};
                if (localtime_s(&timeInfo, &lastModifiedTime) == 0) {
                    if (lastModifiedTime > lastBootTime) {
                        // Display a warning message
                        std::wcout << L"[!] Disk " << driveLetter << L" was installed at: "
                            << std::put_time(&timeInfo, L"%c")
                            << L". Ban the user." << std::endl;
                    }
                }
                else {
                    // Handle error when getting local time fails
                    std::wcerr << L"[#] Error getting local time for drive " << driveLetter << std::endl;
                }
            }
            else {
                // Handle error when the path doesn't exist
                std::wcerr << L"[#] Could not detect disk bypasses in drive letter: " << rootPath << std::endl;
            }
        }
    }
    catch (const std::exception& ex) {
        // Handle any other exceptions that might occur
        std::wcerr << L"[#] Exception: " << ex.what() << L". Report the error to Requiem if you see this warning." << std::endl;
    }
}

