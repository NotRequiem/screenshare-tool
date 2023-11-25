#include "..\gui\color.hpp"
#include "diskchk.hpp"

// Function to check if a file exists at the given file path
static bool FileExists(const std::wstring& filePath) {
    // Get file attributes
    DWORD fileAttributes = GetFileAttributesW(filePath.c_str());
    // Check if the file exists and is not a directory
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
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
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    // Get file attributes, including the last write time
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        FILETIME ft = fileInfo.ftLastWriteTime;
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        // Convert the file time to seconds since the epoch
        return static_cast<time_t>(li.QuadPart / 10000000ULL - 11644473600ULL);
    }
    // Return 0 if there is an error getting file attributes
    return 0;
}

// Function to check for disks that have been replaced since the last boot
void ReplacedDisks() {
    Console::SetColor(ConsoleColor::Yellow, ConsoleColor::Black);
    std::wcout << "[Disk Scanner] Running checks for replaced drives bypass... " << std::endl;
    std::wcout << "[Disk Scanner] Running checks for virtual disk bypasses... " << std::endl;
    Console::ResetColor();

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

        // Get the last modified time of the "System Volume Information" directory
        time_t lastModifiedTime = GetLastModifiedTime(systemInfoPath);

        // Check if the "System Volume Information" directory was modified after the last boot
        if (lastModifiedTime > lastBootTime) {
            // Display a warning message
            struct tm timeInfo;
            localtime_s(&timeInfo, &lastModifiedTime);
            std::wcout << L"Warning: Disk " << driveLetter << L" was installed at: "
                       << std::put_time(&timeInfo, L"%c")
                       << L". This can be used as an anti-forensic bypass method." << std::endl;
        }
    }
}
