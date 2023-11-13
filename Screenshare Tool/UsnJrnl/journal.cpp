#include "journal.hpp"
#include <iostream>
#include <iomanip>

// Function to get a list of available drive letters
std::vector<std::wstring> GetDriveLetters() {
    std::vector<std::wstring> driveLetters;
    WCHAR buffer[MAX_PATH];
    DWORD drives = GetLogicalDrives();

    for (int drive = 0; drive < 26; ++drive) {
        if (drives & (1 << drive)) {
            buffer[0] = L'A' + drive;
            buffer[1] = L':';
            buffer[2] = L'\\';
            buffer[3] = L'\0';
            driveLetters.push_back(buffer);
        }
    }

    return driveLetters;
}

void CheckDriveJournal(const std::wstring& driveLetter) {
    // Construct the path to the $Extend\$UsnJrnl file for the current drive
    std::wstring journalPath = driveLetter + L"$Extend\\$UsnJrnl:$J";

    // Get the modification date of the $J journal data stream
    BY_HANDLE_FILE_INFORMATION fileInformation;
    HANDLE hFile = CreateFileW(journalPath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile != INVALID_HANDLE_VALUE && GetFileInformationByHandle(hFile, &fileInformation)) {
        FILETIME modificationTimeUTC = fileInformation.ftLastWriteTime;
        CloseHandle(hFile);

        // Convert the modification time to local time
        FILETIME modificationTimeLocal;
        FileTimeToLocalFileTime(&modificationTimeUTC, &modificationTimeLocal);

        SYSTEMTIME systemTime;
        FileTimeToSystemTime(&modificationTimeLocal, &systemTime);

        // Calculate the number of seconds since the system was started
        ULONGLONG modificationTimeInSeconds = systemTime.wHour * 3600 + systemTime.wMinute * 60 + systemTime.wSecond;

        // Get the system start time in ticks
        ULONGLONG systemStartTicks = GetTickCount64();

        // Calculate the number of seconds since system start
        ULONGLONG seconds = systemStartTicks / 1000;
        ULONGLONG minutes = seconds / 60;
        ULONGLONG hours = minutes / 60;
        ULONGLONG days = hours / 24;

        // Calculate the remaining hours, minutes, and seconds
        hours %= 24;
        minutes %= 60;
        seconds %= 60;

        // Calculate the system start time in local time
        ULONGLONG startedTimeInSeconds = systemTime.wHour * 3600 + systemTime.wMinute * 60 + systemTime.wSecond -
            (hours * 3600 + minutes * 60 + seconds);

        // Check if $J was modified after the system started
        if (modificationTimeInSeconds > startedTimeInSeconds) {
            std::wcout << L"Drive " << driveLetter << L": Warning: USNJournal cleared." << std::endl;
        }
        else {
            std::wcout << L"Drive " << driveLetter << L": USNJournal not cleared for this drive." << std::endl;
        }

        // Print the modification date of $J in local time
        std::wcout << L"Drive " << driveLetter << L": Modification Date of the USNJournal (Local Time): ";
        std::wcout << systemTime.wYear << L"-" << systemTime.wMonth << L"-" << systemTime.wDay << L" ";
        std::wcout << std::setfill(L'0') << std::setw(2) << systemTime.wHour << L":";
        std::wcout << std::setfill(L'0') << std::setw(2) << systemTime.wMinute << L":";
        std::wcout << std::setfill(L'0') << std::setw(2) << systemTime.wSecond << std::endl;
    }
    else {
        std::wcerr << L"Drive " << driveLetter << L": is formatted as a FAT file system." << std::endl;
    }
}