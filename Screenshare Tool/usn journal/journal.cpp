#include "journal.hpp"

// Function to get a list of available drive letters
std::vector<std::wstring> GetDriveLetters() {
    std::vector<std::wstring> driveLetters;
    WCHAR buffer[MAX_PATH];
    DWORD drives = GetLogicalDrives();

    // Iterate through drive letters and add available drives to the vector
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

// Function to retrieve the system's last boot time
void LastBootTime(SYSTEMTIME& startTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (1000 * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (1000 * 60 * 60)) % 24);

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

// Function to check if the USNJournal on a specified drive has been cleared
void CheckDriveJournal(const std::wstring& driveLetter) {
    std::wstring journalPath = driveLetter + L"$Extend\\$UsnJrnl:$J";

    BY_HANDLE_FILE_INFORMATION fileInformation;
    HANDLE hFile = CreateFileW(journalPath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    // Check if the file handle is valid and retrieve file information
    if (hFile != INVALID_HANDLE_VALUE && GetFileInformationByHandle(hFile, &fileInformation)) {
        FILETIME modificationTimeUTC = fileInformation.ftLastWriteTime;
        CloseHandle(hFile);

        SYSTEMTIME systemTime;
        GetSystemTime(&systemTime);

        SYSTEMTIME localModificationTime;
        FileTimeToLocalFileTime(&modificationTimeUTC, &modificationTimeUTC);
        FileTimeToSystemTime(&modificationTimeUTC, &localModificationTime);

        SYSTEMTIME startTime;
        LastBootTime(startTime);

        ULONGLONG modificationTimeTicks = (static_cast<ULONGLONG>(localModificationTime.wHour) * 3600 +
            static_cast<ULONGLONG>(localModificationTime.wMinute) * 60 +
            static_cast<ULONGLONG>(localModificationTime.wSecond)) * 1000;

        ULONGLONG systemStartTicks = (static_cast<ULONGLONG>(startTime.wHour) * 3600 +
            static_cast<ULONGLONG>(startTime.wMinute) * 60 +
            static_cast<ULONGLONG>(startTime.wSecond)) * 1000;

        // Compare modification time with system start time
        if (modificationTimeTicks > systemStartTicks) {
            std::wcout << L"WARNING: USNJournal was cleared on drive " << driveLetter << L". This is bannable." << std::endl;
        }
    }
    else {
        std::wcerr << L"USNJournal is not active on drive: " << driveLetter << std::endl;
    }
}

// Function to check if the USNJournal has been cleared on all available drives
void USNJournalCleared() {
    std::vector<std::wstring> driveLetters = GetDriveLetters();

    // Iterate through drive letters and check the USNJournal for each drive
    for (const std::wstring& driveLetter : driveLetters) {
        CheckDriveJournal(driveLetter);
    }
}
