#include "journal.hpp"

constexpr int NUM_DRIVE_LETTERS = 26;

static std::vector<std::wstring> GetDriveLetters() {
    std::vector<std::wstring> driveLetters;
    DWORD drives = GetLogicalDrives();

    for (int drive = 0; drive < NUM_DRIVE_LETTERS; ++drive) {
        if (drives & (1 << drive)) {
            std::wstring driveLetter = L"";
            driveLetter += static_cast<wchar_t>(L'A' + drive);
            driveLetter += L":\\";
            driveLetters.push_back(driveLetter);
        }
    }

    return driveLetters;
}

// Function to retrieve the system's last boot time
static void LastBootTime(SYSTEMTIME& startTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

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
static void CheckDriveJournal(const std::wstring& driveLetter) {
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

        // Convert modification time to FILETIME for direct comparison
        SystemTimeToFileTime(&localModificationTime, &modificationTimeUTC);

        // Convert system start time to FILETIME for direct comparison
        FILETIME systemStartUTC;
        SystemTimeToFileTime(&startTime, &systemStartUTC);

        // Convert FILETIME to ULONGLONG for comparison
        ULONGLONG modificationTimeTicks =
            static_cast<ULONGLONG>(modificationTimeUTC.dwHighDateTime) << 32 | modificationTimeUTC.dwLowDateTime;

        ULONGLONG systemStartTicks =
            static_cast<ULONGLONG>(systemStartUTC.dwHighDateTime) << 32 | systemStartUTC.dwLowDateTime;

        // Compare modification time with system start time
        if (modificationTimeTicks > systemStartTicks) {
            std::wcout << L"[!] USNJournal was cleared on drive " << driveLetter << L". This is bannable." << std::endl;
        }
    }
    else {
        std::wcerr << L"[#] USNJournal is not active on drive: " << driveLetter << std::endl;
    }
}

// Function to check if the USNJournal has been cleared on all available drives
void USNJournalCleared() {
    setConsoleTextColor(Cyan);
    std::wcout << "[NTFS Scanner] Running checks to detect usn journal cleared...\n";
    resetConsoleTextColor();

    std::vector<std::wstring> driveLetters = GetDriveLetters();

    // Iterate through drive letters and check the USNJournal for each drive
    for (const std::wstring& driveLetter : driveLetters) {
        CheckDriveJournal(driveLetter);
    }
}
