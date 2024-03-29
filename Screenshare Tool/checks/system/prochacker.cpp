#include "prochacker.hpp"

static void Time(SYSTEMTIME& lastBootTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Get the current local time
    GetLocalTime(&lastBootTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&lastBootTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *reinterpret_cast<ULARGE_INTEGER*>(&ftStartTime);
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime(reinterpret_cast<FILETIME*>(reinterpret_cast<void*>(&startDateTime)), &lastBootTime);
}

static void FileTimeToSystemTimeLocal(const FILETIME* ft, SYSTEMTIME* st) {
    FILETIME localFileTime;
    FileTimeToLocalFileTime(ft, &localFileTime);
    FileTimeToSystemTime(&localFileTime, st);
}

static void CheckPrefetchFolder(const std::wstring& folderPath, const SYSTEMTIME& lastBootTime) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((folderPath + L"\\*.pf").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] The Prefetch folder does not contain prefetch files. This may be bannable if the user is running an official, non-modified version of Windows.\n";
        return;
    }

    do {
        // Convert the file name from WCHAR array to std::wstring
        std::wstring fileName = findFileData.cFileName;

        // Check if the file starts with "SYSTEMINFORMER.EXE-" or "PROCESSHACKER.EXE-"
        if ((fileName.compare(0, 19, L"SYSTEMINFORMER.EXE-") == 0 ||
            fileName.compare(0, 18, L"PROCESSHACKER.EXE-") == 0) &&
            CompareFileTime(&findFileData.ftLastWriteTime, (FILETIME*)&lastBootTime) > 0) { // Ignore C-style pointer casting here

            // Convert FILETIME to SYSTEMTIME using local time
            SYSTEMTIME systemTime;
            FileTimeToSystemTimeLocal(&findFileData.ftLastWriteTime, &systemTime);

            // Print a warning message
            std::cout << "[!] System Informer or Process Hacker were executed at: "
                << systemTime.wYear << "/" << systemTime.wMonth << "/" << systemTime.wDay
                << " " << systemTime.wHour << ":" << systemTime.wMinute << ":" << systemTime.wSecond
                << ". Ban the user if you didn't open this program on this computer." << std::endl;
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void SystemInformer(bool imp) {
    if (!imp) {
        setConsoleTextColor(Gray);
        std::wcout << "[System Scanner] Running checks to detect if certain string cleaners were executed...\n";
        resetConsoleTextColor();
    }

    SYSTEMTIME lastBootTime;
    Time(lastBootTime);

    // Path to the Prefetch folder
    std::wstring prefetchFolderPath = L"C:\\Windows\\Prefetch";

    // Check for SYSTEMINFORMER.EXE-*.pf files in the Prefetch folder
    CheckPrefetchFolder(prefetchFolderPath, lastBootTime);
}
