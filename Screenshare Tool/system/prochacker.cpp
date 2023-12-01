#include "..\gui\color.hpp"
#include "prochacker.hpp"

static void Time(SYSTEMTIME& lastBootTime) {
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

static void CheckPrefetchFolder(const std::wstring& folderPath, const SYSTEMTIME& lastBootTime) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((folderPath + L"\\*.pf").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] The Prefetch folder does not contain prefeth files. This may be bannable if the user is running an official, non modified version of Windows.\n";
        return;
    }

    do {
        // Convert the file name from WCHAR array to std::wstring
        std::wstring fileName = findFileData.cFileName;

        // Check if the file starts with "SYSTEMINFORMER.EXE-" or "PROCESSHACKER.EXE-"
        if ((fileName.compare(0, 19, L"SYSTEMINFORMER.EXE-") == 0 ||
            fileName.compare(0, 18, L"PROCESSHACKER.EXE-") == 0) &&
            CompareFileTime(&findFileData.ftLastWriteTime, (FILETIME*)&lastBootTime) > 0) {

            // Convert FILETIME to SYSTEMTIME
            SYSTEMTIME systemTime;
            FileTimeToSystemTime(&findFileData.ftLastWriteTime, &systemTime);

            // Print a warning message
            std::wcout << L"[!] System Informer or Process Hacker were executed at: "
                << systemTime.wYear << L"-" << systemTime.wMonth << L"-" << systemTime.wDay
                << L" " << systemTime.wHour << L":" << systemTime.wMinute << L":" << systemTime.wSecond
                << L". Ban the user if you didn't open this program in this computer." << std::endl;
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void SystemInformer() {
    Console::SetColor(ConsoleColor::Gray, ConsoleColor::Black);
    std::wcout << "[System Scanner] Running checks to detect if certain string cleaners were executed... " << std::endl;
    Console::ResetColor();

    SYSTEMTIME lastBootTime;
    Time(lastBootTime);

    // Path to the Prefetch folder
    std::wstring prefetchFolderPath = L"C:\\Windows\\Prefetch";

    // Check for SYSTEMINFORMER.EXE-*.pf files in the Prefetch folder
    CheckPrefetchFolder(prefetchFolderPath, lastBootTime);  
}