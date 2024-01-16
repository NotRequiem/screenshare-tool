#include "appcrash.hpp"

void AppCrash() {
    setConsoleTextColor(Magenta);
    std::wcout << "[Forensic Scanner] Running checks to detect executed files with crash logs...\n";
    resetConsoleTextColor();

    SYSTEMTIME lastLogonTime;
    if (!LogonTime(lastLogonTime)) {
        std::cerr << "Error getting last logon time\n";
        return;
    }

    // Specify the directory path
    std::wstring directoryPath = L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\";

    // Prepare the search pattern
    std::wstring searchPattern = directoryPath + L"AppCrash_*";

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Error scanning for AppCrash files\n";
        return;
    }

    do {
        // Extract the file name from the folder name
        std::wstring folderName = findFileData.cFileName;
        size_t firstUnderscorePos = folderName.find_first_of(L"_");  // Start searching from the 9th character (after AppCrash)
        size_t lastUnderscorePos = folderName.find_first_of(L"_", firstUnderscorePos + 1);

        if (firstUnderscorePos == std::wstring::npos || lastUnderscorePos == std::wstring::npos) {
            continue;
        }

        std::wstring fileName = folderName.substr(firstUnderscorePos + 1, lastUnderscorePos - firstUnderscorePos - 1);

        // Get the modified time of the folder
        FILETIME lastWriteTime = findFileData.ftLastWriteTime;
        SYSTEMTIME stUTC, stLocal;

        FileTimeToSystemTime(&lastWriteTime, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        // Convert lastLogonTime to FILETIME for comparison
        FILETIME lastLogonFileTime;
        SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);

        // Compare the modified time with the last logon time
        if (CompareFileTime(&lastWriteTime, &lastLogonFileTime) > 0) {
            // Print the file name and modified time
            std::wcout << L"[#] Executed file: " << fileName << L" at "
                << stLocal.wYear << L"-" << stLocal.wMonth << L"-" << stLocal.wDay
                << L" " << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond
                << std::endl;
        }

    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}