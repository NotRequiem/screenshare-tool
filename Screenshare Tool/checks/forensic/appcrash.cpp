#include "appcrash.hpp"

void AppCrash(bool imp) {
    if (!imp) {
        setConsoleTextColor(Magenta);
        std::wcout << "[Forensic Scanner] Running checks to detect executed files with crash logs...\n";
        resetConsoleTextColor();
    }

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
    std::unique_ptr<void, decltype(&FindClose)> hFind(FindFirstFileW(searchPattern.c_str(), &findFileData), &FindClose);

    if (hFind.get() == nullptr) {
        std::cerr << "Error scanning for AppCrash files\n";
        return;
    }

    // Check for an empty directory
    if (FindNextFileW(hFind.get(), &findFileData) == 0) {
        std::cerr << "No AppCrash files found\n";
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
            // Convert fileName to UTF-8
            std::string fileNameUtf8 = convertWStringToUtf8(fileName);

            // Print the file name and modified time using wprintf
            wprintf(L"[#] Executed file: %hs at %04d-%02d-%02d %02d:%02d:%02d\n",
                fileNameUtf8.c_str(),
                stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        }

    } while (FindNextFileW(hFind.get(), &findFileData) != 0);
}
