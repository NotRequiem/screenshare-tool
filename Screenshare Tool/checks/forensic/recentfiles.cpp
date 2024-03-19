#include "recentfiles.hpp"

static bool GetRecentDirectory(std::wstring& recentDir) {
    PWSTR appDataPath;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Recent, 0, NULL, &appDataPath))) {
        recentDir = appDataPath;
        CoTaskMemFree(appDataPath);
        return true;
    }
    return false;
}

static bool ContainsSubstring(const std::wstring& fileName, const std::vector<std::wstring>& substrings) {
    for (const auto& substring : substrings) {
        if (fileName.find(substring) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void RecentFiles(bool imp) {
    if (!imp) {
        setConsoleTextColor(Magenta);
        std::wcout << "[Forensic Scanner] Running checks to detect recently accessed files...\n";
        resetConsoleTextColor();
    }

    std::wstring recentDir;
    if (!GetRecentDirectory(recentDir)) {
        return;
    }

    SYSTEMTIME lastLogonTime;
    if (!LogonTime(lastLogonTime)) {
        return;
    }

    std::wstring searchPattern = recentDir + L"\\*.*";
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    std::vector<std::wstring> substrings = { L".jar", L".bat", L".vbs", L".py", L".ps1", L".dll"};
    do {
        if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            std::wstring wideFileName = findFileData.cFileName;
            if (ContainsSubstring(wideFileName, substrings) &&
                CompareFileTime(&findFileData.ftLastWriteTime, (FILETIME*)&lastLogonTime) > 0) {
                std::wcout << "[#] Recently accessed file: " << wideFileName << std::endl;
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}
