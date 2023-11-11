#include "DiskChecker.hpp"

bool FileExists(const std::wstring& filePath) {
    DWORD fileAttributes = GetFileAttributesW(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

time_t GetLastBootTime() {
    DWORD64 tickCount = GetTickCount64();
    return time(nullptr) - (static_cast<time_t>(tickCount) / 1000);
}

time_t GetLastModifiedTime(const std::wstring& filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        FILETIME ft = fileInfo.ftLastWriteTime;
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        return static_cast<time_t>(li.QuadPart / 10000000ULL - 11644473600ULL);
    }
    return 0;
}

void CheckDiskInstallation() {
    std::vector<std::wstring> driveLetters;
    DWORD drives = GetLogicalDrives();
    for (wchar_t i = L'A'; i <= L'Z'; i++) {
        if ((drives & 1) == 1) {
            std::wstring driveLetter(1, i);
            driveLetters.push_back(driveLetter);
        }
        drives >>= 1;
    }

    time_t lastBootTime = GetLastBootTime();

    for (const std::wstring& driveLetter : driveLetters) {
        if (driveLetter == L"C") {
            continue;
        }

        std::wstring rootPath = driveLetter + L":\\";
        std::wstring systemInfoPath = rootPath + L"System Volume Information";

        time_t lastModifiedTime = GetLastModifiedTime(systemInfoPath);
        if (lastModifiedTime > lastBootTime) {
            struct tm timeInfo;
            localtime_s(&timeInfo, &lastModifiedTime);
            std::wcout << L"Warning: Disk " << driveLetter << L" was installed at: " << std::put_time(&timeInfo, L"%c")
                       << L". This can be used as an anti-forensic bypass method." << std::endl;
        }
    }
}
