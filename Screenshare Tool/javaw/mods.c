#include "mods.h"

int main() {
    SYSTEMTIME sysTime;
    GetProcessStartTime(_T("javaw.exe"), &sysTime);
    GetProcessStartTime(_T("Minecraft.Windows.exe"), &sysTime);
    return 0;
}

void CheckLastModifiedTime(const TCHAR* directoryPath, const SYSTEMTIME* processStartTime) {
    // Expand the environment variables in the directory path
    TCHAR expandedPath[MAX_PATH];
    if (ExpandEnvironmentStrings(directoryPath, expandedPath, MAX_PATH) == 0) {
        _tprintf(_T("Error expanding environment strings. Error: %d\n"), GetLastError());
        return;
    }

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(expandedPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Error: Unable to find files in the specified directory.\n"));
        return;
    }

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            _tprintf(_T("File: %s\n"), findFileData.cFileName);

            // Convert FILETIME to SYSTEMTIME for last write time
            SYSTEMTIME fileLastModifiedTime;
            FileTimeToSystemTime(&findFileData.ftLastWriteTime, &fileLastModifiedTime);

            // Print the last modified time
            _tprintf(_T("Last Modified Time: %02d/%02d/%d %02d:%02d:%02d\n"),
                fileLastModifiedTime.wMonth, fileLastModifiedTime.wDay, fileLastModifiedTime.wYear,
                fileLastModifiedTime.wHour, fileLastModifiedTime.wMinute, fileLastModifiedTime.wSecond);

            // Convert process start time to FILETIME for comparison
            FILETIME processStartFileTime;
            SystemTimeToFileTime(processStartTime, &processStartFileTime);

            // Compare with process start time
            if (CompareFileTime(&findFileData.ftLastWriteTime, &processStartFileTime) > 0) {
                _tprintf(_T("Last modified time is after process start time.\n"));
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void GetProcessStartTime(const TCHAR* processName, SYSTEMTIME* processStartTime) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Error creating process snapshot.\n"));
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_tcsicmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    FILETIME createTime, exitTime, kernelTime, userTime;

                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        SYSTEMTIME sysTime;
                        FileTimeToSystemTime(&createTime, &sysTime);

                        _tprintf(_T("Process: %s\n"), processName);
                        _tprintf(_T("Start Time: %02d/%02d/%d %02d:%02d:%02d\n"),
                            sysTime.wMonth, sysTime.wDay, sysTime.wYear,
                            sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

                        CheckLastModifiedTime(_T("%appdata%\\.minecraft\\mods\\*.jar"), &sysTime);
                    }
                    else {
                        _tprintf(_T("Error getting process times for %s. Error: %d\n"), processName, GetLastError());
                    }

                    CloseHandle(hProcess);
                }
                else {
                    _tprintf(_T("Error opening process for %s. Error: %d\n"), processName, GetLastError());
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}
