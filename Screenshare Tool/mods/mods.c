#include "mods.h"

// Function to check the last modified time of files in a directory
static void CheckLastModifiedTime(const TCHAR* directoryPath, const SYSTEMTIME* processStartTime) {
    // Expand the environment variables in the directory path
    TCHAR expandedPath[MAX_PATH];
    if (ExpandEnvironmentStrings(directoryPath, expandedPath, MAX_PATH) == 0) {
        _tprintf(_T("Error expanding environment strings while checking for suspicious mods ran by the game. Error: %d\n"), GetLastError());
        return;
    }

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(expandedPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Error: Unable to find files in Minecraft's mod directory.\n"));
        return;
    }

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            // Convert FILETIME to SYSTEMTIME for last write time
            SYSTEMTIME fileLastModifiedTime;
            FileTimeToSystemTime(&findFileData.ftLastWriteTime, &fileLastModifiedTime);

            // Convert process start time to FILETIME for comparison
            FILETIME processStartFileTime;
            SystemTimeToFileTime(processStartTime, &processStartFileTime);

            // Compare with process start time
            if (CompareFileTime(&findFileData.ftLastWriteTime, &processStartFileTime) > 0) {
                _tprintf(_T("Suspicious mod found: %s\n"), findFileData.cFileName);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// Function to get the start time of javaw.exe and Minecraft.Windows.exe
static void GetProcessStartTime(const TCHAR* processName, SYSTEMTIME* processStartTime) {
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

                    // Get process times
                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        SYSTEMTIME sysTime;
                        FileTimeToSystemTime(&createTime, &sysTime);

                        // Check the last modified time of files in the Minecraft mod directory
                        CheckLastModifiedTime(_T("%appdata%\\.minecraft\\mods\\*.jar"), &sysTime);
                    }
                    else {
                        _tprintf(_T("Error getting process times for %s while checking for suspicious mods ran by the game. Error: %d\n"), processName, GetLastError());
                    }

                    CloseHandle(hProcess);
                }
                else {
                    _tprintf(_T("Error opening process for %s while checking for suspicious mods ran by the game. Error: %d\n"), processName, GetLastError());
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

// Function to detect suspicious mods by checking the start time of relevant processes
void SuspiciousMods() {
    SYSTEMTIME sysTime;
    _tprintf("Running checks to detect suspicious mods ran by the game... \n");

    // Get the start time of the Java process
    GetProcessStartTime(_T("javaw.exe"), &sysTime);
    // Get the start time of the Minecraft Windows process
    GetProcessStartTime(_T("Minecraft.Windows.exe"), &sysTime);
}