#include "mods.h"

// Function to check the last modified time of files in a directory
static void CheckLastModifiedTime(const wchar_t* directoryPath, const SYSTEMTIME* processStartTime) {
    // Expand the environment variables in the directory path
    wchar_t expandedPath[MAX_PATH];
    if (ExpandEnvironmentStringsW(directoryPath, expandedPath, MAX_PATH) == 0) {
        return;
    }

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(expandedPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
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
                wprintf(L"[!] Suspicious mod found: %s. Analyze it with Bintext.\n", findFileData.cFileName);
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// Function to get the start time of javaw.exe and Minecraft.Windows.exe
static void GetProcessStartTime(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    FILETIME createTime, exitTime, kernelTime, userTime;

                    // Get process times
                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        SYSTEMTIME sysTime;
                        FileTimeToSystemTime(&createTime, &sysTime);

                        // Check the last modified time of files in the Minecraft mod directory
                        CheckLastModifiedTime(L"%appdata%\\.minecraft\\mods\\*.jar", &sysTime);
                    }

                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

// Function to detect suspicious mods by checking the start time of relevant processes
void SuspiciousMods() {
    // Get the start time of the Java process
    GetProcessStartTime(L"javaw.exe");
    // Get the start time of the Minecraft Windows process
    GetProcessStartTime(L"Minecraft.Windows.exe");
}
