#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <regex>
#include "process_scanner.hpp"

void scanProcessStrings(const wchar_t* processName, const std::regex& pattern) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create a process snapshot" << std::endl;
        return;
    }

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess != NULL) {
            MEMORY_BASIC_INFORMATION mbi;
            unsigned char* address = 0;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
                    unsigned char buffer[4096];
                    SIZE_T bytesRead;
                    address = (unsigned char*)mbi.BaseAddress;

                    if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead)) {
                        std::string data(reinterpret_cast<char*>(buffer), bytesRead);
                        std::smatch match;

                        while (std::regex_search(data, match, pattern)) {
                            std::wcout << L"Macro detected in " << processName << L" (PID: " << pid << L"): " << std::wstring(match[0].first, match[0].second) << std::endl;
                            data = match.suffix();
                        }
                    }

                    address += mbi.RegionSize;
                } else {
                    address += mbi.RegionSize;
                }
            }

            CloseHandle(hProcess);
        }
    }
}
