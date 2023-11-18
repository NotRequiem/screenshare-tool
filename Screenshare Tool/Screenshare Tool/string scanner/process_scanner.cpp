#include "process_scanner.hpp"

void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex) {

    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create a process snapshot to detect strings." << std::endl;
        return;
    }

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                std::wcout << L"Scanning process: " << processName << L" (PID: " << pid << L")" << std::endl;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess != NULL) {
            MEMORY_BASIC_INFORMATION mbi;
            unsigned char* address = 0;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
                    unsigned char buffer[4096];
                    SIZE_T bytesRead;
                    address = (unsigned char*)mbi.BaseAddress;
                    while (address < (unsigned char*)mbi.BaseAddress + mbi.RegionSize) {
                    if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead)) {
                        std::string data(reinterpret_cast<char*>(buffer), bytesRead);

                        if (useRegex) {
                            std::wregex pattern(searchPattern.begin(), searchPattern.end());
                            std::wcmatch wmatch;
                            const std::wstring dataString(data.begin(), data.end());
                            const wchar_t* dataStart = dataString.c_str();
                            const wchar_t* dataEnd = dataStart + data.size();

                            while (std::regex_search(dataStart, dataEnd, wmatch, pattern)) {
                                std::wcout << L"String detected in " << processName << L" (PID: " << pid << L"): " << wmatch[0].str() << std::endl;
                                dataStart = wmatch[0].second;
                            }
                        }
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
