#include "process_scanner.hpp" // TEST VERSION //

struct ProcessParams {
    const wchar_t* processName;
    std::wstring searchPattern;
    bool useRegex;
};

class ProcessScanException : public std::exception {
public:
    ProcessScanException(const std::wstring& message)
        : message_(message), utf8Message_(ConvertToUtf8(message)) {}

    const char* what() const noexcept override {
        return utf8Message_.c_str();
    }

private:
    std::wstring message_;
    std::string utf8Message_;

    std::string ConvertToUtf8(const std::wstring& wideStr) const {
        int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string utf8Message(bufferSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, utf8Message.data(), bufferSize, nullptr, nullptr);
        return utf8Message;
    }
};

constexpr DWORD PROCESS_ACCESS_FLAGS = PROCESS_ALL_ACCESS;
constexpr BOOL INVALID_HANDLE_VALUE_FALSE = FALSE;

class ProcessSnapshot {
public:
    explicit ProcessSnapshot(DWORD flags) : handle_(CreateToolhelp32Snapshot(flags, 0)) {
        if (handle_ == INVALID_HANDLE_VALUE) {
            throw ProcessScanException(L"Failed to create a process snapshot. Error: " + std::to_wstring(GetLastError()));
        }
    }

    ~ProcessSnapshot() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    HANDLE GetHandle() const {
        return handle_;
    }

private:
    HANDLE handle_;
};

class ProcessHandle {
public:
    explicit ProcessHandle(HANDLE handle) : handle_(handle) {
        if (handle_ == INVALID_HANDLE_VALUE) {
            throw ProcessScanException(L"Invalid process handle.");
        }
    }

    ~ProcessHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    HANDLE GetHandle() const {
        return handle_;
    }

private:
    HANDLE handle_;
};

void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
                throw ProcessScanException(L"AdjustTokenPrivileges failed with error code: " + std::to_wstring(GetLastError()));
            }
        }
        else {
            throw ProcessScanException(L"LookupPrivilegeValue failed with error code: " + std::to_wstring(GetLastError()));
        }

        CloseHandle(hToken);
    }
    else {
        throw ProcessScanException(L"OpenProcessToken failed with error code: " + std::to_wstring(GetLastError()));
    }
}

void scanMemoryRegion(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi, const std::wstring& processName, DWORD pid, const std::wstring& searchPattern, bool useRegex, size_t startIndex);

void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex) {
    if (processName == nullptr) {
        std::wcerr << L"Invalid processName parameter.\n";
        return;
    }

    if (searchPattern.empty()) {
        std::wcerr << L"Invalid searchPattern parameter.\n";
        return;
    }

    DWORD pid = 0;
    ProcessSnapshot snapshot(TH32CS_SNAPPROCESS);
    HANDLE hSnapshot = snapshot.GetHandle();

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                std::wcout << L"[Process Scanner] Scanning process: " << processName << L" (PID: " << pid << L")" << std::endl;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    if (pid == 0) {
        std::wcout << L"[Process Scanner] Process not running: " << processName << '\n';
        return;
    }

    ProcessHandle processHandle(OpenProcess(PROCESS_ACCESS_FLAGS, INVALID_HANDLE_VALUE_FALSE, pid));
    HANDLE hProcess = processHandle.GetHandle();

    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != 0) {
        if ((mbi.Protect & PAGE_GUARD) != PAGE_GUARD) {
            if (mbi.State == MEM_COMMIT) {
                scanMemoryRegion(hProcess, mbi, processName, pid, searchPattern, useRegex, 0);
            }
        }

        address += mbi.RegionSize;
    }
}

bool isUnicodeCharacter(wchar_t ch) {
    return iswprint(ch) != 0;
}

void scanMemoryRegion(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi, const std::wstring& processName, DWORD pid, const std::wstring& searchPattern, bool useRegex, size_t startIndex) {
    SIZE_T bytesRead;
    std::vector<wchar_t> candidate(mbi.RegionSize / sizeof(wchar_t));

    if (startIndex >= candidate.size()) {
        std::wcerr << L"Invalid startIndex parameter." << std::endl;
        return;
    }

    if (mbi.BaseAddress != nullptr) {
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, candidate.data(), mbi.RegionSize, &bytesRead)) {
            if (startIndex >= bytesRead / sizeof(wchar_t)) {
                std::wcerr << L"Invalid startIndex parameter." << std::endl;
                return;
            }

            for (auto it = candidate.begin() + startIndex; it != candidate.begin() + bytesRead / sizeof(wchar_t); ++it) {
                if (!isUnicodeCharacter(*it)) {
                    auto start = candidate.begin() + startIndex;
                    auto end = it;
                    std::wstring candidateString(start, end);

                    if (useRegex) {
                        std::wregex pattern(searchPattern);
                        if (std::regex_search(candidateString, pattern)) {
                            std::wcout << L"String detected in " << processName << L" (PID: " << pid << L"): " << candidateString << std::endl;
                        }
                    }
                    else {
                        size_t found = candidateString.find(searchPattern);
                        if (found != std::wstring::npos) {
                            std::wcout << L"String detected in " << processName << L" (PID: " << pid << L"): " << candidateString << std::endl;
                        }
                    }

                    startIndex = std::distance(candidate.begin(), it) + 1;
                }
            }
        }
        else {
            std::wcerr << L"ReadProcessMemory failed. Error: " << GetLastError() << L", Address: " << mbi.BaseAddress << std::endl;
        }
    }
}

int main() {
    EnableDebugPrivilege();

    std::vector<ProcessParams> processParameters = {
        { L"lghub_agent.exe", L"durationms.+\"isDown\"", true },
        { L"Razer Synapse.exe", L"DeleteMacroEvent", false },
        { L"Razer Synapse 3.exe", L"SetKeysPerSecond", false },
        { L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false },
        { L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true },
        { L"Onikuma.exe", L"LeftKey CODE:", false },
        { L"explorer.exe", L"^file:///.+?.exe", true }
    };

    for (const auto& params : processParameters) {
        scanProcessStrings(params.processName, params.searchPattern, params.useRegex);
    }

    return 0;
}
