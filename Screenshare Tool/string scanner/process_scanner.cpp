#include "process_scanner.hpp"

bool isUnicodeCharacter(wchar_t ch) {
    return iswprint(ch) != 0;
}

void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create a process snapshot to detect strings. Error: " << GetLastError() << std::endl;
        return;
    }

    // Check if the process is running
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                std::wcout << L"[Process Scanner] Scanning process: " << processName << L" (PID: " << pid << L")" << std::endl;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // If the process is not running, skip the memory scanning
    if (pid == 0) {
        std::wcout << L"[Process Scanner] Process not running: " << processName << std::endl;
        return;
    }

    // Open the process with PROCESS_ALL_ACCESS access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProcess == NULL) {
        std::wcerr << L"Failed to open the process. Error: " << GetLastError() << std::endl;
        return;
    }

    // Buffer to read process memory
    wchar_t buffer[4096]{};

    // Size of the candidate buffer
    const size_t candidateSize = 110;

    // Candidate buffer to store potential file paths
    wchar_t* candidate = new wchar_t[candidateSize];

    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    // Iterate through the memory regions of the process
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead;

            // Check if address is not null before reading process memory
            if (address != nullptr) {
                // Read the process memory into the buffer
                if (ReadProcessMemory(hProcess, address, buffer, mbi.RegionSize, &bytesRead)) {
                    size_t startIndex = 0;

                    // Iterate through the buffer and identify potential file paths
                    for (size_t i = 0; i < bytesRead / sizeof(wchar_t); i++) {
                        if (!isUnicodeCharacter(buffer[i])) {
                            int candidateIndex = 0;

                            // Copy the potential file path to the candidate buffer
                            for (size_t j = startIndex; j <= i; j++) {
                                candidate[candidateIndex++] = buffer[j];
                            }

                            candidate[candidateIndex] = L'\0';

                            if (useRegex) {
                                // Convert the search pattern to a regex
                                std::wregex pattern(searchPattern);

                                // Use regex match for the entire buffer
                                if (std::regex_search(std::wstring(candidate), pattern)) {
                                    // Process the candidate string as needed
                                    std::wcout << L"String detected in " << processName << L" (PID: " << pid << L"): " << std::wstring(candidate) << std::endl;
                                }
                            }
                            else {
                                std::wstring candidateString(candidate);
                                // Search for the exact string without using regex
                                size_t found = candidateString.find(searchPattern);
                                if (found != std::wstring::npos) {
                                    // Process the candidate string as needed
                                    std::wcout << L"String detected in " << processName << L" (PID: " << pid << L"): " << candidateString << std::endl;
                                }
                            }

                            startIndex = i + 1;  // Move to the next character after the detected string
                        }
                    }
                }
                else {
                    // Print an error message including the address and continue to the next region
                    std::wcerr << L"ReadProcessMemory failed. Error: " << GetLastError() << L", Address: " << address << std::endl;
                }
            }

            address += mbi.RegionSize;
        }
    }

    delete[] candidate;
    CloseHandle(hProcess);
}

void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                std::cerr << "AdjustTokenPrivileges failed with error code: " << GetLastError() << std::endl;
            }
        }
        else {
            std::cerr << "LookupPrivilegeValue failed with error code: " << GetLastError() << std::endl;
        }

        CloseHandle(hToken);
    }
    else {
        std::cerr << "OpenProcessToken failed with error code: " << GetLastError() << std::endl;
    }
}

int main() {
    EnableDebugPrivilege();

    std::vector<std::tuple<const wchar_t*, std::wstring, bool>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms.+\"isDown\"", true),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false),
        std::make_tuple(L"explorer.exe", L"^file:///.+?.exe", true)
    };

    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);

        scanProcessStrings(processName, searchPattern, useRegex);
    }

    return 0;
}
