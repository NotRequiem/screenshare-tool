#include "..\wmi\wmi.hpp"
#include "scheduler.hpp"

using std::min;

std::set<std::wstring> printedStrings;

template <typename CharType>
bool isValidChar(CharType ch) {
    return iswprint(ch) != 0;
}

void DetectTaskScheduler(DWORD pid) {
    if (pid == 0) {
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to run Task Scheduler checks in memory." << std::endl;
        return;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    std::wcout << L"Running task scheduler checks..." << std::endl;

    std::wregex SchedulerRegex(LR"(^[A-Za-z]:\\.+\.(dll|exe|bat|jar)|"[A-Za-z]:\\.+\.(dll|exe|bat|jar))");

    wchar_t buffer[4096];
    const size_t candidateSize = 110;
    wchar_t* candidate = new wchar_t[candidateSize];

    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead;
            for (size_t offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer)) {
                size_t blockSizeToRead = min(sizeof(buffer), static_cast<size_t>(mbi.RegionSize - offset));
                if (ReadProcessMemory(hProcess, address + offset, buffer, blockSizeToRead, &bytesRead)) {
                    size_t startIndex = 0;
                    for (size_t i = 0; i < bytesRead / sizeof(wchar_t); i++) {
                    if (!isValidChar(buffer[i])) {
                        int candidateIndex = 0;
                        for (int j = startIndex; j <= i; j++) {
                            candidate[candidateIndex++] = buffer[j];
                        }

                        candidate[candidateIndex] = L'\0';

                        if (std::regex_match(candidate, SchedulerRegex) && printedStrings.find(candidate) == printedStrings.end()) {
                            std::wcout << L"Executed file with Task Scheduler found: " << candidate << std::endl;
                            printedStrings.insert(candidate);
                        }

                        startIndex = i + 1;
                    }
                }
                }
            }
        }
        address += mbi.RegionSize / sizeof(wchar_t);
    }
    delete[] candidate;

    CloseHandle(hProcess);
}

void RunTaskSchedulerChecks() {
    const wchar_t* serviceName = L"Schedule";

        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        if (V_VT(&processId) == VT_I4) {
            DetectTaskScheduler(V_I4(&processId));
        }
        else {
            std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses." << std::endl;
        }

        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
}