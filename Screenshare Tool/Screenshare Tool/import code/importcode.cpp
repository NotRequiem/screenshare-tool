#include "..\wmi\wmi.hpp"
#include "importcode.hpp"

std::set<std::wstring, std::less<std::wstring>, std::allocator<std::wstring>> ImportCodeDetector::printedStrings;

void ImportCodeDetector::DetectImportCode(DWORD pid) {
    if (pid == 0) {
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to run ImportCode checks in process: " << pid << std::endl;
        return;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    std::wcout << L"Running import code checks on process with PID: " << pid << L"." << std::endl;

    std::wstring searchString1 = L"Invoke-RestMethod";
    std::wstring searchString2 = L"Invoke-Expression";
    std::wstring searchString3 = L"import base64";

    wchar_t buffer[4196];

    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead;
            for (size_t offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer)) {
                const size_t blockSize = 4096;
                size_t blockSizeToRead = std::min(blockSize, static_cast<size_t>(mbi.RegionSize - offset));
                if (ReadProcessMemory(hProcess, address + offset, buffer, blockSizeToRead, &bytesRead)) {
                    std::wstring candidateString;
                    for (size_t i = 0; i < bytesRead; i++) {
                        wchar_t candidate[sizeof(buffer) / sizeof(wchar_t)];
                        int candidateIndex = 0;

                            for (int j = i; j < bytesRead && candidateIndex < 18; j++) {
                            candidate[candidateIndex++] = buffer[j];
                            candidate[candidateIndex] = L'\0';

                            std::wstring candidateString(candidate);
                            if ((candidateString.find(searchString1) != std::wstring::npos ||
                                candidateString.find(searchString2) != std::wstring::npos ||
                                candidateString.find(searchString3) != std::wstring::npos) &&
                                printedStrings.find(candidateString) == printedStrings.end()) {
                                std::wcout << L"Warning: Suspicious string that may be related to Import Code found: "
                                        << candidateString << std::endl;
                                printedStrings.insert(candidateString);
                            }
                        }
                    }
                }
            }
        }
        address += mbi.RegionSize / sizeof(wchar_t);
    }

    CloseHandle(hProcess);
}

void ImportCodeDetector::RunImportCodeChecks() {
    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    for (const wchar_t* serviceName : serviceNames) {
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        if (V_VT(&processId) == VT_I4) {
            DetectImportCode(V_I4(&processId));
        }
        else {
            std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect ImportCode bypasses." << std::endl;
        }

        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }

}