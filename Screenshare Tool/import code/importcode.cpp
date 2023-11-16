#include "..\wmi\wmi.hpp"
#include "importcode.hpp"

bool isStringChar(unsigned char ch) {
    return (ch >= 32 && ch <= 126);
}

void ImportCodeDetector::DetectImportCode(DWORD pid) {
    if (pid == 0) {
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to run ImportCode checks in process: " << pid << std::endl;
        return;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    std::wcout << L"Running import code checks in process with PID: " << pid << std::endl;

    unsigned char buffer[4096];

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
    if (mbi.State == MEM_COMMIT) {
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead)) {
            size_t startIndex = 0;
            for (size_t i = 0; i < bytesRead; i++) {
                if (!isStringChar(buffer[i])) {
                    char candidate[sizeof(buffer)];
                    int candidateIndex = 0;
                    for (int j = startIndex; j < i; j++) {
                        candidate[candidateIndex++] = buffer[j];
                    }
                    candidate[candidateIndex] = '\0';


                    // Check for warning conditions
                    if (strstr(candidate, "Invoke-Expression") ||
                        strstr(candidate, "Invoke-RestMethod") ||
                        strstr(candidate, "https://") ||
                        strstr(candidate, "import base64")) {
                        // Flag a warning
                        std::wcerr << L"Warning: Suspicious string related to the bypass method 'Code Import' found - " << candidate << std::endl;
                    }

                    // Update the startIndex for the next candidate
                    startIndex = i + 1;
                }
            }
            // Update the address for the next bytes to be read
            address += bytesRead;
        }
    }
    // Update the address for the next memory region
    address += mbi.RegionSize;
}

    CloseHandle(hProcess);
}

void ImportCodeDetector::RunImportCodeChecks() {
    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    // Run ImportCode checks for specified services
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
