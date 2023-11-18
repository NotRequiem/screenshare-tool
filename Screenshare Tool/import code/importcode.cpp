#include "..\wmi\wmi.hpp"
#include "importcode.hpp"

// List of already printed strings, so that the program does not report suspicious strings related to Import Code that were previously reported
std::set<std::wstring, std::less<std::wstring>, std::allocator<std::wstring>> printedStrings;

// Function to detect suspicious strings related to Import Code in a given process
void DetectImportCode(DWORD pid) {
    if (pid == 0) {
        return;
    }

    // Open the process with the necessary access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to run ImportCode checks in process: " << pid << std::endl;
        return;
    }

    // Get system information
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    std::wcout << L"Running import code checks on process with PID: " << pid << L"." << std::endl;

    // Define search strings for suspicious content
    std::wstring searchString1 = L"Invoke-RestMethod";
    std::wstring searchString2 = L"Invoke-Expression";
    std::wstring searchString3 = L"import base64";

    // Buffer to read memory content
    wchar_t buffer[4196];

    // Memory basic information structure
    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    // Iterate through the memory regions of the process
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        // Check if the memory region is committed
        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead;
            for (size_t offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer)) {
                const size_t blockSize = 4096;
                size_t blockSizeToRead = min(blockSize, static_cast<size_t>(mbi.RegionSize - offset));
                // Read memory content into the buffer
                if (ReadProcessMemory(hProcess, address + offset, buffer, blockSizeToRead, &bytesRead)) {
                    // Iterate through the buffer to find potential strings
                    for (size_t i = 0; i < bytesRead; i++) {
                        wchar_t candidate[sizeof(buffer) / sizeof(wchar_t)];
                        int candidateIndex = 0;

                        // Extract strings from the buffer
                        for (int j = i; j < bytesRead && candidateIndex < 18; j++) {
                            candidate[candidateIndex++] = buffer[j];
                            candidate[candidateIndex] = L'\0';

                            std::wstring candidateString(candidate);
                            // Check if the string matches any of the suspicious patterns
                            if ((candidateString.find(searchString1) != std::wstring::npos ||
                                candidateString.find(searchString2) != std::wstring::npos ||
                                candidateString.find(searchString3) != std::wstring::npos) &&
                                printedStrings.find(candidateString) == printedStrings.end()) {
                                // Print a warning if a suspicious string is found
                                std::wcout << L"Warning: Suspicious string that may be related to Import Code found: "
                                        << candidateString << std::endl;
                                // Add the string to the set to avoid duplicate warnings
                                printedStrings.insert(candidateString);
                            }
                        }
                    }
                }
            }
        }
        address += mbi.RegionSize / sizeof(wchar_t);
    }

    // Close the handle to the process
    CloseHandle(hProcess);
}

// Function to detect Import Code bypasses by checking specific services
void ImportCode() {
    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    // Iterate through specified services
    for (const wchar_t* serviceName : serviceNames) {
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        // Initialize WMI
        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect Import Code in the specified process
            DetectImportCode(V_I4(&processId));
        }
        else {
            std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect ImportCode bypasses." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}