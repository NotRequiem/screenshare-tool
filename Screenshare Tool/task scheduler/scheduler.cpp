#include "..\wmi\wmi.hpp"
#include "scheduler.hpp"

// Function to check if a character is a printable character
template <typename CharType>
bool isValidChar(CharType ch) {
    return iswprint(ch) != 0;
}

// Function to detect file execution with Task Scheduler in a specified process
void DetectTaskScheduler(DWORD pid) {
    // Check if the process ID is valid
    if (pid == 0) {
        return;
    }

    // Open the process with all access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        // Failed to open the process
        std::wcerr << L"Failed to run Task Scheduler checks in memory." << std::endl;
        return;
    }

    // Get system information
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    std::wcout << L"Running task scheduler checks..." << std::endl;

    // Regular expression pattern to match file paths with certain extensions
    std::wregex SchedulerRegex(LR"(^[A-Za-z]:\\.+\.(dll|exe|bat|jar)|"[A-Za-z]:\\.+\.(dll|exe|bat|jar))");

    // Buffer to read process memory
    wchar_t buffer[4096];

    // Size of the candidate buffer
    const size_t candidateSize = 110;

    // Candidate buffer to store potential file paths
    wchar_t* candidate = new wchar_t[candidateSize];

    MEMORY_BASIC_INFORMATION mbi;
    wchar_t* address = 0;

    // Set of printed strings to avoid duplicate output
    std::set<std::wstring> printedStrings;

    // Iterate through the memory regions of the process
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead;

            // Iterate through blocks of memory within the region
            for (size_t offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer)) {
                size_t blockSizeToRead = min(sizeof(buffer), static_cast<size_t>(mbi.RegionSize - offset));

                // Read the process memory into the buffer
                if (ReadProcessMemory(hProcess, address + offset, buffer, blockSizeToRead, &bytesRead)) {
                    size_t startIndex = 0;

                    // Iterate through the buffer and identify potential file paths
                    for (size_t i = 0; i < bytesRead / sizeof(wchar_t); i++) {
                        if (!isValidChar(buffer[i])) {
                            int candidateIndex = 0;

                            // Copy the potential file path to the candidate buffer
                            for (int j = startIndex; j <= i; j++) {
                                candidate[candidateIndex++] = buffer[j];
                            }

                            candidate[candidateIndex] = L'\0';

                            // Check if the potential file path matches the pattern and has not been printed before
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

    // Clean up allocated memory
    delete[] candidate;

    // Close the process handle
    CloseHandle(hProcess);
}

// Function to perform Task Scheduler checks using WMI
void TaskScheduler() {
    // Service name for Task Scheduler
    const wchar_t* serviceName = L"Schedule";

    // WMI interfaces
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    VARIANT processId;
    VariantInit(&processId);

    // HRESULT to store WMI operation results
    HRESULT hr;

    // Initialize WMI interfaces
    hr = InitializeWMI(pLoc, pSvc);
    if (FAILED(hr)) {
        std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
        return;
    }

    // Execute WMI query to retrieve the process ID
    hr = ExecuteWMIQuery(pSvc, serviceName, processId);
    if (FAILED(hr)) {
        std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
        // Uninitialize WMI interfaces in case of failure
        UninitializeWMI(pLoc, pSvc);
        return;
    }

    // Check the variant type and call DetectTaskScheduler if it's an integer
    if (V_VT(&processId) == VT_I4) {
        DetectTaskScheduler(V_I4(&processId));
    }
    else {
        std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses." << std::endl;
    }

    // Clear the variant
    VariantClear(&processId);

    // Uninitialize WMI interfaces
    UninitializeWMI(pLoc, pSvc);
}
