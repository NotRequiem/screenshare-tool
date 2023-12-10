#include "importcode.hpp"

// Function to detect specific import code patterns in the memory of a specified process.
static void DetectImportCode(DWORD pid) {
    // Define patterns to search for and corresponding messages
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L"Invoke-RestMethod", L"[!] Found ImportCode string: 'Invoke-RestMethod'." },
        { L"Invoke-Expression", L"[!] Found ImportCode string: 'Invoke-Expression'." },
        { L"import base64", L"[!] Found ImportCode string: 'import base64'." }
    };

    // Build command line to execute the memory scanner.exe and scan these importcode strings
    std::wstring commandLine = L"memory scanner.exe -p " + std::to_wstring(pid);

    // Set up security attributes for the pipe
    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's stdout
    HANDLE hChildStdoutRd, hChildStdoutWr;
    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    // Set up startup info for the child process
    STARTUPINFOW si = { sizeof(STARTUPINFO) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window to avoid interruption with the Screenshare

    // Initialize PROCESS_INFORMATION structure to receive information about the spawned process
    PROCESS_INFORMATION pi;

    // Create the child process
    if (CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        // Close the write end of the pipe as it is not needed in this process
        CloseHandle(hChildStdoutWr);

        // Buffer to store output from the child process
        CHAR buffer[4096]{};
        DWORD bytesRead;

        // Read output from the pipe and search for specified patterns
        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            // Convert wide char buffer to std::wstring
            std::wstring outputWString(buffer, buffer + bytesRead / sizeof(wchar_t));

            // Iterate through patterns and check for matches in the output
            for (const auto& patternAndMessage : patternsAndMessages) {
                const auto& searchPattern = patternAndMessage.first;
                const auto& message = patternAndMessage.second;

                // Convert search pattern to std::wstring for comparison
                std::wstring patternWString = std::wstring(searchPattern.begin(), searchPattern.end());

                // Check if the output contains the import code string
                if (outputWString.find(patternWString) != std::wstring::npos) {
                    // Print the detection message along with the process pid
                    std::wcout << message << L"on process with pid: " << pid << L". This is bannable!" << std::endl;
                }
            }
        }

        // Wait for the child process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Close handles to avoid resource leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Close the read end of the pipe
    CloseHandle(hChildStdoutRd);
}

// Function to detect Import Code bypasses by checking specific services
void ImportCode() {
    setConsoleTextColor(Red);
    std::wcout << L"[Code Import Scanner] Running checks to detect Import code bypasses..." << std::endl;
    resetConsoleTextColor();

    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    // Iterate through specified services
    for (const wchar_t* serviceName : serviceNames) {
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        // Initialize WMI
        hr = InitializeWMI(pLoc, pSvc);

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            // Print a warning message if the "eventlog" service is not found
            if (wcscmp(serviceName, L"eventlog") == 0) {
                std::wcerr << "[!] The 'eventlog' service is not running. Ban the user." << std::endl;
            }

            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect Import Code in the specified process
            DetectImportCode(V_I4(&processId));
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
    }

    UninitializeWMI(pLoc, pSvc);
}
