#include "userproc.hpp"

static void DetectJarsAndBats(DWORD pid) {
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L"-jar", L"[[#] Executed file: " },
        { L".bat", L"[[#] Executed file: " },
    };

    // Build command line to execute the memory scanner
    std::wstring commandLine = L"memory.exe -p " + std::to_wstring(pid);

    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStdoutRd, hChildStdoutWr;
    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

    PROCESS_INFORMATION pi;

    if (CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutWr);

        CHAR buffer[4096]{};
        DWORD bytesRead;

        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            std::string outputString(buffer, bytesRead);

            // Use istringstream to parse the output into lines
            std::istringstream outputStream(outputString);
            std::string line;

            while (std::getline(outputStream, line)) {

                for (const auto& patternAndMessage : patternsAndMessages) {
                    const auto& searchPattern = patternAndMessage.first;
                    const auto& message = patternAndMessage.second;

                    // Convert searchPattern to std::wstring
                    std::wstring wideSearchPattern(searchPattern.begin(), searchPattern.end());

                    // Convert the line to a wide string
                    int lineSize = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, NULL, 0);
                    if (lineSize > 0) {
                        std::wstring wideLine(lineSize, L'\0');
                        MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, &wideLine[0], lineSize);

                        // Use find on std::wstring
                        if (wideLine.find(wideSearchPattern) != std::wstring::npos) {
                            std::wcout << message << wideLine << std::endl;
                        }
                    }
                }
            }
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hChildStdoutRd);
}

// Function to detect executed files by checking specific services
void ExecutedFiles() {
    setConsoleTextColor(BrightYellow);
    std::wcout << "[Memory Scanner] Running checks to detect executed files in memory...\n";
    resetConsoleTextColor();

    // Service names to detect jar and batch file executions
    const wchar_t* serviceNames[] = { L"PlugPlay", L"PcaSvc", L"Winmgmt", L"DiagTrack" };

    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

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
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect jars and bats file executions in the specified service
            DetectJarsAndBats(V_I4(&processId));
        }
        else {
            std::wcerr << L"[!] The following service is not running: '" << serviceName << L"'. Ban the user.\n";
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
    }

    UninitializeWMI(pLoc, pSvc);
}
