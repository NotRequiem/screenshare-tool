#include "userproc.hpp"

std::unordered_set<std::wstring> printedLines;
static std::vector<std::string> extensions = { ".exe", ".dll", ".jar", ".bat", ".vbs", ".py", ".ps1" };

// Function to check if a file signature is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

// Utility function to replace all occurrences of a character in a string
void ReplaceAll(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

static void ExtractFilePath(const std::string& line) {
    size_t startPos = std::string::npos;
    size_t endPos = std::string::npos;

    if (line.find("TRACE,0000,0000,PcaClient,MonitorProcess,") == 0) {
        startPos = line.find("TRACE,0000,0000,PcaClient,MonitorProcess,") + 41; // Move past "TRACE,0000,0000,PcaClient,MonitorProcess,"
    }
    else if (line.find("file:///") == 0) {
        startPos = line.find("file:///") + 8; // Move past "file:///"
    }

    // Find the extension
    for (const auto& ext : extensions) {
        size_t foundPos = line.find(ext, startPos);
        if (foundPos != std::string::npos) {
            endPos = foundPos + ext.size();
            break;
        }
    }

    if (startPos != std::string::npos && endPos != std::string::npos) {
        // Remove any characters after the extension
        std::string filePath = line.substr(startPos, endPos - startPos);
        // Replace forward slashes with backslashes
        size_t pos = 0;
        while ((pos = filePath.find("%20", pos)) != std::string::npos) {
            filePath.replace(pos, 3, " ");
            pos += 1; // Move past the replaced space to avoid infinite loop
        }
        ReplaceAll(filePath, "/", "\\");
        std::wstring wideFilePath(filePath.begin(), filePath.end());
        if (printedLines.find(wideFilePath) == printedLines.end()) {
            if (fs::exists(wideFilePath)) {
                if (!IsFileSignatureValid(wideFilePath)) {
                    std::wcout << L"[#] Executed & Unsigned file: " << wideFilePath << std::endl;
                }
            }
            else {
                std::wcout << L"[#] Executed & Deleted file: " << wideFilePath << std::endl;
            }
            printedLines.insert(wideFilePath);
        }
    }
}

DWORD GetExplorerPID() {
    DWORD processes[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; ++i) {
        DWORD pid = processes[i];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess != NULL) {
            WCHAR processName[MAX_PATH];
            if (GetProcessImageFileNameW(hProcess, processName, sizeof(processName) / sizeof(WCHAR))) {
                std::wstring processNameStr(processName);
                std::transform(processNameStr.begin(), processNameStr.end(), processNameStr.begin(), ::tolower);
                if (processNameStr.find(L"explorer.exe") != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return pid;
                }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}

static void Explorer() {
    // Get the PID of the Explorer process
    DWORD pid = GetExplorerPID();
    if (pid == 0) {
        std::cerr << "Failed to find explorer.exe process." << std::endl;
        return;
    }

    // Build command line to execute the memory scanner
    std::wstring commandLine = L"memory.exe -p " + std::to_wstring(pid);
    // Create pipe handles with proper memory management using smart pointers
    HANDLE hChildStdoutRd, hChildStdoutWr;
    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
        return;
    }

    // Set up STARTUPINFO and PROCESS_INFORMATION structs
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window

    PROCESS_INFORMATION pi;

    // Launch the memory scanner process
    if (!CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutRd);
        CloseHandle(hChildStdoutWr);
        return;
    }

    // Close unnecessary write handle
    CloseHandle(hChildStdoutWr);

    // Read and process the output of the memory scanner
    CHAR buffer[4096]{};
    DWORD bytesRead;
    while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
        std::string outputString(buffer, bytesRead);

        // Use istringstream to parse the output into lines
        std::istringstream outputStream(outputString);
        std::string line;
        while (std::getline(outputStream, line)) {
            if ((line.find("TRACE,0000,0000,PcaClient,MonitorProcess,") == 0 || line.find("file:///") == 0) && line.find(".exe") != std::string::npos) {
                if ((line.find("TRACE,0000,0000,PcaClient,MonitorProcess,") == 0 || line.find("file:///") == 0) && line.find(".exe") != std::string::npos) {
                    ExtractFilePath(line);
                }
            }
        }
    }


    // Wait for the process to finish and close handles
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStdoutRd);
}

static void DetectExes(DWORD pid) {
    // Build command line to execute the memory scanner
    std::wstring commandLine = L"memory.exe -p " + std::to_wstring(pid);

    // Create pipe handles with proper memory management using smart pointers
    HANDLE hChildStdoutRd, hChildStdoutWr;
    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
        return;
    }

    // Set up STARTUPINFO and PROCESS_INFORMATION structs
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window

    PROCESS_INFORMATION pi;

    // Launch the memory scanner process
    if (!CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutRd);
        CloseHandle(hChildStdoutWr);
        return;
    }

    // Close unnecessary write handle
    CloseHandle(hChildStdoutWr);

    // Read and process the output of the memory scanner
    CHAR buffer[4096]{};
    DWORD bytesRead;
    while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
        std::string outputString(buffer, bytesRead);

        // Use istringstream to parse the output into lines
        std::istringstream outputStream(outputString);
        std::string line;
        while (std::getline(outputStream, line)) {
            // Convert the line to a wide string using MultiByteToWideChar
            int wideSize = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, NULL, 0);
            if (wideSize > 0) {
                std::vector<wchar_t> wideLine(wideSize);
                MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, wideLine.data(), wideSize);

                std::wstring wideStr(wideLine.data());

                size_t volumePos = wideStr.find(L"\\device\\harddiskvolume");
                if (volumePos != std::wstring::npos) {
                    wchar_t driveNumber = wideStr[volumePos + 22];
                    std::wstring devicePath = L"\\Device\\HarddiskVolume";
                    devicePath.push_back(driveNumber);

                    std::wstring driveLetter = ConvertDevicePathToFilePath(devicePath);

                    wideStr.replace(volumePos, 23, driveLetter);

                    // Find the last occurrence of ".exe" in wideStr
                    size_t lastExePos = wideStr.rfind(L".exe");
                    if (lastExePos == std::wstring::npos) {
                        // If ".exe" is not found, skip this iteration
                        continue;
                    }

                    // Adjust wideStr's length to include only up to the last occurrence of ".exe"
                    wideStr.resize(lastExePos + 4);
                    if (printedLines.find(wideStr) == printedLines.end()) {
                        // Check if the file exists
                        if (std::filesystem::exists(wideStr)) {
                            if (!IsFileSignatureValid(wideStr)) {
                                std::wcout << "[#] Executed & Unsigned file: " << wideStr << std::endl;
                            }
                        }
                        else {
                            std::wcout << "[#] Executed & Deleted file: " << wideStr << std::endl;
                        }
                        // Add the filename to printedLines to avoid duplicated results
                        printedLines.insert(wideStr);
                    }
                }
            }
        }
    }


    // Wait for the process to finish and close handles
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStdoutRd);
}

static void DetectJarsAndBats(DWORD pid) {
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L"-jar", L"[#] Executed file: " },
        { L".bat", L"[#] Executed file: " },
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
void ExecutedFiles(bool imp) {
    if (!imp) {
        setConsoleTextColor(BrightYellow);
        std::wcout << "[Memory Scanner] Running checks to detect executed files in memory...\n";
        resetConsoleTextColor();
    }

    // Print the process being scanned
    setConsoleTextColor(BrightYellow);
    std::wcout << "[Memory Scanner] Analyzing process " << "Explorer" << std::endl;
    resetConsoleTextColor();
    Explorer();

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    HRESULT hr = InitializeWMI(pLoc, pSvc);
    if (FAILED(hr)) {
        return;
    }

    // Service names and corresponding file types
    const wchar_t* serviceFileNames[][2] = {
        { L"DPS", L"exe" },
        { L"PlugPlay", L"jar/bat" },
        { L"PcaSvc", L"jar/bat" },
        { L"Winmgmt", L"jar/bat" },
        { L"DiagTrack", L"jar/bat" }
    };

    // Iterate through service names to detect file executions
    for (const auto& serviceFile : serviceFileNames) {
        const wchar_t* serviceName = serviceFile[0];
        const wchar_t* fileType = serviceFile[1];

        // Check if service is disabled
        SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scm != nullptr) {
            SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG);
            if (service != nullptr) {
                DWORD bytesNeeded = 0;
                QUERY_SERVICE_CONFIG* serviceConfig = nullptr;
                if (QueryServiceConfig(service, nullptr, 0, &bytesNeeded) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    serviceConfig = (QUERY_SERVICE_CONFIG*)malloc(bytesNeeded);
                    if (serviceConfig != nullptr) {
                        if (QueryServiceConfig(service, serviceConfig, bytesNeeded, &bytesNeeded) != 0) {
                            if (serviceConfig->dwStartType == SERVICE_DISABLED) {
                                std::wcerr << L"[#] The following service is disabled: '" << serviceName << L"'. This is not considered bannable.\n";
                                CloseServiceHandle(service);
                                CloseServiceHandle(scm);
                                free(serviceConfig);
                                continue;
                            }
                        }
                        free(serviceConfig);
                    }
                }
                CloseServiceHandle(service);
            }
            CloseServiceHandle(scm);
        }

        // Print the service being scanned
        setConsoleTextColor(BrightYellow);
        std::wcout << "[Memory Scanner] Analyzing service " << serviceName << std::endl;
        resetConsoleTextColor();

        VARIANT processId;
        VariantInit(&processId);

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);

        if (FAILED(hr)) {
            std::wcerr << L"[!] Failed to retrieve process ID for service: '" << serviceName << L"'.\n";
        }
        else if (V_VT(&processId) == VT_I4) {
            if (wcscmp(serviceName, L"DiagTrack") == 0) {
                // Detect exe and jar/bat file executions for DiagTrack service
                DetectExes(V_I4(&processId));
                DetectJarsAndBats(V_I4(&processId));
            }
            else if (wcscmp(fileType, L"exe") == 0) {
                // Detect exe file executions for other services
                DetectExes(V_I4(&processId));
            }
            else {
                // Detect jar and bat file executions for other services
                DetectJarsAndBats(V_I4(&processId));
            }
        }
        else {
            std::wcerr << L"[!] The following service is not running: '" << serviceName << L"'. Ban the user.\n";
        }

        // Clear the variant
        VariantClear(&processId);
    }

    // Common cleanup
    UninitializeWMI(pLoc, pSvc);
}
