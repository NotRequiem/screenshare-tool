#include "userproc.hpp"

// Function to check if a file signature is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

// Function to detect accessed files using Explorer's memory
static void Explorer() {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp(entry.szExeFile, "explorer.exe") == 0) {
                DWORD pid = entry.th32ProcessID;

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

                        std::regex ExplorerAccessedFiles(R"(file:///.+\.(exe|bat|jar|vbs|py|ps1))");

                        std::istringstream outputStream(outputString);
                        std::string line;

                        std::set<std::wstring> printedLines;  // Container to track printed lines

                        while (std::getline(outputStream, line)) {
                            if (std::regex_search(line, ExplorerAccessedFiles)) {

                                // Here I just process the memory contents for better output:

                                // Remove "file:///" and replace "%20" with "/"
                                std::wstring wline;
                                int requiredSize = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, NULL, 0);
                                if (requiredSize > 0) {
                                    wline.resize(requiredSize);
                                    MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, &wline[0], requiredSize);
                                }

                                size_t pos = wline.find(L"file:///");
                                if (pos != std::wstring::npos) {
                                    wline.erase(pos, 8);  // Remove "file:///"
                                }

                                // Replace %20 with a space
                                size_t pos_percent = wline.find(L"%20");
                                while (pos_percent != std::wstring::npos) {
                                    wline.replace(pos_percent, 3, L" ");  // Replace %20 with a space
                                    pos_percent = wline.find(L"%20");
                                }

                                // Replace \\20 with a backslash
                                size_t pos_backslash = wline.find(L"\\20");
                                while (pos_backslash != std::wstring::npos) {
                                    wline.replace(pos_backslash, 3, L"\\");  // Replace \\20 with a backslash
                                    pos_backslash = wline.find(L"\\20");
                                }

                                // Replace / with a forward slash
                                std::replace(wline.begin(), wline.end(), L'/', L'\\');

                                if (printedLines.find(wline) == printedLines.end() && !IsFileSignatureValid(wline)) {
                                    std::wcout << L"[[#] Accessed file: " << wline << std::endl;
                                    printedLines.insert(wline);  // to not print the same file twice
                                }
                            }
                        }
                    }

                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }

                CloseHandle(hChildStdoutRd);

                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

static void DetectJarsAndBats(DWORD pid) {
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L".bat", L"[#] Executed file (false flags here may happen and won't be fixed): " },
        { L"-jar", L"[#] Executed file (false flags here may happen and won't be fixed): " },
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
    std::wcout << "[Memory Scanner] Running checks to detect accessed files in memory...\n";
    resetConsoleTextColor();

    Explorer();
    const wchar_t* serviceNames[] = { L"PlugPlay", L"PcaSvc" };

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
        hr = ExecuteWMIQuery(pSvc, serviceName, processId); // ignore hr overwriting
        
        if (FAILED(hr)) {
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect jars and bats file executions in PcaSvc and PlugPlay
            DetectJarsAndBats(V_I4(&processId));
        }
        else {
            std::wcerr << L"[!] The following process is not running: '" << serviceName << L"'. Ban the user." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
    }

    UninitializeWMI(pLoc, pSvc);
}
