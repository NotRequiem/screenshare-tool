#include "..\wmi\wmi.hpp"
#include "userproc.hpp"

bool warningDisplayed = false;

// Function to detect accessed files using Explorer's memory
static void Explorer() {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        do {
            if (wcscmp(entry.szExeFile, L"explorer.exe") == 0) {
                DWORD pid = entry.th32ProcessID;

                // Build command line directly in the Explorer function
                std::wstring commandLine = L"memory scanner.exe -p " + std::to_wstring(pid);

                SECURITY_ATTRIBUTES saAttr{};
                saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
                saAttr.bInheritHandle = TRUE;
                saAttr.lpSecurityDescriptor = NULL;

                HANDLE hChildStdoutRd, hChildStdoutWr;
                CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
                SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

                STARTUPINFO si = { sizeof(STARTUPINFO) };
                si.hStdOutput = hChildStdoutWr;
                si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

                PROCESS_INFORMATION pi;

                if (CreateProcess(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                    CloseHandle(hChildStdoutWr);

                    CHAR buffer[4096]{};
                    DWORD bytesRead;

                    while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
                        // Convert std::wstring to std::string
                        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
                        std::string outputString(buffer, bytesRead);

                        std::regex ExplorerAccessedFiles(R"(^[A-Za-z]:\\.+\.(dll|exe|bat|jar)|"[A-Za-z]:\\.+\.(dll|exe|bat|jar))");

                        if (std::regex_search(outputString, ExplorerAccessedFiles)) {
                            // Needs to be updated
                        }         
                    }

                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else {
                    if (!warningDisplayed) {
                        std::wcerr << L"Warning: memory scanner.exe not found near the Screenshare Tool. Please download it at: https://github.com/NotRequiem/StrngExtract/blob/main/Release/xxstrings.exe" << std::endl;
                        warningDisplayed = true;
                    }
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
        { L".bat", L"Executed file: " },
        { L"jar", L"Executed file: " },
    };

    // Build command line to execute the memory scanner.exe
    std::wstring commandLine = L"memory scanner.exe -p " + std::to_wstring(pid);

    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStdoutRd, hChildStdoutWr;
    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

    PROCESS_INFORMATION pi;

    if (CreateProcess(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutWr);

        CHAR buffer[4096]{};
        DWORD bytesRead;

        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            // Convert std::wstring to std::string for proper parsing
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string outputString(buffer, bytesRead);

            for (const auto& patternAndMessage : patternsAndMessages) {
                const auto& searchPattern = patternAndMessage.first;
                const auto& message = patternAndMessage.second;

                if (outputString.find(converter.to_bytes(searchPattern)) != std::string::npos) {
                    std::wcout << message << std::endl; // Needs to be updated
                }
            }
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        if (!warningDisplayed) {
            std::wcerr << L"Warning: memory scanner.exe not found near the Screenshare Tool. Please download it at: https://github.com/NotRequiem/StrngExtract/blob/main/Release/xxstrings.exe" << std::endl;
            warningDisplayed = true;
        }
    }

    CloseHandle(hChildStdoutRd);
}

// Function to detect executed files by checking specific services
void PcaSvcAndPlugPlay() {
    const wchar_t* serviceNames[] = { L"PlugPlay", L"PcaSvc" };

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
            std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect executed files. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect executed files. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect Import Code in the specified process
            DetectJarsAndBats(V_I4(&processId));
        }
        else {
            std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect executed files." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}

void ExecutedFiles() {
    Explorer();
    PcaSvcAndPlugPlay();
}